use std::sync::Arc;

use ed25519_dalek::SigningKey;
use snix_castore::{blobservice::BlobService, directoryservice::DirectoryService};
use snix_store::{nar::NarCalculationService, pathinfoservice::PathInfoService};
use tonic::service::Interceptor;
use url::Url;

use base64::prelude::*;
use rand_core::OsRng;
use rusty_paseto::prelude::*;

/// State that is needed to perform operations on the PASETO tokens.
#[derive(Clone)]
pub struct ServerState {
    /// The underlying signing key bytes. First 32 bytes are private key, remaining 32 bytes are the public key.
    /// We use ed25519-dalek SigningKey here and just dynamically create the PasetoAsymmetric keys.
    signing_key: SigningKey,
}

impl ServerState {
    /// Get the public token that can be given to clients
    pub fn public_token(&self) -> Result<String, GenericBuilderError> {
        let keypair_bytes = self.signing_key.to_keypair_bytes();
        let private_key = PasetoAsymmetricPrivateKey::<V4, Public>::from(keypair_bytes.as_slice());

        let token = GenericBuilder::<V4, Public>::default()
            .set_claim(SubjectClaim::from("manage cache"))
            .try_sign(&private_key)?;

        Ok(token)
    }

    /// Verify a client token for this PasetoState (signing_key). Currently, this
    /// just checks whether it is a valid token, no claims are checked at all.
    pub fn verify_token(&self, token: &str) -> bool {
        let public_key =
            Key::<32>::try_from(self.signing_key.verifying_key().as_bytes()).expect("expect");
        let paseto_public_key = PasetoAsymmetricPublicKey::<V4, Public>::from(&public_key);
        GenericParser::<V4, Public>::default()
            .parse(&token, &paseto_public_key)
            .is_ok()
    }

    pub fn key_bytes(&self) -> [u8; 64] {
        self.signing_key.to_keypair_bytes()
    }

    pub fn signing_key(&self) -> SigningKey {
        self.signing_key.clone()
    }
}

impl TryFrom<&[u8]> for ServerState {
    type Error = &'static str;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if let Ok(bytes_arr) = bytes.try_into() {
            return Ok(Self {
                signing_key: SigningKey::from_keypair_bytes(bytes_arr)
                    .map_err(|_| "Failed to generate SigningKey from bytes")?,
            });
        }

        Err("Failed to contruct PasetoState from bytes")
    }
}

impl Default for ServerState {
    fn default() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }
}
#[derive(Default, Clone)]
struct PasetoAuthInterceptor {
    state: ServerState,
}

impl Interceptor for PasetoAuthInterceptor {
    fn call(&mut self, request: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
        let header = request
            .metadata()
            .get("authorization")
            .ok_or_else(|| tonic::Status::unauthenticated("authorization header missing"))?;

        // 2) convert to &str
        let header_str = header
            .to_str()
            .map_err(|_| tonic::Status::unauthenticated("invalid authorization header"))?;

        // 3) expect "Bearer <token>"
        let token = header_str
            .strip_prefix("Bearer ")
            .ok_or_else(|| tonic::Status::unauthenticated("invalid authentication scheme"))?;

        if !self.state.verify_token(token) {
            return Err(tonic::Status::unauthenticated(
                "invalid authentication scheme",
            ));
        }

        Ok(request)
    }
}

impl From<ServerState> for PasetoAuthInterceptor {
    fn from(state: ServerState) -> Self {
        Self { state }
    }
}

#[derive(Clone)]
struct PasetoTokenInterceptor {
    token: String,
}

impl From<&str> for PasetoTokenInterceptor {
    fn from(token: &str) -> Self {
        Self {
            token: token.to_owned(),
        }
    }
}

impl Interceptor for PasetoTokenInterceptor {
    fn call(
        &mut self,
        mut request: tonic::Request<()>,
    ) -> Result<tonic::Request<()>, tonic::Status> {
        let token: tonic::metadata::MetadataValue<_> =
            format!("Bearer {}", self.token).parse().unwrap();
        request.metadata_mut().insert("authorization", token);
        Ok(request)
    }
}

/// Get the routes used for the server. These will route the usual services but additionally
/// provide a check for authentication.
pub fn server_routes(
    paseto_state: &ServerState,
    blob_service: Arc<dyn BlobService>,
    directory_service: Arc<dyn DirectoryService>,
    path_info_service: Arc<dyn PathInfoService>,
    nar_calculation_service: Box<dyn NarCalculationService>,
) -> tonic::service::Routes {
    tonic::service::Routes::new(
        snix_castore::proto::blob_service_server::BlobServiceServer::with_interceptor(
            snix_castore::proto::GRPCBlobServiceWrapper::new(blob_service),
            PasetoAuthInterceptor::from(paseto_state.clone()),
        ),
    )
    .add_service(
        snix_castore::proto::directory_service_server::DirectoryServiceServer::with_interceptor(
            snix_castore::proto::GRPCDirectoryServiceWrapper::new(directory_service),
            PasetoAuthInterceptor::from(paseto_state.clone()),
        ),
    )
    .add_service(
        snix_store::proto::path_info_service_server::PathInfoServiceServer::with_interceptor(
            snix_store::proto::GRPCPathInfoServiceWrapper::new(
                path_info_service,
                nar_calculation_service,
            ),
            PasetoAuthInterceptor::from(paseto_state.clone()),
        ),
    )
}

/// Create the clients that are necessary to talk to the server. Currently,
/// these are the blob-, directory- and path_info services. These can be used
/// to manage a remote Snix store.
/// Additionally to the usual Snix way of constructing the services, this
/// function ensures that the authentication is passed to the server.
pub async fn clients(
    token: &str,
    url: &Url,
) -> Result<
    (
        Arc<dyn BlobService>,
        Arc<dyn DirectoryService>,
        Arc<dyn PathInfoService>,
    ),
    Box<dyn std::error::Error + Send + Sync + 'static>,
> {
    Ok(
        (Arc::new(snix_castore::blobservice::GRPCBlobService::from_client(
            "root".into(),
            snix_castore::proto::blob_service_client::BlobServiceClient::with_interceptor(
                snix_castore::tonic::channel_from_url(url).await?,
                PasetoTokenInterceptor::from(token),
            ),
        )),
        Arc::new(snix_castore::directoryservice::GRPCDirectoryService::from_client(
            "root".into(),
            snix_castore::proto::directory_service_client::DirectoryServiceClient::with_interceptor(
                snix_castore::tonic::channel_from_url(url).await?,
                PasetoTokenInterceptor::from(token),
            ),
        )),
        Arc::new(snix_store::pathinfoservice::GRPCPathInfoService::from_client(
            "root".into(),
            snix_store::proto::path_info_service_client::PathInfoServiceClient::with_interceptor(
                snix_castore::tonic::channel_from_url(url).await?,
                PasetoTokenInterceptor::from(token),
            ),
        ))),
    )
}

/// Serialize an ed25519 keypair in the format that Nix uses with
/// `nix-store --generate-binary-cache-key`.
/// Snix provides the counterpart of this, but it doesn't expose the key bytes, so we cannot use it to display the public key nicely.
pub fn serialize_nix_store_signing_key(
    path: &std::path::Path,
    name: &str,
    key: ed25519_dalek::SigningKey,
) -> Result<(), std::io::Error> {
    let base64_keypair = BASE64_STANDARD.encode(key.to_keypair_bytes());
    let nix_format = format!("{}:{}", name, base64_keypair);
    std::fs::write(path, nix_format)?;
    Ok(())
}
