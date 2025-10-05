use std::sync::Arc;

use snix_castore::{blobservice::BlobService, directoryservice::DirectoryService};
use snix_store::{nar::NarCalculationService, pathinfoservice::PathInfoService};
use tonic::async_trait;
use tonic::service::Interceptor;
use url::Url;

use base64::prelude::*;
use rand_core::OsRng;
use rusty_paseto::prelude::*;

#[derive(Clone)]
enum ServerInitialization {
    /// The server is not initialized and does not have a secret key.
    Uninitialized,
    /// The server loaded a serialized secret key and operates normally.
    Initialized,
    /// The server was initialized but still needs to serialize the key.
    NewlyInitialized,
}

/// State that is needed to perform operations on the PASETO tokens.
#[derive(Clone)]
pub struct ServerState {
    initialzation: ServerInitialization,
    /// The underlying signing key bytes. First 32 bytes are private key, remaining 32 bytes are the public key.
    /// We use ed25519-dalek SigningKey here and just dynamically create the PasetoAsymmetric keys.
    signing_key: ed25519_dalek::SigningKey,
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
        let public_key = Key::<32>::try_from(self.signing_key.verifying_key().as_bytes())
            .expect("The siging_key is not a valid key");
        let paseto_public_key = PasetoAsymmetricPublicKey::<V4, Public>::from(&public_key);
        GenericParser::<V4, Public>::default()
            .parse(&token, &paseto_public_key)
            .is_ok()
    }

    pub fn key_bytes(&self) -> [u8; 64] {
        self.signing_key.to_keypair_bytes()
    }

    pub fn signing_key(&self) -> ed25519_dalek::SigningKey {
        self.signing_key.clone()
    }
}

impl TryFrom<&[u8]> for ServerState {
    type Error = &'static str;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if let Ok(bytes_arr) = bytes.try_into() {
            return Ok(Self {
                initialzation: ServerInitialization::Initialized,
                signing_key: ed25519_dalek::SigningKey::from_keypair_bytes(bytes_arr)
                    .map_err(|_| "Failed to generate SigningKey from bytes")?,
            });
        }

        Err("Failed to contruct PasetoState from bytes")
    }
}

impl Default for ServerState {
    fn default() -> Self {
        Self {
            initialzation: ServerInitialization::Uninitialized,
            signing_key: ed25519_dalek::SigningKey::generate(&mut OsRng),
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

        // TODO: split this off into capabilities
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

/// A PathInfoService wrapper that sing path_infos on the retrieval of entries. This makes
/// it easy to change the signature by using a different keypair.
pub struct LazySigningPathInfoService<T> {
    /// The inner [PathInfoService]
    inner: T,
    /// The key to sign narinfos
    signing_key: Arc<nix_compat::narinfo::SigningKey<ed25519_dalek::SigningKey>>,
}

impl<T> LazySigningPathInfoService<T> {
    pub fn new(
        inner: T,
        signing_key: Arc<nix_compat::narinfo::SigningKey<ed25519_dalek::SigningKey>>,
    ) -> Self {
        Self { inner, signing_key }
    }
}

#[async_trait]
impl<T> PathInfoService for LazySigningPathInfoService<T>
where
    T: PathInfoService,
{
    /// Get the pathinfo for a digest. This performs the actual signing of a path_info
    /// is found for the digest.
    async fn get(
        &self,
        digest: [u8; 20],
    ) -> Result<Option<snix_store::path_info::PathInfo>, snix_castore::Error> {
        let path_info = self.inner.get(digest).await?;

        Ok(path_info.map(|mut info| {
            info.signatures.push({
                let mut nar_info = info.to_narinfo();
                nar_info.signatures.clear();
                nar_info.add_signature(&self.signing_key);

                let new_signature = nar_info
                    .signatures
                    .pop()
                    .expect("Snix bug: no signature after signing op");

                nix_compat::narinfo::Signature::new(
                    new_signature.name().to_string(),
                    *new_signature.bytes(),
                )
            });
            info
        }))
    }

    /// Don't sign on putting the object into the store.
    async fn put(
        &self,
        path_info: snix_store::path_info::PathInfo,
    ) -> Result<snix_store::path_info::PathInfo, snix_castore::Error> {
        self.inner.put(path_info).await
    }

    /// List all path_infos in this cache
    fn list(
        &self,
    ) -> futures::stream::BoxStream<
        'static,
        Result<snix_store::path_info::PathInfo, snix_castore::Error>,
    > {
        self.inner.list()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_token() {
        let server_state = ServerState::default();
        assert!(server_state.verify_token(server_state.public_token().unwrap().as_ref()))
    }

    #[test]
    fn invalid_token() {
        let server_state = ServerState::default();
        let different_server_state = ServerState::default();
        assert!(!server_state.verify_token(different_server_state.public_token().unwrap().as_ref()))
    }

    #[test]
    fn server_state_from_bytes() {
        let server_state = ServerState::default();
        assert!(ServerState::try_from(server_state.key_bytes().as_slice()).is_ok())
    }

    #[test]
    fn server_state_from_invalid_bytes() {
        let server_state = ServerState::default();
        let mut bytes = server_state.key_bytes();
        // change a random bytes
        bytes[4] += 1;
        assert!(!ServerState::try_from(bytes.as_slice().as_ref()).is_ok())
    }
}
