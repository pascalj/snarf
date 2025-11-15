use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
};

use rand_core::OsRng;

use base64::{DecodeError, prelude::*};
use rusty_paseto::prelude::*;

use snix_castore::{blobservice::BlobService, directoryservice::DirectoryService};
use snix_store::{nar::NarCalculationService, pathinfoservice::PathInfoService};

use tokio::sync::mpsc;
use tonic::{async_trait, service::Interceptor};

use tracing::{error, info};

tonic::include_proto!("snarf.v1");

#[derive(Clone)]
pub struct CacheKeypair {
    pub name: String,
    pub signing_key: ed25519_dalek::SigningKey,
}

impl CacheKeypair {
    pub fn new(name: &str, signing_key: Option<ed25519_dalek::SigningKey>) -> Self {
        use rand_core::OsRng;
        Self {
            name: name.into(),
            signing_key: signing_key.unwrap_or(ed25519_dalek::SigningKey::generate(&mut OsRng)),
        }
    }

    pub fn signing_key(&self) -> &ed25519_dalek::SigningKey {
        &self.signing_key
    }
}

impl From<&CacheKeypair> for nix_compat::narinfo::SigningKey<ed25519_dalek::SigningKey> {
    fn from(
        cache_keypair: &CacheKeypair,
    ) -> nix_compat::narinfo::SigningKey<ed25519_dalek::SigningKey> {
        Self::new(
            cache_keypair.name.clone(),
            cache_keypair.signing_key.clone(),
        )
    }
}

pub type PasetoKeypair = ed25519_dalek::SigningKey;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Signing key error: {0}")]
    SigningKeyError(nix_compat::narinfo::SigningKeyError),
    #[error("IO error: {0}")]
    IOError(std::io::Error),
    #[error("Invalid name: {0}")]
    InvalidName(String),
    #[error("Invalid verifying key: {0}")]
    InvalidVerifyingKey(ed25519_dalek::SignatureError),
    #[error("Deciding error: {0}")]
    DecodeError(DecodeError),
    #[error("Invalid signing key lenght: {0}")]
    InvalidSigningKeyLen(usize),
    #[error("Missing separator")]
    MissingSeparator,
}

pub enum ServerCommand {
    UpdateState(ServerState),
    Shutdown,
}

#[derive(Clone, Eq, PartialEq, Debug)]
enum ServerInitialization {
    /// The server is not initialized and does not have a secret key.
    Uninitialized(PathBuf),
    /// The server loaded a serialized secret key and operates normally.
    Initialized,
    /// The server was initialized but still needs to serialize the key.
    NewlyInitialized,
}

/// State that is needed to perform operations on the PASETO tokens.
#[derive(Clone)]
pub struct ServerState {
    initialization: ServerInitialization,

    /// The underlying signing key bytes. First 32 bytes are private key, remaining 32 bytes are the public key.
    /// We use ed25519-dalek SigningKey here and just dynamically create the PasetoAsymmetric keys.
    paseto_keypair: PasetoKeypair,

    /// The key that is used for signing the narinfo.
    cache_keypair: CacheKeypair,
}

impl ServerState {
    pub fn new(paseto_keypair: &PasetoKeypair, cache_keypair: &CacheKeypair) -> ServerState {
        Self {
            initialization: ServerInitialization::Initialized,
            paseto_keypair: paseto_keypair.clone(),
            cache_keypair: cache_keypair.clone(),
        }
    }
    /// Renew the signing key
    pub fn initialize_signing_key(&mut self) {
        match &self.initialization {
            ServerInitialization::Uninitialized(out_path) => {
                self.paseto_keypair = PasetoKeypair::generate(&mut OsRng);
                if let Ok(_) = self.write_key(&out_path) {
                    self.initialization = ServerInitialization::NewlyInitialized;
                } else {
                    error!("Unable to create the key file");
                }
            }
            _ => assert!(false, "Cannot initialize an already initialized server."),
        }
    }

    fn write_key(&self, out_path: &PathBuf) -> std::result::Result<(), std::io::Error> {
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
            // TODO: save in nix-compatible form (name:base64)
            std::fs::write(out_path.clone(), self.key_bytes())?;
        }

        info!(
            file=%out_path.display(),
            "Generated and wrote a new private key",
        );

        Ok(())
    }

    /// Get the public token that can be given to clients
    pub fn public_token(&self) -> Result<String, rusty_paseto::prelude::GenericBuilderError> {
        let keypair_bytes = self.paseto_keypair.to_keypair_bytes();
        let private_key = rusty_paseto::core::PasetoAsymmetricPrivateKey::<V4, Public>::from(
            keypair_bytes.as_slice(),
        );

        let token = rusty_paseto::prelude::GenericBuilder::<V4, Public>::default()
            .set_claim(SubjectClaim::from("manage cache"))
            .try_sign(&private_key)?;

        Ok(token)
    }

    /// Verify a client token for this PasetoState (signing_key). Currently, this
    /// just checks whether it is a valid token, no claims are checked at all.
    pub fn verify_token(&self, token: &str) -> bool {
        let public_key =
            rusty_paseto::core::Key::<32>::try_from(self.paseto_keypair.verifying_key().as_bytes())
                .expect("The siging_key is not a valid key");
        let paseto_public_key = PasetoAsymmetricPublicKey::<V4, Public>::from(&public_key);
        rusty_paseto::prelude::GenericParser::<V4, Public>::default()
            .parse(&token, &paseto_public_key)
            .is_ok()
    }

    pub fn key_bytes(&self) -> [u8; 64] {
        self.paseto_keypair.to_keypair_bytes()
    }

    pub fn signing_key(&self) -> ed25519_dalek::SigningKey {
        self.paseto_keypair.clone()
    }
}

#[derive(Clone)]
/// An interceptor for the gRPC endpoint. It validates the incoming token
/// on the server and ensures that the client has the sufficient permissions to
/// perform a certain action.
struct PasetoAuthInterceptor {
    /// The server state to use for authentication.
    state: ServerState,
}

impl Interceptor for PasetoAuthInterceptor {
    /// Check the authentication for this request based on a PASETO token.
    /// This currently only takes into account whether the token is valid
    /// in general, not any specific capabilities.
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

impl From<&ServerState> for PasetoAuthInterceptor {
    fn from(state: &ServerState) -> Self {
        Self {
            state: state.clone(),
        }
    }
}

/// A PathInfoService wrapper that sing path_infos on the retrieval of entries. This makes
/// it easy to change the signature by using a different keypair.
pub struct LazySigningPathInfoService<T> {
    /// The inner [PathInfoService]
    inner: T,
    /// The key to sign narinfos
    cache_keypair: CacheKeypair,
}

impl<T> LazySigningPathInfoService<T> {
    pub fn new(inner: T, cache_keypair: CacheKeypair) -> Self {
        Self {
            inner,
            cache_keypair,
        }
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
                let key: nix_compat::narinfo::SigningKey<ed25519_dalek::SigningKey> =
                    (&self.cache_keypair).into();
                nar_info.signatures.clear();
                nar_info.add_signature(&key);

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
    command_channel: &mpsc::Sender<ServerCommand>,
    server_state: &ServerState,
    blob_service: Arc<dyn BlobService>,
    directory_service: Arc<dyn DirectoryService>,
    path_info_service: Arc<dyn PathInfoService>,
    nar_calculation_service: Box<dyn NarCalculationService>,
) -> tonic::service::Routes {
    tonic::service::Routes::new(
        snix_castore::proto::blob_service_server::BlobServiceServer::with_interceptor(
            snix_castore::proto::GRPCBlobServiceWrapper::new(blob_service),
            PasetoAuthInterceptor::from(server_state),
        ),
    )
    .add_service(
        snix_castore::proto::directory_service_server::DirectoryServiceServer::with_interceptor(
            snix_castore::proto::GRPCDirectoryServiceWrapper::new(directory_service),
            PasetoAuthInterceptor::from(server_state),
        ),
    )
    .add_service(
        snix_store::proto::path_info_service_server::PathInfoServiceServer::with_interceptor(
            snix_store::proto::GRPCPathInfoServiceWrapper::new(
                path_info_service,
                nar_calculation_service,
            ),
            PasetoAuthInterceptor::from(server_state),
        ),
    )
    .add_service(management_service_server::ManagementServiceServer::new(
        ManagementServiceServer::new(command_channel, server_state),
    ))
}

#[derive(Clone)]
pub struct ManagementServiceServer {
    server_state: ServerState,
    command_channel: mpsc::Sender<ServerCommand>,
}

impl ManagementServiceServer {
    fn new(command_channel: &mpsc::Sender<ServerCommand>, server_state: &ServerState) -> Self {
        Self {
            command_channel: command_channel.clone(),
            server_state: server_state.clone(),
        }
    }
}

#[tonic::async_trait]
impl management_service_server::ManagementService for ManagementServiceServer {
    async fn create_client_token(
        &self,
        _: tonic::Request<NewClientTokenRequest>,
    ) -> Result<tonic::Response<ClientToken>, tonic::Status> {
        let mut state = self.server_state.clone();

        match state.initialization {
            ServerInitialization::Uninitialized(_) => {
                info!("Generating new admin token");
                state.initialize_signing_key();
                let token = state.public_token();

                self.command_channel
                    .send(ServerCommand::UpdateState(state))
                    .await
                    .unwrap();

                Ok(tonic::Response::new(ClientToken {
                    token: token.map_err(|_| {
                        tonic::Status::internal("Unable to generate token from state")
                    })?,
                }))
            }

            _ => Err(tonic::Status::permission_denied(
                "Server is already initialized",
            )),
        }
    }
}

/// Serialize an ed25519 keypair in the format that Nix uses with `nix-store
/// --generate-binary-cache-key`. Snix provides the counterpart of this, but
/// it doesn't expose the key bytes, so we cannot use it to display the public
/// key nicely.
pub fn serialize_nix_store_signing_key(
    path: &std::path::Path,
    key: &CacheKeypair,
) -> Result<(), Error> {
    let base64_keypair = BASE64_STANDARD.encode(key.signing_key().to_keypair_bytes());
    let nix_format = format!("{}:{}", key.name, base64_keypair);
    std::fs::write(path, nix_format).map_err(Error::IOError)
}

/// Load a serialized nix store signing key from disk.
/// The file has the format `<name>:encode_base64(<bytes>)`.
pub fn deserialize_nix_store_signing_key(path: &std::path::Path) -> Result<CacheKeypair, Error> {
    let input = std::fs::read_to_string(path).map_err(Error::IOError)?;

    let (name, bytes64) = input.split_once(':').ok_or(Error::MissingSeparator)?;

    if name.is_empty()
        || !name
            .chars()
            .all(|c| char::is_alphanumeric(c) || c == '-' || c == '.')
    {
        return Err(Error::InvalidName(name.to_string()));
    }

    let bytes = BASE64_STANDARD
        .decode(bytes64.as_bytes())
        .map_err(Error::DecodeError)?;

    let signing_key = CacheKeypair::new(
        name,
        Some(
            ed25519_dalek::SigningKey::from_keypair_bytes(&bytes.try_into().unwrap())
                .map_err(Error::InvalidVerifyingKey)?,
        ),
    );

    Ok(signing_key)
}
