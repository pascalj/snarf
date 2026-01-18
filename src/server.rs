use std::sync::Arc;

use snix_castore::{blobservice::BlobService, directoryservice::DirectoryService};
use snix_store::{nar::NarCalculationService, pathinfoservice::PathInfoService};

use tokio::sync::mpsc;
use tonic::{async_trait, service::Interceptor};

use crate::{
    cache::NARCache,
    keys::{CacheKey, PasetoKey},
};

tonic::include_proto!("snarf.v1");

pub enum ServerCommand {
    MarkInitialized,
    Shutdown,
}

/// State that is needed to perform operations on the PASETO tokens.
#[derive(Clone)]
pub struct ServerState {
    /// The underlying signing key bytes. First 32 bytes are private key, remaining 32 bytes are the public key.
    /// We use ed25519-dalek SigningKey here and just dynamically create the PasetoAsymmetric keys.
    paseto_key: PasetoKey,

    /// The key that is used for signing the narinfo.
    cache_key: CacheKey,

    /// Whether the server was initialized. An uninitialized server may create tokens
    /// for unauthorized users to make the setup easier.
    initialized: bool,
}

pub mod persistence {
    use crate::database::snarf::DbServerState;
    use crate::keys::{CacheKey, PasetoKey};

    use super::ServerState;

    /// Try to construct a ServerState from a deserialized [DbServerState]
    pub fn from_database_state(db_state: DbServerState) -> anyhow::Result<ServerState> {
        let paseto_key =
            PasetoKey::from_keypair_bytes(db_state.paseto_key_bytes.as_slice().try_into()?)?;
        let cache_key = CacheKey::with_signing_key(
            &db_state.name,
            db_state.cache_key_bytes.as_slice().try_into()?,
        )?;
        Ok(ServerState {
            paseto_key,
            cache_key,
            initialized: db_state.initialized,
        })
    }

    /// Construct a [DbServerState] for serialization.
    pub fn to_database_state(server_state: &ServerState) -> DbServerState {
        DbServerState {
            paseto_key_bytes: server_state.paseto_key.to_keypair_bytes().into(),
            cache_key_bytes: server_state
                .cache_key
                .signing_key()
                .to_keypair_bytes()
                .into(),
            initialized: server_state.initialized,
            name: server_state.cache_key.name.clone(),
        }
    }
}

impl TryFrom<crate::database::snarf::DbServerState> for ServerState {
    type Error = anyhow::Error;

    fn try_from(dto: crate::database::snarf::DbServerState) -> anyhow::Result<Self> {
        persistence::from_database_state(dto)
    }
}

impl From<&ServerState> for crate::database::snarf::DbServerState {
    fn from(val: &ServerState) -> Self {
        persistence::to_database_state(val)
    }
}

impl ServerState {
    pub fn key_bytes(&self) -> [u8; 64] {
        self.paseto_key.to_keypair_bytes()
    }

    pub fn paseto_key(&self) -> PasetoKey {
        self.paseto_key.clone()
    }

    pub fn cache_key(&self) -> CacheKey {
        self.cache_key.clone()
    }

    pub fn initialize(&mut self) {
        self.initialized = true;
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

impl Default for ServerState {
    fn default() -> Self {
        let cache_key = CacheKey::new("snarf");
        let paseto_key = PasetoKey::default();
        Self {
            cache_key,
            paseto_key,
            initialized: false,
        }
    }
}

#[derive(Clone)]
/// An interceptor for the gRPC endpoint. It validates the incoming token
/// on the server and ensures that the client has the sufficient permissions to
/// perform a certain action.
struct PasetoAuthInterceptor {
    /// The server state to use for authentication.
    paseto_key: PasetoKey,
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
        if !self.paseto_key.verify_token(token) {
            return Err(tonic::Status::unauthenticated(
                "invalid authentication scheme",
            ));
        }

        Ok(request)
    }
}

impl From<&PasetoKey> for PasetoAuthInterceptor {
    fn from(paseto_key: &PasetoKey) -> Self {
        Self {
            paseto_key: paseto_key.clone(),
        }
    }
}

/// A PathInfoService wrapper that sing path_infos on the retrieval of entries. This makes
/// it easy to change the signature by using a different keypair.
pub struct LazySigningPathInfoService<T> {
    /// The inner [PathInfoService]
    inner: T,
    /// The key to sign narinfos
    cache_keypair: CacheKey,
}

impl<T> LazySigningPathInfoService<T> {
    pub fn new(inner: T, cache_keypair: CacheKey) -> Self {
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
    server_state: &ServerState,
    blob_service: Arc<dyn BlobService>,
    directory_service: Arc<dyn DirectoryService>,
    path_info_service: Arc<dyn PathInfoService>,
    nar_calculation_service: Box<dyn NarCalculationService>,
) -> tonic::service::Routes {
    let authenticator = PasetoAuthInterceptor::from(&server_state.paseto_key);
    tonic::service::Routes::new(
        snix_castore::proto::blob_service_server::BlobServiceServer::with_interceptor(
            snix_castore::proto::GRPCBlobServiceWrapper::new(blob_service),
            authenticator.clone(),
        ),
    )
    .add_service(
        snix_castore::proto::directory_service_server::DirectoryServiceServer::with_interceptor(
            snix_castore::proto::GRPCDirectoryServiceWrapper::new(directory_service),
            authenticator.clone(),
        ),
    )
    .add_service(
        snix_store::proto::path_info_service_server::PathInfoServiceServer::with_interceptor(
            snix_store::proto::GRPCPathInfoServiceWrapper::new(
                path_info_service.clone(),
                nar_calculation_service,
            ),
            authenticator.clone(),
        ),
    )
}

pub struct ManagementServiceWrapper {
    initialized: bool,
    paseto_key: PasetoKey,
    upstream_caches: Vec<NARCache>,
    command_channel: mpsc::Sender<ServerCommand>,
}

impl ManagementServiceWrapper {
    pub fn new(
        command_channel: &mpsc::Sender<ServerCommand>,
        paseto_key: &PasetoKey,
        upstream_caches: Vec<NARCache>,
        initialized: bool,
    ) -> Self {
        Self {
            initialized,
            paseto_key: paseto_key.clone(),
            upstream_caches,
            command_channel: command_channel.clone(),
        }
    }
}

#[tonic::async_trait]
impl management_service_server::ManagementService for ManagementServiceWrapper {
    async fn create_client_token(
        &self,
        _: tonic::Request<NewClientTokenRequest>,
    ) -> anyhow::Result<tonic::Response<ClientToken>, tonic::Status> {
        // TODO: check token
        if self.initialized {
            return Err(tonic::Status::permission_denied(
                "Server is already initialized",
            ));
        }

        self.command_channel
            .send(ServerCommand::MarkInitialized)
            .await
            .map_err(|_| tonic::Status::internal("Unable to mark initialized"))?;

        Ok(tonic::Response::new(ClientToken {
            token: self
                .paseto_key
                .public_token()
                .map_err(|_| tonic::Status::internal("Unable to generate token from state"))?,
        }))
    }
}
