use std::sync::Arc;

use snix_castore::{blobservice::BlobService, directoryservice::DirectoryService};
use snix_store::{nar::NarCalculationService, pathinfoservice::PathInfoService};

use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tonic::async_trait;

use crate::{
    cache::{UpstreamCacheCommand, UpstreamCaches},
    keys::{CacheKey, PasetoKey},
    server::state::ServerState,
};

tonic::include_proto!("snarf.v1");

/// An interceptor for the gRPC endpoint. It validates the incoming token
/// on the server and ensures that the client has the sufficient permissions to
/// perform a certain action.
#[derive(Clone)]
struct PasetoAuthInterceptor {
    /// The server state to use for authentication.
    paseto_key: PasetoKey,
}

pub enum ServerCommand {
    MarkInitialized,
}

impl From<&PasetoKey> for PasetoAuthInterceptor {
    fn from(paseto_key: &PasetoKey) -> Self {
        Self {
            paseto_key: paseto_key.clone(),
        }
    }
}

impl tonic::service::Interceptor for PasetoAuthInterceptor {
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
    let authenticator = PasetoAuthInterceptor::from(&server_state.paseto_key());
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
    server_commands_tx: mpsc::Sender<ServerCommand>,
    cache_commands_tx: mpsc::Sender<UpstreamCacheCommand>,
    server_state: ServerState,
    upstream_caches: UpstreamCaches,
}

impl ManagementServiceWrapper {
    pub fn new(
        server_commands_tx: mpsc::Sender<ServerCommand>,
        cache_commands_tx: mpsc::Sender<UpstreamCacheCommand>,
        server_state: ServerState,
        upstream_caches: UpstreamCaches,
    ) -> Self {
        Self {
            server_commands_tx,
            cache_commands_tx,
            server_state,
            upstream_caches,
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
        if self.server_state.is_initialized() {
            return Err(tonic::Status::permission_denied(
                "Server is already initialized",
            ));
        }

        self.server_commands_tx
            .send(ServerCommand::MarkInitialized)
            .await
            .map_err(|_| tonic::Status::internal("Unable to mark initialized"))?;

        Ok(tonic::Response::new(ClientToken {
            token: self
                .server_state
                .paseto_key()
                .public_token()
                .map_err(|_| tonic::Status::internal("Unable to generate token from state"))?,
        }))
    }
    type FilterHashesStream = std::pin::Pin<
        Box<dyn futures::Stream<Item = Result<NarHashResponse, tonic::Status>> + Send>,
    >;

    /// Filter hashes whether they need uploading.
    async fn filter_hashes(
        &self,
        request: tonic::Request<tonic::Streaming<NarHashRequest>>,
    ) -> std::result::Result<tonic::Response<Self::FilterHashesStream>, tonic::Status> {
        let mut in_stream = request.into_inner();
        let (tx, rx) = mpsc::channel::<Result<NarHashResponse, tonic::Status>>(16);

        let upstream_caches = self.upstream_caches.clone();

        tokio::spawn(async move {
            let client = reqwest::Client::new();
            while let Some(Ok(nar_hash_request)) = in_stream.next().await {
                let digest = nar_hash_request.digest.clone();

                let client_ref = &client;
                let digest_ref = &digest;

                let is_upstream =
                    futures::future::join_all(upstream_caches.caches().blocking_read().iter().map(
                        |cache| async move {
                            matches!(
                                cache.has_nar_hash(client_ref, digest_ref.as_slice()).await,
                                Ok(true)
                            )
                        },
                    ))
                    .await
                    .into_iter()
                    .any(|x| x);

                let response = NarHashResponse { is_upstream };

                // if receiver dropped, stop processing
                if tx.send(Ok(response)).await.is_err() {
                    break;
                }
            }
        });

        let out_stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        Ok(tonic::Response::new(
            Box::pin(out_stream) as Self::FilterHashesStream
        ))
    }

    async fn add_upstream_cache(
        &self,
        request: tonic::Request<AddUpstreamCacheRequest>,
    ) -> anyhow::Result<tonic::Response<AddUpstreamCacheResponse>, tonic::Status> {
        let AddUpstreamCacheRequest { base_url } = request.into_inner();

        self.cache_commands_tx
            .send(UpstreamCacheCommand::Add { base_url })
            .await
            .map_err(|_| tonic::Status::internal("Unable to mark initialized"))?;

        Ok(tonic::Response::new(AddUpstreamCacheResponse {
            success: true,
        }))
    }
}
