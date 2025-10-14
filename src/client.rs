use std::sync::Arc;

use snix_castore::{blobservice::BlobService, directoryservice::DirectoryService};
use snix_store::pathinfoservice::PathInfoService;

use tonic::service::Interceptor;
use url::Url;

tonic::include_proto!("snarf.v1");

/// Responsible for adding the bearer token from a Paseto token on the
/// client side.
#[derive(Clone)]
struct ClientPasetoTokenInterceptor {
    token: String,
}

impl From<&str> for ClientPasetoTokenInterceptor {
    fn from(token: &str) -> Self {
        Self {
            token: token.to_owned(),
        }
    }
}

impl Interceptor for ClientPasetoTokenInterceptor {
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
                ClientPasetoTokenInterceptor::from(token),
            ),
        )),
        Arc::new(snix_castore::directoryservice::GRPCDirectoryService::from_client(
            "root".into(),
            snix_castore::proto::directory_service_client::DirectoryServiceClient::with_interceptor(
                snix_castore::tonic::channel_from_url(url).await?,
                ClientPasetoTokenInterceptor::from(token),
            ),
        )),
        Arc::new(snix_store::pathinfoservice::GRPCPathInfoService::from_client(
            "root".into(),
            snix_store::proto::path_info_service_client::PathInfoServiceClient::with_interceptor(
                snix_castore::tonic::channel_from_url(url).await?,
                ClientPasetoTokenInterceptor::from(token),
            ),
        ))),
    )
}
