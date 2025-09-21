use std::sync::Arc;

use snix_castore::{
    blobservice::BlobService, directoryservice::DirectoryService,
    proto::blob_service_client::BlobServiceClient,
};
use snix_store::{nar::NarCalculationService, pathinfoservice::PathInfoService};

fn check_auth(req: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
    let token: tonic::metadata::MetadataValue<_> = "Bearer some-secret-token".parse().unwrap();

    match req.metadata().get("authorization") {
        Some(t) if token == t => Ok(req),
        _ => Err(tonic::Status::unauthenticated("No valid auth token")),
    }
}

fn provide_auth(mut req: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
    let token: tonic::metadata::MetadataValue<_> = "Bearer some-secret-token".parse().unwrap();
    req.metadata_mut().insert("authorization", token);
    Ok(req)
}

pub fn routes(
    blob_service: Arc<dyn BlobService>,
    directory_service: Arc<dyn DirectoryService>,
    path_info_service: Arc<dyn PathInfoService>,
    nar_calculation_service: Box<dyn NarCalculationService>,
) -> tonic::service::Routes {
    tonic::service::Routes::new(
        snix_castore::proto::blob_service_server::BlobServiceServer::with_interceptor(
            snix_castore::proto::GRPCBlobServiceWrapper::new(blob_service),
            check_auth,
        ),
    )
    .add_service(
        snix_castore::proto::directory_service_server::DirectoryServiceServer::with_interceptor(
            snix_castore::proto::GRPCDirectoryServiceWrapper::new(directory_service),
            check_auth,
        ),
    )
    .add_service(
        snix_store::proto::path_info_service_server::PathInfoServiceServer::with_interceptor(
            snix_store::proto::GRPCPathInfoServiceWrapper::new(
                path_info_service,
                nar_calculation_service,
            ),
            check_auth,
        ),
    )
}

pub async fn client(
    url: &url::Url,
    blob_service: Arc<dyn BlobService>,
) -> Result<Arc<dyn BlobService>, Box<dyn std::error::Error + Send + Sync + 'static>> {
    Ok(Arc::new(
        snix_castore::blobservice::GRPCBlobService::from_client(
            "root".into(),
            BlobServiceClient::with_interceptor(
                snix_castore::tonic::channel_from_url(url).await?,
                provide_auth,
            ),
        ),
    ))
}
