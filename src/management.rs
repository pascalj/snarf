use std::sync::Arc;

use snix_castore::{blobservice::BlobService, directoryservice::DirectoryService};
use snix_store::{nar::NarCalculationService, pathinfoservice::PathInfoService};
use url::Url;

use rusty_paseto::prelude::*;

pub fn generate_token() -> Result<String, GenericBuilderError> {
    let raw_private_key = Key::<64>::try_from(
        // TODO: obviously replace with an runtime value.
        // Generated using:
        // 
        // openssl genpkey -algorithm ED25519 -out private_key.pem
        // set privhex (openssl pkey -in private_key.pem -text -noout | awk '/priv:/{flag=1;next}/pub:/{flag=0}flag' | tr -d ' :\n')
        // set pubhex  (openssl pkey -in private_key.pem -text -noout | awk '/pub:/{flag=1;next}flag' | tr -d ' :\n')
        // printf "%s" "$privhex$pubhex" | xxd -r -p > key64.bin
        // xxd  -c 64 -p key64.bin
        "4b8cfc546c8bbf4ed9ddaa579474d07375fd5f3d7cc71224a312ae833b99fea1232b2682925597b53d94d42794df1f88fab558ae76ca1b76c5538e25c162b57f",
    ).expect("expect");
    let private_key = PasetoAsymmetricPrivateKey::<V4, Public>::from(&raw_private_key);

    let token = GenericBuilder::<V4, Public>::default()
        .set_claim(SubjectClaim::from("manage cache"))
        .try_sign(&private_key)?;

    Ok(token)
}

/// Check the authentication. Dummy implementation, this will be replaced with
/// PASETO.
fn check_auth(req: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
    let token: tonic::metadata::MetadataValue<_> = "Bearer some-secret-token".parse().unwrap();

    match req.metadata().get("authorization") {
        Some(t) if token == t => Ok(req),
        _ => Err(tonic::Status::unauthenticated("No valid auth token")),
    }
}

/// Provide the authentication. Dummy implementation, this will be replaced with
/// PASETO.
fn provide_auth(mut req: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
    let token: tonic::metadata::MetadataValue<_> = "Bearer some-secret-token".parse().unwrap();
    req.metadata_mut().insert("authorization", token);
    Ok(req)
}

/// Get the routes used for the server. These will route the usual services but additionally
/// provide a check for authentication.
pub fn server_routes(
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

/// Create the clients that are necessary to talk to the server. Currently,
/// these are the blob-, directory- and path_info services. These can be used
/// to manage a remote Snix store.
/// Additionally to the usual Snix way of constructing the services, this
/// function ensures that the authentication is passed to the server.
pub async fn clients(
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
                provide_auth,
            ),
        )),
        Arc::new(snix_castore::directoryservice::GRPCDirectoryService::from_client(
            "root".into(),
            snix_castore::proto::directory_service_client::DirectoryServiceClient::with_interceptor(
                snix_castore::tonic::channel_from_url(url).await?,
                provide_auth,
            ),
        )),
        Arc::new(snix_store::pathinfoservice::GRPCPathInfoService::from_client(
            "root".into(),
            snix_store::proto::path_info_service_client::PathInfoServiceClient::with_interceptor(
                snix_castore::tonic::channel_from_url(url).await?,
                provide_auth,
            ),
        ))),
    )
}
