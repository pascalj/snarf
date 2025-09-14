use clap::Parser;
use snix_castore::utils::ServiceUrlsGrpc;
use tracing::info;

#[derive(Parser)]
struct Arguments {
    #[clap(flatten)]
    service_addrs: ServiceUrlsGrpc,

    /// The address to listen on.
    #[clap(flatten)]
    listen_args: tokio_listener::ListenerAddressLFlag,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env()) // use RUST_LOG or fallback
        .init();
    let arguments = Arguments::parse();
    let (blob_service, directory_service, path_info_service, nar_calculation_service) =
        snix_store::utils::construct_services(snix_store::utils::ServiceUrlsMemory::parse_from(
            std::iter::empty::<&str>(),
        ))
        .await?;

    let state = nar_bridge::AppState::new(
        blob_service.clone(),
        directory_service.clone(),
        path_info_service.clone(),
        std::num::NonZero::new(64usize).unwrap(),
    );

    let router = tonic::service::Routes::new(
        snix_castore::proto::blob_service_server::BlobServiceServer::new(
            snix_castore::proto::GRPCBlobServiceWrapper::new(blob_service),
        ),
    )
    .add_service(
        snix_castore::proto::directory_service_server::DirectoryServiceServer::new(
            snix_castore::proto::GRPCDirectoryServiceWrapper::new(directory_service),
        ),
    )
    .add_service(
        snix_store::proto::path_info_service_server::PathInfoServiceServer::new(
            snix_store::proto::GRPCPathInfoServiceWrapper::new(
                path_info_service,
                nar_calculation_service,
            ),
        ),
    );

    // HTTP
    let app = nar_bridge::gen_router(30)
        .with_state(state)
        .merge(router.into_axum_router());

    let listen_address = &arguments.listen_args.listen_address.unwrap_or_else(|| {
        "[::]:9000"
            .parse()
            .expect("invalid fallback listen address")
    });

    let listener = tokio_listener::Listener::bind(
        listen_address,
        &Default::default(),
        &arguments.listen_args.listener_options,
    )
    .await;

    info!(listen_address=%listen_address, "starting daemon");

    tokio_listener::axum07::serve(
        listener.unwrap(),
        app.into_make_service_with_connect_info::<tokio_listener::SomeSocketAddrClonable>(),
    )
    .await?;

    Ok(())
}
