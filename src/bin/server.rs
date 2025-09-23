use std::error::Error;

use clap::Parser;

use snarf::management;

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
    // Add some logging for the moment
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env()) // use RUST_LOG or fallback
        .init();
    let arguments = Arguments::parse();
    let (blob_service, directory_service, path_info_service, nar_calculation_service) =
        snix_store::utils::construct_services(snix_store::utils::ServiceUrlsMemory::parse_from(
            std::iter::empty::<&str>(),
        ))
        .await?;

    match crate::management::generate_token() {
        Ok(token) => println!("Client token: {}", token),
        Err(err) => println!(
            "Failed to create client token: {}",
            err.source().expect("foo").to_string()
        ),
    }

    let management_routes = management::server_routes(
        blob_service.clone(),
        directory_service.clone(),
        path_info_service.clone(),
        nar_calculation_service,
    );

    let state = nar_bridge::AppState::new(
        blob_service.clone(),
        directory_service.clone(),
        path_info_service.clone(),
        std::num::NonZero::new(64usize).unwrap(),
    );

    // HTTP
    let app = nar_bridge::gen_router(30)
        .with_state(state)
        .merge(management_routes.into_axum_router());

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
