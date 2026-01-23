use std::{path::PathBuf, sync::Arc};

use clap::Parser;

use snarf::cache::{NARCache, UpstreamCacheCommand, UpstreamCaches};
use snarf::database::snarf::{load_nar_caches, store_server_state};
use snarf::{
    database::snarf::{connect_database, load_server_state},
    server::{
        services::{LazySigningPathInfoService, ServerCommand},
        state::ServerState,
    },
};

use tokio::sync::mpsc;

use tracing::info;

/// Arguments to configure the snix-castore services with customized defaults.
#[derive(clap::Parser, Clone)]
#[group(id = "CastoreServiceUrls")]
pub struct CastoreServiceUrls {
    #[arg(
        long,
        env,
        default_value = "objectstore+file:///var/lib/snarf/snix-castore/blobs"
    )]
    pub blob_service_addr: String,

    #[arg(
        long,
        env,
        default_value = "redb:///var/lib/snarf/snix-castore/directories.redb"
    )]
    pub directory_service_addr: String,
}

/// Arguments to configure the snix-store services with customized defaults.
#[derive(clap::Parser, Clone)]
#[group(id = "StoreServiceUrls")]
pub struct ServiceUrls {
    #[clap(flatten)]
    pub castore_service_addrs: CastoreServiceUrls,

    #[arg(
        long,
        env,
        default_value = "redb:///var/lib/snarf/snix-store/pathinfo.redb"
    )]
    pub path_info_service_addr: String,
}

impl From<CastoreServiceUrls> for snix_castore::utils::ServiceUrls {
    fn from(urls: CastoreServiceUrls) -> snix_castore::utils::ServiceUrls {
        snix_castore::utils::ServiceUrls {
            blob_service_addr: urls.blob_service_addr,
            directory_service_addr: urls.directory_service_addr,
        }
    }
}

impl From<ServiceUrls> for snix_store::utils::ServiceUrls {
    fn from(urls: ServiceUrls) -> snix_store::utils::ServiceUrls {
        snix_store::utils::ServiceUrls {
            castore_service_addrs: urls.castore_service_addrs.into(),
            path_info_service_addr: urls.path_info_service_addr,
        }
    }
}

#[derive(Parser)]
struct Arguments {
    /// The name of the cache, for example for signing info.
    #[clap(long, default_value = "snarf")]
    cache_name: String,

    /// The directory where snarf holds it's state (database)
    #[arg(long, env, default_value = "/var/lib/snarf/")]
    state_directory: PathBuf,

    /// The Snix store service URLs that are used for the underlying store.
    #[clap(flatten)]
    service_addrs: ServiceUrls,

    /// The address to listen on.
    #[clap(flatten)]
    listen_args: tokio_listener::ListenerAddressLFlag,
}

#[tokio::main]
async fn main() -> anyhow::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Add some logging for the moment
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env()) // use RUST_LOG or fallback
        .init();

    let arguments = Arguments::parse();
    start_server(&arguments).await?;

    Ok(())
}

/// Start the actual server handling incoming client connections.
///
/// This also sets up the communication between internal signal handlers,
/// for example for restarting or shutdding down the server
async fn start_server(
    arguments: &Arguments,
) -> anyhow::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let db_connection = connect_database(arguments.state_directory.as_path().join("snarf.sqlite"))?;
    let server_state = match load_server_state(&db_connection)? {
        Some(server_state) => ServerState::try_from(server_state)?,
        None => {
            let default_state = ServerState::default();
            store_server_state(&db_connection, &(&default_state).into())?;
            default_state
        }
    };
    let upstream_caches = UpstreamCaches::new(
        load_nar_caches(&db_connection)?
            .iter()
            .map(NARCache::try_from)
            .collect::<anyhow::Result<_>>()?,
    );

    let (server_command_tx, server_command_rx) = mpsc::channel::<ServerCommand>(8);
    let (cache_command_tx, cache_command_rx) = mpsc::channel::<UpstreamCacheCommand>(8);

    let (blob_service, directory_service, path_info_service, nar_calculation_service) =
        snix_store::utils::construct_services(arguments.service_addrs.clone()).await?;

    // The signing_path_info service will sign only while serving new path_infos.
    let signing_path_info_service = Arc::new(LazySigningPathInfoService::new(
        path_info_service.clone(),
        server_state.cache_key(),
    ));

    // The management channels are used to fill the cache and potentially to configure
    // it, authenticated.
    let management_routes = snarf::server::services::server_routes(
        &server_state,
        blob_service.clone(),
        directory_service.clone(),
        signing_path_info_service.clone(),
        nar_calculation_service,
    )
    .add_service(
        snarf::server::services::management_service_server::ManagementServiceServer::new(
            snarf::server::services::ManagementServiceWrapper::new(
                server_command_tx,
                cache_command_tx,
                server_state.clone(),
                upstream_caches.clone(),
            ),
        ),
    );

    // The nar-bridge serves the actual cache data, unauthenticated.
    let nar_bridge_state = nar_bridge::AppState::new(
        blob_service.clone(),
        directory_service.clone(),
        signing_path_info_service,
        std::num::NonZero::new(64usize).unwrap(),
    );

    // HTTP
    let app = nar_bridge::gen_router(30)
        .with_state(nar_bridge_state)
        .merge(management_routes.into_axum_router());

    let listen_address = &arguments
        .listen_args
        .listen_address
        .clone()
        .unwrap_or_else(|| {
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

    let services = tokio_listener::axum07::serve(
        listener.unwrap(),
        app.into_make_service_with_connect_info::<tokio_listener::SomeSocketAddrClonable>(),
    )
    .with_graceful_shutdown(shutdown_signal());

    let server_result = snarf::server::state::handle_server_commands(
        &db_connection,
        &server_state,
        server_command_rx,
    );

    let cache_result =
        snarf::cache::handle_cache_commands(&db_connection, &upstream_caches, cache_command_rx);

    tokio::join!(server_result, cache_result, services).2?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal;

        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
