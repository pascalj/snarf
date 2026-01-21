use std::{path::PathBuf, sync::Arc};

use clap::Parser;

use snarf::cache::NARCache;
use snarf::database::snarf::{load_nar_caches, store_server_state};
use snarf::server::ServerCommand;
use snarf::{
    database::snarf::{connect_database, load_server_state},
    server::{LazySigningPathInfoService, ServerState},
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

    loop {
        if let ServerTransition::Shutdown = start_server(&arguments).await? {
            break;
        };
    }

    Ok(())
}

/// The new state of the main loop.
enum ServerTransition {
    Shutdown,
    Restart,
}

/// The signal to shutdown the server.
///
/// This is supposed to be send to axum to perform a graceful shutdown on request.
enum ShutdownCommand {
    Shutdown,
}

/// Start the actual server handling incoming client connections.
///
/// This also sets up the communication between internal signal handlers,
/// for example for restarting or shutdding down the server
async fn start_server(
    arguments: &Arguments,
) -> anyhow::Result<ServerTransition, Box<dyn std::error::Error + Send + Sync>> {
    let db_connection = connect_database(arguments.state_directory.as_path().join("snarf.sqlite"))?;
    let server_state = match load_server_state(&db_connection)? {
        Some(server_state) => ServerState::try_from(server_state)?,
        None => {
            let default_state = ServerState::default();
            store_server_state(&db_connection, &(&default_state).into())?;
            default_state
        }
    };
    let upstream_caches = load_nar_caches(&db_connection)?
        .iter()
        .map(NARCache::try_from)
        .collect::<anyhow::Result<_>>()?;

    let (command_sender, command_receiver) = mpsc::channel::<ServerCommand>(8);
    let (shutdown_sender, mut shutdown_receiver) = mpsc::channel::<ShutdownCommand>(1);

    let (blob_service, directory_service, path_info_service, nar_calculation_service) =
        snix_store::utils::construct_services(arguments.service_addrs.clone()).await?;

    // The signing_path_info service will sign only while serving new path_infos.
    let signing_path_info_service = Arc::new(LazySigningPathInfoService::new(
        path_info_service.clone(),
        server_state.cache_key(),
    ));

    // The management channels are used to fill the cache and potentially to configure
    // it, authenticated.
    let management_routes = snarf::server::server_routes(
        &server_state,
        blob_service.clone(),
        directory_service.clone(),
        signing_path_info_service.clone(),
        nar_calculation_service,
    )
    .add_service(
        snarf::server::management_service_server::ManagementServiceServer::new(
            snarf::server::ManagementServiceWrapper::new(
                &command_sender,
                &server_state.paseto_key(),
                upstream_caches,
                server_state.is_initialized(),
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
    let shutdown = async move {
        info!("Press Cltr-C for graceful shutdown.");
        shutdown_receiver.recv().await;
    };
    // _= tokio::signal::ctrl_c() => { }
    let services = tokio_listener::axum07::serve(
        listener.unwrap(),
        app.into_make_service_with_connect_info::<tokio_listener::SomeSocketAddrClonable>(),
    )
    .with_graceful_shutdown(shutdown);

    let result = handle_server_commands(
        &db_connection,
        &server_state,
        command_receiver,
        shutdown_sender,
    );

    Ok(tokio::join!(result, services).0)
}

/// Handle internal server commands.
///
/// This can update the server state and then pass the shutdown/restart commands
/// on to axum, so that it reloads the services with the new state.
async fn handle_server_commands(
    db_connection: &rusqlite::Connection,
    server_state: &ServerState,
    mut command_receiver: mpsc::Receiver<ServerCommand>,
    shutdown_sender: mpsc::Sender<ShutdownCommand>,
) -> ServerTransition {
    tokio::select! {
        command = command_receiver.recv() => {
            match command {
                Some(ServerCommand::MarkInitialized) => {
                     let mut new_state = server_state.clone();
                     new_state.initialize();
                     let db_server_state = snarf::database::snarf::DbServerState::from(&new_state);
                    store_server_state(db_connection, &db_server_state)
                                .expect("Updating the server state");
                    shutdown_sender
                                .send(ShutdownCommand::Shutdown)
                                .await
                                .expect("Sending the shutdown signal");
                            ServerTransition::Restart
                },
                Some(ServerCommand::Shutdown) => {
                    shutdown_sender
                            .send(ShutdownCommand::Shutdown)
                                .await
                                .expect("Sending the shutdown signal");
                            ServerTransition::Shutdown
                }
                None => ServerTransition::Restart,
            }
        }
        _ = tokio::signal::ctrl_c() => ServerTransition::Shutdown
    }
}
