use std::{
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use clap::Parser;

use snarf::management::{self, ServerState};

use tracing::{debug, info};

use directories::ProjectDirs;

#[derive(Parser)]
struct Arguments {
    /// The name of the cache, for example for signing info.
    #[clap(short, long, default_value = "snarf")]
    cache_name: String,

    /// The path to the paseto key file as raw bytes.
    #[arg(short, long, default_value = server_key_file_default())]
    private_key_file: PathBuf,

    /// The Snix store service URLs that are used for the underlying store.
    /// TODO: have better default paths using ProjectDirs.
    #[clap(flatten)]
    service_addrs: snix_store::utils::ServiceUrls,

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
        snix_store::utils::construct_services(arguments.service_addrs).await?;

    let server_state = if !std::fs::exists(arguments.private_key_file.clone())? {
        let state = ServerState::default();

        // TODO: make this safe when the keypair is initialized on request.
        // if let Some(parent) = arguments.private_key_file.parent() {
        //     std::fs::create_dir_all(parent)?;
        //     // TODO: save in nix-compatible form (name:base64)
        //     std::fs::write(arguments.private_key_file.clone(), state.key_bytes())?;
        // }

        // info!(
        //     file=%arguments.private_key_file.display(),
        //     "Generated and wrote a new private key",
        // );

        state
    } else {
        debug!(file=%arguments.private_key_file.display(),  "Reading keypair");
        std::fs::read(arguments.private_key_file).and_then(|x| {
            ServerState::try_from(x.as_slice()).map_err(|err| std::io::Error::other(err))
        })?
    };

    // For now we can just re-use the server's private key for signing.
    // TODO: make this configurable to override with a different key
    let signing_key =
        nix_compat::narinfo::SigningKey::new(arguments.cache_name, server_state.signing_key());

    // The signing_path_info service will sign only while serving new path_infos.
    let signing_path_info_service = Arc::new(management::LazySigningPathInfoService::new(
        path_info_service.clone(),
        Arc::new(signing_key),
    ));

    // The management channels are used to fill the cache and potentially to configure
    // it, authenticated.
    let management_routes = management::server_routes(
        Arc::new(RwLock::new(server_state)),
        blob_service.clone(),
        directory_service.clone(),
        signing_path_info_service.clone(),
        nar_calculation_service,
    );

    // The nar-bridge serves the actual cache data, unauthenticated.
    let nar_bridge_state = nar_bridge::AppState::new(
        blob_service.clone(),
        directory_service.clone(),
        signing_path_info_service.clone(),
        std::num::NonZero::new(64usize).unwrap(),
    );

    // HTTP
    let app = nar_bridge::gen_router(30)
        .with_state(nar_bridge_state)
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

    let shutdown = async {
        info!("Press Cltr-C for graceful shutdown.");
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl-C handler");
    };

    tokio_listener::axum07::serve(
        listener.unwrap(),
        app.into_make_service_with_connect_info::<tokio_listener::SomeSocketAddrClonable>(),
    )
    .with_graceful_shutdown(shutdown)
    .await?;

    Ok(())
}

/// The server key default path. It's a bit unwieldy. Revisit when https://github.com/clap-rs/clap/issues/4558 is fixed.
fn server_key_file_default() -> String {
    ProjectDirs::from("de.pascalj.snarf", "", "snarf")
        .map(|dir| Path::join(dir.config_dir(), "server_key.bin"))
        .expect("Unable to construct key path")
        .to_str()
        .unwrap_or("server_key.bin")
        .to_owned()
}
