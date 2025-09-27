use std::{
    error::Error,
    path::{Path, PathBuf},
};

use clap::Parser;

use snarf::management::{self, PasetoState};

use tracing::{debug, error, info};

use directories::ProjectDirs;

#[derive(Parser)]
struct Arguments {
    #[clap(flatten)]
    service_addrs: snix_store::utils::ServiceUrls,

    /// The path to the paseto key file as raw bytes
    #[arg(short, long, default_value = server_key_file_default())]
    private_key_file: PathBuf,

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

    let paseto_state = if !std::fs::exists(arguments.private_key_file.clone())? {
        let state = PasetoState::default();

        if let Some(parent) = arguments.private_key_file.parent() {
            std::fs::create_dir_all(parent)?;
            std::fs::write(arguments.private_key_file.clone(), state.key_bytes())?;
        }

        info!(
            file=%arguments.private_key_file.display(),
            "Generated and wrote a new private key",
        );
        state
    } else {
        debug!(file=%arguments.private_key_file.display(),  "Reading private key");
        std::fs::read(arguments.private_key_file).and_then(|x| {
            PasetoState::try_from(x.as_slice()).map_err(|err| std::io::Error::other(err))
        })?
    };

    match paseto_state.public_token() {
        Ok(token) => info!(token=%token, "Client token"),
        Err(err) => error!(
            "Failed to create client token: {}",
            err.source().expect("No error source available").to_string()
        ),
    }

    let management_routes = management::server_routes(
        &paseto_state,
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

    let shutdown = async {
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
