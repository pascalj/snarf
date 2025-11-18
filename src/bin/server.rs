use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use clap::Parser;

use ed25519_dalek::{pkcs8::DecodePrivateKey, pkcs8::EncodePrivateKey};
use snarf::server::{self, CacheKeypair, ServerCommand};

use tokio::sync::mpsc;

use tracing::info;

#[derive(thiserror::Error, Debug)]
enum Error {
    #[error("PKCS processing error: {0}")]
    PKCS(ed25519_dalek::pkcs8::Error),
    #[error("Snarf server error: {0}")]
    Server(server::Error),
    #[error("IO error: {0}")]
    IO(std::io::Error),
}

#[derive(Parser)]
struct Arguments {
    /// The name of the cache, for example for signing info.
    #[clap(long, default_value = "snarf")]
    cache_name: String,

    /// The path to the paseto key file as raw bytes.
    #[arg(long, env, default_value = "/var/lib/snarf/paseto_keypair.key")]
    paseto_key_file: PathBuf,

    /// The path to the cache key file as created by `nix-store --generate-binary-cache-key`.
    #[arg(long, env, default_value = "/var/lib/snarf/cache_keypair.key")]
    cache_keypair_file: PathBuf,

    /// The Snix store service URLs that are used for the underlying store.
    /// TODO: have better default paths using ProjectDirs.
    #[clap(flatten)]
    service_addrs: snix_store::utils::ServiceUrls,

    /// The address to listen on.
    #[clap(flatten)]
    listen_args: tokio_listener::ListenerAddressLFlag,
}

fn load_paseto_keypair(path: &Path) -> Result<server::PasetoKeypair, Error> {
    ed25519_dalek::SigningKey::read_pkcs8_der_file(path).map_err(&Error::PKCS)
}

fn serialize_new_paseto_keypair(path: PathBuf) -> Result<server::PasetoKeypair, Error> {
    std::fs::create_dir_all(path.parent().unwrap()).map_err(&Error::IO)?;
    use rand_core::OsRng;
    let key = ed25519_dalek::SigningKey::generate(&mut OsRng);
    key.write_pkcs8_der_file(path).map_err(&Error::PKCS)?;
    Ok(key)
}

fn load_cache_keypair(path: &Path) -> Result<server::CacheKeypair, Error> {
    server::deserialize_nix_store_signing_key(&path).map_err(&Error::Server)
}

fn serialize_new_cache_keypair(path: PathBuf) -> Result<server::CacheKeypair, Error> {
    use rand_core::OsRng;
    let key = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let cache_key = CacheKeypair::new("snarf".into(), Some(key));
    server::serialize_nix_store_signing_key(&path, &cache_key).map_err(&Error::Server)?;
    Ok(cache_key)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Add some logging for the moment
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env()) // use RUST_LOG or fallback
        .init();

    let arguments = Arguments::parse();

    let paseto_key = if arguments.paseto_key_file.exists() {
        load_paseto_keypair(&arguments.paseto_key_file)
    } else {
        serialize_new_paseto_keypair(arguments.paseto_key_file)
    }?;

    let cache_key = if arguments.cache_keypair_file.exists() {
        load_cache_keypair(&arguments.cache_keypair_file)
    } else {
        serialize_new_cache_keypair(arguments.cache_keypair_file)
    }?;
    let new_server_state = Arc::new(std::sync::Mutex::new(server::ServerState::new(
        &paseto_key,
        &cache_key,
    )));

    loop {
        let (command_sender, mut command_receiver) = mpsc::channel::<ServerCommand>(8);
        let do_shutdown = Arc::new(std::sync::Mutex::new(false));

        let do_shutdown_copy = do_shutdown.clone();
        let shutdown = async move {
            info!("Press Cltr-C for graceful shutdown.");
            tokio::select! {
                _= tokio::signal::ctrl_c() => {
                    *do_shutdown_copy.lock().unwrap() = true;
                }
                action = command_receiver.recv() => {
                    match action {
                        Some(ServerCommand::Shutdown) => {
                            *do_shutdown_copy.lock().unwrap() = false;
                        },
                        None => {}
                    }
                }
            }
        };

        let (blob_service, directory_service, path_info_service, nar_calculation_service) =
            snix_store::utils::construct_services(arguments.service_addrs.clone()).await?;
        // The signing_path_info service will sign only while serving new path_infos.
        let signing_path_info_service = Arc::new(server::LazySigningPathInfoService::new(
            path_info_service.clone(),
            cache_key.clone(),
        ));

        let server_state = new_server_state.clone().lock().unwrap().clone();

        // The management channels are used to fill the cache and potentially to configure
        // it, authenticated.
        let management_routes = snarf::server::server_routes(
            &command_sender,
            &server_state,
            blob_service.clone(),
            directory_service.clone(),
            signing_path_info_service.clone(),
            nar_calculation_service,
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

        let serve = tokio_listener::axum07::serve(
            listener.unwrap(),
            app.into_make_service_with_connect_info::<tokio_listener::SomeSocketAddrClonable>(),
        )
        .with_graceful_shutdown(shutdown);

        serve.await?;

        if *do_shutdown.lock().unwrap() {
            break;
        }
    }

    Ok(())
}
