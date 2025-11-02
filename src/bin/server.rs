use std::{
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use clap::Parser;

use ed25519_dalek::{pkcs8::DecodePrivateKey, pkcs8::EncodePrivateKey};
use snarf::server::{self, CacheKeypair};

use tracing::info;

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

fn load_paseto_keypair(
    path: &Path,
) -> Result<Option<server::PasetoKeypair>, ed25519_dalek::pkcs8::Error> {
    if path.exists() {
        return Ok(Some(
            ed25519_dalek::SigningKey::read_pkcs8_der_file(path).unwrap(),
        ));
    }
    Ok(None)
}

fn serialize_new_paseto_keypair(path: PathBuf) -> Result<server::PasetoKeypair, server::Error> {
    use rand_core::OsRng;
    let key = ed25519_dalek::SigningKey::generate(&mut OsRng);
    key.write_pkcs8_der_file(path).unwrap();
    Ok(key)
}

fn load_cache_keypair(path: &Path) -> Result<Option<server::CacheKeypair>, server::Error> {
    if path.exists() {
        let cache_key = server::deserialize_nix_store_signing_key(&path)?;
        return Ok(Some(cache_key));
    }
    Ok(None)
}

fn serialize_new_cache_keypair(path: PathBuf) -> Result<server::CacheKeypair, server::Error> {
    use rand_core::OsRng;
    let key = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let cache_key = CacheKeypair::new("snarf".into(), Some(key));
    server::serialize_nix_store_signing_key(&path, &cache_key)?;
    Ok(cache_key)
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

    let paseto_key = load_paseto_keypair(&arguments.paseto_key_file)
        .or_else(|err| Some(serialize_new_paseto_keypair(arguments.paseto_key_file)).transpose())
        .unwrap();

    let cache_key = load_cache_keypair(&arguments.cache_keypair_file)
        .or_else(|err| Some(serialize_new_cache_keypair(arguments.cache_keypair_file)).transpose())
        .unwrap()
        .unwrap();

    let server_state = server::ServerState::new(&paseto_key.unwrap(), &cache_key);

    // The signing_path_info service will sign only while serving new path_infos.
    let signing_path_info_service = Arc::new(snarf::server::LazySigningPathInfoService::new(
        path_info_service.clone(),
        cache_key.clone(),
    ));

    // The management channels are used to fill the cache and potentially to configure
    // it, authenticated.
    let management_routes = snarf::server::server_routes(
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
