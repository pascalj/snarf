use std::str::FromStr;

use anyhow::bail;
use futures::{StreamExt, TryStreamExt};

use clap::{Parser, Subcommand};

use nix_compat::store_path::StorePathRef;
use snarf::{client::ClientPasetoTokenInterceptor, database::nix::LocalPathInfo};
use tokio::sync::mpsc;
use tracing::{debug, info};

tonic::include_proto!("snarf.v1");

/// The commands this client supports
#[derive(Subcommand)]
enum ClientCommand {
    /// Add files from a local Nix store to the cache
    AddClosure {
        /// The authentication token
        #[arg(short, long, env = "SNARF_CLIENT_TOKEN", required = true)]
        token: String,
        store_path: std::path::PathBuf,
    },
    /// Create a new token on a freshly initialized server
    CreateToken,
    /// Add an upstream cache server for Snarf to check before uploading
    AddUpstreamCache {
        /// The authentication token
        #[arg(short, long, env = "SNARF_CLIENT_TOKEN", required = true)]
        token: String,
        /// The base_url of the upstream cache
        base_url: String,
    },
    /// List all configured upstream caches
    ListUpstreamCaches {
        /// The authentication token
        #[arg(short, long, env = "SNARF_CLIENT_TOKEN", required = true)]
        token: String,
    },
}

/// CLI arguments for the client
#[derive(Parser)]
struct ClientCli {
    /// The server address, currently expecting grpc+http as a protocol, but
    /// that is likely to change to make it easier for users.
    #[arg(
        short,
        long,
        env = "SNARF_SERVER_ADDRESS",
        default_value = "localhost:9000"
    )]
    server_address: String,

    /// The command to execute
    #[command(subcommand)]
    command: ClientCommand,
}

#[tokio::main]
async fn main() -> anyhow::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Add some logging for the moment
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env()) // use RUST_LOG or fallback
        .init();

    let client_cli = ClientCli::parse();

    match &client_cli.command {
        ClientCommand::AddClosure { .. } => add_closure(&client_cli).await?,
        ClientCommand::CreateToken => create_token(&client_cli).await?,
        ClientCommand::AddUpstreamCache { .. } => add_upstream_cache(&client_cli).await?,
        ClientCommand::ListUpstreamCaches { .. } => list_upstream_caches(&client_cli).await?,
    };

    Ok(())
}

/// Add the closure of a path in the store to the cache. The path can be of arbitrary depth, in any case
/// the complete nar and its closure will be added.
async fn add_closure(
    client_cli: &ClientCli,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ClientCommand::AddClosure { token, store_path } = &client_cli.command else {
        return Ok(());
    };

    let store_path = StorePathRef::from_absolute_path_full(&store_path)?;
    let closure = snarf::database::nix::Closure::for_path(store_path.0)?;

    let url = url::Url::parse(format!("grpc+http://{}", client_cli.server_address).as_ref())?;

    let (blob_service, directory_service, path_info_service) =
        snarf::client::clients(token, &url).await?;

    // TODO: factor the following section into its own function or even module for
    // uploading.
    let hashes = closure
        .all_path_infos()
        .iter()
        .map(|p| *p.path.digest())
        .collect();

    let upstream_flags = flag_upstream_nars(client_cli, hashes).await?;
    let to_upload: Vec<LocalPathInfo> = closure
        .all_path_infos()
        .iter()
        .zip(upstream_flags.iter())
        .filter_map(|(p, &is_up)| if !is_up { Some(p.clone()) } else { None })
        .collect();

    info!(
        "Found {} of {} NAR in upstream caches, uploading {}",
        to_upload.len(),
        upstream_flags.len(),
        upstream_flags.len() - to_upload.len()
    );

    let elems: Vec<_> = futures::stream::iter(to_upload)
        .map(|elem| {
            let path_info_service = path_info_service.clone();
            async move {
                path_info_service
                    .get(*elem.path.digest())
                    .await
                    .map(|resp| (elem, resp))
            }
        })
        .buffer_unordered(50)
        .try_filter_map(|(elem, path_info)| {
            std::future::ready(if path_info.is_none() {
                Ok(Some(elem))
            } else {
                Ok(None)
            })
        })
        .try_collect()
        .await?;

    debug!(missing=%elems.len(), "Parsed elements from the reference graph");

    // Run ingest_path on all of them.
    // TODO: rework this for progress metering
    let uploads: Vec<_> = futures::stream::iter(elems)
        .map(|elem| {
            // Map to a future returning the root node, alongside with the closure info.
            let blob_service = blob_service.clone();
            let directory_service = directory_service.clone();
            async move {
                snix_castore::import::fs::ingest_path::<_, _, _, &[u8]>(
                    blob_service,
                    directory_service,
                    std::path::PathBuf::from(elem.path.to_absolute_path()),
                    None,
                )
                .await
                .map(|root_node| (elem, root_node))
            }
        })
        .buffer_unordered(10)
        .try_collect()
        .await?;

    info!(uploads=%uploads.len(), "Uploaded data");

    // Insert them into the PathInfoService.
    // FUTUREWORK: do this properly respecting the reference graph.
    for (elem, root_node) in uploads {
        // Create and upload a PathInfo pointing to the root_node,
        // annotated with information we have from the reference graph.
        let path_info = snix_store::path_info::PathInfo {
            store_path: elem.path.to_owned(),
            node: root_node,
            references: closure
                .references_for_path(elem.valid_path_id)
                .iter()
                .map(nix_compat::store_path::StorePath::to_owned)
                .collect(),
            nar_size: elem.nar_size,
            nar_sha256: elem.nar_sha256,
            signatures: elem.signatures.iter().map(|s| s.to_owned()).collect(),
            deriver: elem.deriver.clone(),
            ca: None,
        };

        path_info_service.put(path_info).await?;
    }

    info!("Uploaded PathInfo entries");

    Ok(())
}

async fn create_token(client_cli: &ClientCli) -> anyhow::Result<()> {
    let request = tonic::Request::new(NewClientTokenRequest {
        capabilities: vec![],
    });
    let response = get_client(&client_cli.server_address, None)
        .await?
        .create_client_token(request)
        .await?;

    println!("{}", response.into_inner().token);

    Ok(())
}

async fn flag_upstream_nars(
    client_cli: &ClientCli,
    hashes: Vec<[u8; 20]>,
) -> anyhow::Result<Vec<bool>> {
    let (tx, rx) = mpsc::channel::<NarHashRequest>(20);
    tokio::spawn(async move {
        for h in hashes {
            if tx.send(NarHashRequest { digest: h.into() }).await.is_err() {
                break;
            }
        }
    });

    let in_stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let response = get_client(&client_cli.server_address, None)
        .await?
        .filter_hashes(in_stream)
        .await?;

    let resp_stream = response.into_inner();

    Ok(resp_stream
        .map_ok(|msg| msg.is_upstream)
        .try_collect()
        .await?)
}

async fn add_upstream_cache(client_cli: &ClientCli) -> anyhow::Result<()> {
    let ClientCommand::AddUpstreamCache { token, base_url } = &client_cli.command else {
        bail!("Upstream cache called with the wrong command");
    };

    let response = get_client(&client_cli.server_address, Some(token))
        .await?
        .add_upstream_cache(tonic::Request::new(AddUpstreamCacheRequest {
            base_url: base_url.into(),
        }))
        .await?;

    if !response.into_inner().success {
        bail!("Could not add the upstream cache");
    }

    Ok(())
}

async fn list_upstream_caches(client_cli: &ClientCli) -> anyhow::Result<()> {
    let ClientCommand::ListUpstreamCaches { token } = &client_cli.command else {
        bail!("Upstream cache called with the wrong command");
    };

    let response = get_client(&client_cli.server_address, Some(token))
        .await?
        .list_upstream_caches(tonic::Request::new(ListUpstreamCachesRequest {}))
        .await?;

    for base_url in response.into_inner().base_urls {
        println!("{}", base_url);
    }

    Ok(())
}

/// Get a client to connect to the server at server_address.
///
/// An optional token can be passed to authenticate the requests.
async fn get_client(
    server_address: &str,
    token: Option<&str>,
) -> anyhow::Result<
    management_service_client::ManagementServiceClient<
        tonic::service::interceptor::InterceptedService<
            tonic::transport::Channel,
            ClientPasetoTokenInterceptor,
        >,
    >,
> {
    let url = format!("grpc+http://{}", server_address);
    let channel = tonic::transport::Endpoint::from_str(url.as_ref())?
        .connect()
        .await?;

    Ok(
        management_service_client::ManagementServiceClient::with_interceptor(
            channel,
            ClientPasetoTokenInterceptor::from(token.unwrap_or_default()),
        ),
    )
}
