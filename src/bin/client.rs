use std::path::PathBuf;

use futures::{StreamExt, TryStreamExt};

use clap::{Parser, Subcommand};

use nix_compat::store_path::StorePathRef;
use tracing::{debug, info};

tonic::include_proto!("snarf.v1");

/// The commands this client supports
///
/// TODO: make this ergonomic for users
#[derive(Subcommand)]
enum ClientCommand {
    /// Add files from a local Nix store to the cache
    Add {
        path: PathBuf,
    },
    CreateToken,
}

/// CLI arguments for the client
#[derive(Parser)]
struct ClientCli {
    /// The authentication token
    #[arg(short, long, env = "SNARF_CLIENT_TOKEN")]
    token: String,

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
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Add some logging for the moment
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env()) // use RUST_LOG or fallback
        .init();

    let client_cli = ClientCli::parse();

    match client_cli.command {
        // The "add" command is at the moment basically nix-store's "copy" with
        // some dummy authentication slapped on top of it.
        ClientCommand::Add { path } => {
            let store_path = StorePathRef::from_absolute_path_full(&path)?;
            let closure = snarf::database::Closure::for_path(store_path.0)?;

            let url =
                url::Url::parse(format!("grpc+http://{}", client_cli.server_address).as_ref())?;

            let (blob_service, directory_service, path_info_service) =
                snarf::client::clients(client_cli.token.as_ref(), &url).await?;

            let elems: Vec<_> = futures::stream::iter(closure.all_path_infos())
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
                            PathBuf::from(elem.path.to_absolute_path()),
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
        }
        ClientCommand::CreateToken => {
            let mut client = management_service_client::ManagementServiceClient::connect(format!(
                "grpc+http://{}",
                client_cli.server_address
            ))
            .await?;

            let request = tonic::Request::new(NewClientTokenRequest {
                capabilities: vec![],
            });
            let response = client.create_client_token(request).await?;

            info!("Token: {}", response.into_inner().token);
        }
    }

    Ok(())
}
