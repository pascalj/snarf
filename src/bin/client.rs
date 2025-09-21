use std::path::PathBuf;

use serde::Deserialize;
use serde::Serialize;

use futures::StreamExt;
use futures::TryStreamExt;

use clap::{Parser, Subcommand};

#[derive(Subcommand)]
enum ClientCommand {
    Add {
        #[clap(flatten)]
        service_addrs: snix_store::utils::ServiceUrlsGrpc,

        #[arg(value_name = "NIX_ATTRS_JSON_FILE", env = "NIX_ATTRS_JSON_FILE")]
        reference_graph_path: PathBuf,
    },
}

#[derive(Parser)]
struct ClientCli {
    #[command(subcommand)]
    command: ClientCommand,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client_cli = ClientCli::parse();
    match client_cli.command {
        ClientCommand::Add {
            service_addrs,
            reference_graph_path,
        } => {
            let (blob_service, directory_service, path_info_service, _nar_calculation_service) =
                snix_store::utils::construct_services(service_addrs).await?;

            snix_castore::proto::blob_service_client::BlobServiceClient::with_interceptor(
                snix_castore::proto::GRPCBlobServiceWrapper::new(blob_service),
                check_auth,
            );
            // Parse the file at reference_graph_path.
            let reference_graph_json = if reference_graph_path == PathBuf::from("-") {
                let mut writer: Vec<u8> = vec![];
                tokio::io::copy(&mut tokio::io::stdin(), &mut writer).await?;
                writer
            } else {
                tokio::fs::read(&reference_graph_path).await?
            };

            #[derive(Deserialize, Serialize)]
            struct ReferenceGraph<'a> {
                #[serde(borrow)]
                closure: Vec<nix_compat::path_info::ExportedPathInfo<'a>>,
            }

            let reference_graph: ReferenceGraph<'_> =
                serde_json::from_slice(reference_graph_json.as_slice())?;

            // From our reference graph, lookup all pathinfos that might exist.
            let elems: Vec<_> = futures::stream::iter(reference_graph.closure)
                .map(|elem| {
                    let path_info_service = path_info_service.clone();
                    async move {
                        let resp = path_info_service
                            .get(*elem.path.digest())
                            .await
                            .map(|resp| (elem, resp));
                        resp
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

            // Run ingest_path on all of them.
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

            // Insert them into the PathInfoService.
            // FUTUREWORK: do this properly respecting the reference graph.
            for (elem, root_node) in uploads {
                // Create and upload a PathInfo pointing to the root_node,
                // annotated with information we have from the reference graph.
                let path_info = snix_store::path_info::PathInfo {
                    store_path: elem.path.to_owned(),
                    node: root_node,
                    references: elem
                        .references
                        .iter()
                        .map(nix_compat::store_path::StorePath::to_owned)
                        .collect(),
                    nar_size: elem.nar_size,
                    nar_sha256: elem.nar_sha256,
                    signatures: elem.signatures.iter().map(|s| s.to_owned()).collect(),
                    deriver: elem.deriver.map(|p| p.to_owned()),
                    ca: None,
                };

                path_info_service.put(path_info).await?;
            }
        }
    }

    Ok(())
}
