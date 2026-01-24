use std::sync::Arc;

use arc_swap::ArcSwap;
use reqwest::Client;
use tokio::sync::mpsc;
use tracing::debug;

use crate::database::snarf::{DbNARCache, insert_nar_cache};

/// Represents an upstream NAR cache.
///
/// It can be queried to avoid duplicate storage.
#[derive(Clone)]
pub struct NARCache {
    base_url: String,
}

pub enum UpstreamCacheCommand {
    Add { base_url: String },
}

#[derive(Clone)]
pub struct UpstreamCaches {
    nar_caches: Arc<ArcSwap<Vec<NARCache>>>,
}

impl UpstreamCaches {
    pub fn new(nar_caches: Vec<NARCache>) -> Self {
        Self {
            nar_caches: Arc::new(ArcSwap::from(Arc::new(nar_caches))),
        }
    }

    pub fn caches(&self) -> Arc<Vec<NARCache>> {
        self.nar_caches.load_full()
    }

    pub fn replace_caches(&self, new_caches: Vec<NARCache>) {
        self.nar_caches.store(Arc::new(new_caches));
    }
}

impl NARCache {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches("/").into(),
        }
    }

    /// Test a list of hashes against this cache. Returns the hashes that are not in this cache.
    pub async fn has_nar_hash(&self, client: &Client, nar_hash: &[u8]) -> anyhow::Result<bool> {
        let url = format!(
            "{}/{}.narinfo",
            self.base_url,
            nix_compat::nixbase32::encode(nar_hash)
        );

        debug!("Checking narinfo {} for existence", url);
        Ok(client.head(&url).send().await?.status().is_success())
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

pub mod persistence {
    use crate::database::snarf::DbNARCache;

    use super::NARCache;

    /// Try to construct a ServerState from a deserialized [DbServerState]
    pub fn from_database(db_nar_cache: &DbNARCache) -> anyhow::Result<NARCache> {
        Ok(NARCache {
            base_url: db_nar_cache.base_url.clone(),
        })
    }

    /// Construct a [DbServerState] for serialization.
    pub fn to_database(nar_cache: &NARCache) -> DbNARCache {
        DbNARCache {
            base_url: nar_cache.base_url.clone(),
        }
    }
}

impl TryFrom<&DbNARCache> for NARCache {
    type Error = anyhow::Error;

    fn try_from(dto: &DbNARCache) -> anyhow::Result<Self> {
        persistence::from_database(dto)
    }
}

impl From<&NARCache> for DbNARCache {
    fn from(value: &NARCache) -> Self {
        persistence::to_database(value)
    }
}

pub async fn handle_cache_commands(
    db_connection: &rusqlite::Connection,
    upstream_caches: &UpstreamCaches,
    mut command_receiver: mpsc::Receiver<UpstreamCacheCommand>,
) {
    while let Some(command) = command_receiver.recv().await {
        match command {
            UpstreamCacheCommand::Add { base_url } => {
                let cache = NARCache::new(&base_url);
                let mut new_caches = upstream_caches.caches().to_vec();
                new_caches.push(cache.clone());
                upstream_caches.replace_caches(new_caches);
                insert_nar_cache(db_connection, &(&cache).into()).expect("Cache insertion failed.");
            }
        }
    }
}
