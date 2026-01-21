use reqwest::Client;
use tracing::debug;

use crate::database::snarf::DbNARCache;

/// Represents an upstream NAR cache.
///
/// It can be queried to avoid duplicate storage.
#[derive(Clone)]
pub struct NARCache {
    base_url: String,
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
