use ed25519_dalek::SigningKey;

/// A CacheKey is used to sign the NARs this cache hosts.
///
/// This will result in a "signature" in the NAR info.
#[derive(Clone)]
pub struct CacheKey {
    pub name: String,
    pub signing_key: SigningKey,
}

pub type PasetoKey = SigningKey;

/// A keypair for signing the cache's contents
///
/// This is not to be confused with the keys to authorize remote actions on the keys, which is done via the PasetoKeypair.
impl CacheKey {
    /// Create a new [CacheKey] with a fresh signing key.
    pub fn new(name: &str) -> Self {
        use rand_core::OsRng;
        Self {
            name: name.into(),
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    /// Create a [CacheKey] from an existing ed25519 key.
    pub fn with_signing_key(name: &str, signing_key: SigningKey) -> Self {
        Self {
            name: name.into(),
            signing_key,
        }
    }

    /// Return the key for signing NARs in the store.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

impl From<&CacheKey> for nix_compat::narinfo::SigningKey<SigningKey> {
    fn from(cache_keypair: &CacheKey) -> nix_compat::narinfo::SigningKey<SigningKey> {
        Self::new(
            cache_keypair.name.clone(),
            cache_keypair.signing_key.clone(),
        )
    }
}
