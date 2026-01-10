use ed25519_dalek::SigningKey;

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
    /// Create a new keypair, possibly from an existing ed25519 key. If the key is not given, a new one is generated.
    pub fn new(name: &str, signing_key: Option<SigningKey>) -> Self {
        use rand_core::OsRng;
        Self {
            name: name.into(),
            signing_key: signing_key.unwrap_or(SigningKey::generate(&mut OsRng)),
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
