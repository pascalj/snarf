use ed25519_dalek::SigningKey;

use rusty_paseto::prelude::*;

/// A CacheKey is used to sign the NARs this cache hosts.
///
/// This will result in a "signature" in the NAR info.
#[derive(Clone)]
pub struct CacheKey {
    pub name: String,
    pub signing_key: SigningKey,
}

#[derive(Clone)]
pub struct PasetoKey(SigningKey);

impl Default for PasetoKey {
    fn default() -> Self {
        Self(ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng))
    }
}

impl PasetoKey {
    /// Get the public token that can be given to clients
    pub fn public_token(&self) -> anyhow::Result<String> {
        let keypair_bytes = self.0.to_keypair_bytes();
        let private_key = rusty_paseto::core::PasetoAsymmetricPrivateKey::<V4, Public>::from(
            keypair_bytes.as_slice(),
        );

        let token = rusty_paseto::prelude::GenericBuilder::<V4, Public>::default()
            .set_claim(SubjectClaim::from("manage cache"))
            .try_sign(&private_key)?;

        Ok(token)
    }

    /// Verify a client token for this PasetoState (signing_key). Currently, this
    /// just checks whether it is a valid token, no claims are checked at all.
    pub fn verify_token(&self, token: &str) -> bool {
        let public_key = rusty_paseto::core::Key::<32>::from(self.0.verifying_key().as_bytes());
        let paseto_public_key = PasetoAsymmetricPublicKey::<V4, Public>::from(&public_key);
        rusty_paseto::prelude::GenericParser::<V4, Public>::default()
            .parse(token, &paseto_public_key)
            .is_ok()
    }

    /// Get the underlying bytes of the keypair.
    pub fn to_keypair_bytes(&self) -> [u8; 64] {
        self.0.to_keypair_bytes()
    }

    pub fn from_keypair_bytes(bytes: &[u8; 64]) -> anyhow::Result<Self> {
        Ok(Self(ed25519_dalek::SigningKey::from_keypair_bytes(bytes)?))
    }
}

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
