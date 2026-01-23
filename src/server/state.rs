use crate::keys::{CacheKey, PasetoKey};

/// State that is needed to perform operations on the PASETO tokens.
#[derive(Clone)]
pub struct ServerState {
    /// The underlying signing key bytes. First 32 bytes are private key, remaining 32 bytes are the public key.
    /// We use ed25519-dalek SigningKey here and just dynamically create the PasetoAsymmetric keys.
    paseto_key: PasetoKey,

    /// The key that is used for signing the narinfo.
    cache_key: CacheKey,

    /// Whether the server was initialized. An uninitialized server may create tokens
    /// for unauthorized users to make the setup easier.
    initialized: bool,
}

pub mod persistence {
    use crate::database::snarf::DbServerState;
    use crate::keys::{CacheKey, PasetoKey};

    use super::ServerState;

    /// Try to construct a ServerState from a deserialized [DbServerState]
    pub fn from_database_state(db_state: DbServerState) -> anyhow::Result<ServerState> {
        let paseto_key =
            PasetoKey::from_keypair_bytes(db_state.paseto_key_bytes.as_slice().try_into()?)?;
        let cache_key = CacheKey::with_signing_key(
            &db_state.name,
            db_state.cache_key_bytes.as_slice().try_into()?,
        )?;
        Ok(ServerState {
            paseto_key,
            cache_key,
            initialized: db_state.initialized,
        })
    }

    /// Construct a [DbServerState] for serialization.
    pub fn to_database_state(server_state: &ServerState) -> DbServerState {
        DbServerState {
            paseto_key_bytes: server_state.paseto_key.to_keypair_bytes().into(),
            cache_key_bytes: server_state
                .cache_key
                .signing_key()
                .to_keypair_bytes()
                .into(),
            initialized: server_state.initialized,
            name: server_state.cache_key.name.clone(),
        }
    }
}

impl TryFrom<crate::database::snarf::DbServerState> for ServerState {
    type Error = anyhow::Error;

    fn try_from(dto: crate::database::snarf::DbServerState) -> anyhow::Result<Self> {
        persistence::from_database_state(dto)
    }
}

impl From<&ServerState> for crate::database::snarf::DbServerState {
    fn from(val: &ServerState) -> Self {
        persistence::to_database_state(val)
    }
}

impl ServerState {
    /// Get the server's keypair as bytes. This is used for the authentication.
    pub fn key_bytes(&self) -> [u8; 64] {
        self.paseto_key.to_keypair_bytes()
    }

    /// Return the [PasetoKey] for this server's state.
    pub fn paseto_key(&self) -> PasetoKey {
        self.paseto_key.clone()
    }

    /// Get the Nix cache's key. This one is used to sign the NARs.
    pub fn cache_key(&self) -> CacheKey {
        self.cache_key.clone()
    }

    /// Initialize the server. Once initialized, `create-token` is a noop and
    /// will not reveal the initial token.
    pub fn initialize(&mut self) {
        self.initialized = true;
    }

    /// Returns whether the server has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

impl Default for ServerState {
    /// Create a new server from scratch. This is typically only useful for testing
    /// or the very first startup, since it generates new keys.
    fn default() -> Self {
        let cache_key = CacheKey::new("snarf");
        let paseto_key = PasetoKey::default();
        Self {
            cache_key,
            paseto_key,
            initialized: false,
        }
    }
}
