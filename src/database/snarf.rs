use std::path::Path;

use anyhow::Context;
use rusqlite::{Connection, OptionalExtension, Result};

refinery::embed_migrations!("sql");

/// Holds data from the database related to the [ServerState]. The purpose of this
/// is to act as a small bridge for serialization.
#[derive(Clone)]
pub struct DbServerState {
    pub paseto_key_bytes: Vec<u8>,
    pub cache_key_bytes: Vec<u8>,
    pub initialized: bool,
    pub name: String,
}

/// Holds data from the database related to the [NARCache].
#[derive(Clone)]
pub struct DbNARCache {
    pub base_url: String,
}

/// Connect to the sqlite database at path.
pub fn connect_database<P: AsRef<Path>>(path: P) -> Result<Connection> {
    let mut connection = rusqlite::Connection::open(path)?;
    migrations::runner()
        .run(&mut connection)
        .context("Running database migrations")
        .expect("Failed to execute the SQL migrations");
    Ok(connection)
}

/// Load the server state from the database.
pub fn load_server_state(connection: &Connection) -> Result<Option<DbServerState>> {
    connection
        .query_row(
            "SELECT paseto_key, cache_key, initialized, cache_name FROM server_state",
            [],
            |row| {
                Ok(DbServerState {
                    paseto_key_bytes: row.get(0)?,
                    cache_key_bytes: row.get(1)?,
                    initialized: row.get(2)?,
                    name: row.get(3)?,
                })
            },
        )
        .optional()
}

/// Store the server state in the database. This will ensure that only one server state
/// exists. Thus, it can be used to initialize or update the server's state.
pub fn store_server_state(connection: &Connection, server_state: &DbServerState) -> Result<usize> {
    connection.execute(
        "INSERT OR REPLACE INTO server_state (id, paseto_key, cache_key, cache_name, initialized) VALUES (1, ?1, ?2, ?3, ?4)",
        (
            &server_state.paseto_key_bytes,
            &server_state.cache_key_bytes,
            &server_state.name,
            &server_state.initialized,
        ),
    )
}

/// Load all nar_caches from the database.
pub fn load_nar_caches(connection: &Connection) -> Result<Vec<DbNARCache>> {
    let mut stmt = connection.prepare("SELECT base_url FROM nar_caches")?;
    stmt.query_map([], |row| {
        Ok(DbNARCache {
            base_url: row.get(0)?,
        })
    })?
    .collect()
}

/// Insert a new cache into the database.
pub fn insert_nar_cache(connection: &Connection, db_nar_cache: &DbNARCache) -> Result<usize> {
    connection.execute(
        "INSERT OR REPLACE INTO nar_caches (base_url) VALUES (?1)",
        [&db_nar_cache.base_url],
    )
}

pub fn remove_nar_cache(connection: &Connection, base_url: &str) -> Result<usize> {
    connection.execute("DELETE FROM nar_caches WHERE base_url == ?1", [base_url])
}

#[cfg(test)]
mod tests {
    use crate::server::state::ServerState;

    use super::*;

    fn open_database() -> Connection {
        let mut connection =
            rusqlite::Connection::open_in_memory().expect("Error opening connection");
        migrations::runner()
            .run(&mut connection)
            .expect("Failed to execute the SQL migrations");
        connection
    }

    #[test]
    fn inserting_default_state() {
        let connection = open_database();
        let default_state = ServerState::default();
        assert_eq!(
            store_server_state(&connection, &DbServerState::from(&default_state)).unwrap(),
            1
        )
    }

    #[test]
    fn loading_state() {
        let connection = open_database();
        let default_state = ServerState::default();
        store_server_state(&connection, &DbServerState::from(&default_state))
            .expect("Failed to store data");

        let server_state = load_server_state(&connection).expect("Unable to load state");

        assert!(server_state.is_some());
        assert_eq!(server_state.unwrap().name, "snarf");
    }

    #[test]
    fn storing_over_existing_state() {
        let connection = open_database();
        let default_state = ServerState::default();
        store_server_state(&connection, &DbServerState::from(&default_state)).unwrap();
        store_server_state(&connection, &DbServerState::from(&default_state)).unwrap();

        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM server_state", [], |row| {
                    let states: i64 = row.get(0)?;
                    Ok(states)
                })
                .expect("Failed to find number of server states"),
            1
        );
    }

    #[test]
    fn loading_nar_caches() {
        let connection = open_database();
        connection
            .execute(
                "INSERT INTO nar_caches (base_url) VALUES (\"https://my.cache.example.com\"), (\"https://other.cache.example.com\")",
                [],
            )
            .expect("Failed to insert");
        let caches = load_nar_caches(&connection).expect("Loading caches failed");
        assert_eq!(caches.len(), 2);
        assert_eq!(
            caches.first().unwrap().base_url,
            "https://my.cache.example.com"
        );
        assert_eq!(
            caches.get(1).unwrap().base_url,
            "https://other.cache.example.com"
        );
    }

    #[test]
    fn inserting_and_removing_caches() {
        let connection = open_database();
        let cache = DbNARCache {
            base_url: "foo".into(),
        };
        let insert_count = insert_nar_cache(&connection, &cache).expect("Inserting cache failed");
        let caches = load_nar_caches(&connection)
            .expect("Loading cache failed")
            .len();
        let deleted = remove_nar_cache(&connection, &cache.base_url).expect("Deleting failed");
        let is_empty = load_nar_caches(&connection)
            .expect("Loading cache failed")
            .is_empty();

        assert_eq!(insert_count, 1);
        assert_eq!(caches, 1);
        assert_eq!(deleted, 1);
        assert!(is_empty)
    }
}
