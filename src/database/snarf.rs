use std::path::Path;

use anyhow::Context;
use rusqlite::{Connection, OptionalExtension, Result};

refinery::embed_migrations!("sql");

#[derive(Clone)]
pub struct DbServerState {
    pub paseto_key_bytes: Vec<u8>,
    pub cache_key_bytes: Vec<u8>,
    pub initialized: bool,
    pub name: String,
}

pub fn connect_database<P: AsRef<Path>>(path: P) -> Result<Connection> {
    let mut connection = rusqlite::Connection::open(path)?;
    migrations::runner()
        .run(&mut connection)
        .context("Running database migrations")
        .expect("Failed to execute the SQL migrations");
    Ok(connection)
}

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

#[cfg(test)]
mod tests {
    use crate::server::ServerState;

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
            store_server_state(&connection, &DbServerState::from(default_state.clone())).unwrap(),
            1
        )
    }

    #[test]
    fn loading_state() {
        let connection = open_database();
        let default_state = ServerState::default();
        store_server_state(&connection, &DbServerState::from(default_state.clone()))
            .expect("Failed to store data");

        let server_state = load_server_state(&connection).expect("Unable to load state");

        assert!(server_state.is_some());
        assert_eq!(server_state.unwrap().name, "snarf");
    }

    #[test]
    fn storing_over_existing_state() {
        let connection = open_database();
        let default_state = ServerState::default();
        store_server_state(&connection, &DbServerState::from(default_state.clone())).unwrap();
        store_server_state(&connection, &DbServerState::from(default_state.clone())).unwrap();

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
}
