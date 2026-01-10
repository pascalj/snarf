use std::path::Path;

use rusqlite::{Connection, Result};

refinery::embed_migrations!("sql");

pub struct DbServerState {
    pub paseto_key_bytes: Vec<u8>,
    pub cache_key_bytes: Vec<u8>,
    pub initialized: bool,
}

pub fn connect_database<P: AsRef<Path>>(path: P) -> Result<Connection> {
    let mut inner = rusqlite::Connection::open(path)?;
    migrations::runner()
        .run(&mut inner)
        .expect("Failed to execute the SQL migrations");
    Ok(inner)
}

pub fn load_server_state(connection: Connection) -> Result<DbServerState> {
    connection.query_row(
        "SELECT paseto_key, cache_key FROM server_state",
        [],
        |row| {
            Ok(DbServerState {
                paseto_key_bytes: row.get(0)?,
                cache_key_bytes: row.get(1)?,
                initialized: row.get(2)?,
            })
        },
    )
}
