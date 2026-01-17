use std::collections::HashMap;

use nix_compat::{
    narinfo::Signature,
    nixhash::{HashAlgo, NixHash},
    store_path::StorePathRef,
};
use rusqlite::{Connection, Result};

/// Representation of a closure computed from the database.
///
/// The closure is computed once for a path and it is only valid
/// to query for information related to that path.
pub struct Closure {
    path_infos: Vec<LocalPathInfo>,
    references: HashMap<u64, Vec<nix_compat::store_path::StorePath<String>>>,
}

impl Closure {
    /// Create a [Closure] for a given store path. This will query
    /// the local database for this information. No checks whether
    /// the files actually exist are performed.
    pub fn for_path(path: StorePathRef) -> Result<Self> {
        let conn = Connection::open("/nix/var/nix/db/db.sqlite")?;

        let path_infos = closure_path_infos(&conn, path)?;

        let closure_paths: Vec<String> = path_infos
            .iter()
            .map(|x| x.path.to_absolute_path())
            .collect();
        let references = references_for_paths(&conn, &closure_paths)?;

        Ok(Self {
            path_infos,
            references,
        })
    }

    /// Get all the path infos of this [Closure].
    pub fn all_path_infos(&self) -> &[LocalPathInfo] {
        &self.path_infos
    }

    /// Get the references for a path that is part of the
    /// [Closure]. Querying for a path outside of the closure
    /// will yield an empty result.
    pub fn references_for_path(
        &self,
        path_id: u64,
    ) -> &[nix_compat::store_path::StorePath<String>] {
        self.references
            .get(&path_id)
            .map(|val| val.as_slice())
            .unwrap_or(&[])
    }
}

/// An owning alternative to the [ExternalPathInfo] struct of Snix.
///
/// It does not contain the references, since we compute that separately.
#[derive(Clone, Debug)]
pub struct LocalPathInfo {
    pub valid_path_id: u64,
    pub nar_sha256: [u8; 32],
    pub nar_size: u64,
    pub path: nix_compat::store_path::StorePath<String>,
    pub deriver: Option<nix_compat::store_path::StorePath<String>>,
    pub signatures: Vec<nix_compat::narinfo::Signature<String>>,
}

/// Get a map of store paths to their references.
fn references_for_paths(
    connection: &Connection,
    store_paths: &[String],
) -> Result<HashMap<u64, Vec<nix_compat::store_path::StorePath<String>>>> {
    let placeholders = std::iter::repeat_n("?", store_paths.len())
        .collect::<Vec<_>>()
        .join(",");
    let references = format!("
SELECT origin.id, target.path FROM ValidPaths origin JOIN Refs ON Refs.referrer = origin.id JOIN ValidPaths target ON Refs.reference = target.id WHERE origin.path IN ({})
", placeholders);

    let mut reference_query = connection.prepare(&references)?;
    let mut rows = reference_query.query(rusqlite::params_from_iter(store_paths.iter()))?;

    let mut reference_map = HashMap::<u64, Vec<nix_compat::store_path::StorePath<String>>>::new();

    while let Some(row) = rows.next()? {
        let id: u64 = row.get(0)?;
        let path: String = row.get(1)?;
        reference_map.entry(id).or_default().push(
            nix_compat::store_path::StorePath::from_absolute_path_full(&path)
                .expect("Could not create path from database entry")
                .0,
        )
    }

    Ok(reference_map)
}

/// Get the path infos of a closure of a store path.
fn closure_path_infos(
    connection: &Connection,
    store_path: StorePathRef,
) -> Result<Vec<LocalPathInfo>> {
    // Get the closure of a path
    let mut statement = connection.prepare(
        "
WITH RECURSIVE closure(
  id, path, hash, registrationTime, deriver, narSize, ultimate, sigs, ca
) AS (
  -- Seed row
  SELECT
    id, path, hash, registrationTime, deriver, narSize, ultimate, sigs, ca
  FROM ValidPaths
  WHERE path = ?

  UNION

  -- Find rows that refer to any path already in the closure
  SELECT
    vp.id, vp.path, vp.hash, vp.registrationTime, vp.deriver, vp.narSize, vp.ultimate, vp.sigs, vp.ca
  FROM closure c
  JOIN Refs r       ON r.referrer = c.id
  JOIN ValidPaths vp ON vp.id = r.reference
)
SELECT DISTINCT
  id, path, hash, registrationTime, deriver, narSize, ultimate, sigs, ca
FROM closure
ORDER BY id; "
    )?;

    statement
        .query_map([store_path.to_absolute_path()], |row| {
            let path_string: String = row.get(1)?;
            let path = nix_compat::store_path::StorePath::from_absolute_path_full(&path_string)
                .map(|x| x.0)
                .expect("Could not create StorePath from the databasse");
            let deriver_string: Option<String> = row.get(4)?;
            let signatures_string: Option<String> = row.get(7)?;
            let nar_sha256 =
                NixHash::from_str(row.get_ref_unwrap(2).as_str()?, Some(HashAlgo::Sha256))
                    .expect("Unable to construct a nar hash from the database")
                    .digest_as_bytes()
                    .try_into()
                    .expect("Unable to convert a hash into 32 bytes of data");

            let deriver = deriver_string.map(|deriver_string| {
                nix_compat::store_path::StorePath::from_absolute_path_full(&deriver_string)
                    .expect("Could not create path from database entry")
                    .0
            });
            let signatures = signatures_string
                .map(|signature_string| {
                    signature_string
                        .split_terminator(";")
                        .map(|s| Signature::parse(s).expect("Unable to parse signature"))
                        .collect()
                })
                .unwrap_or_default();

            Ok(LocalPathInfo {
                valid_path_id: row.get(0)?,
                nar_sha256,
                nar_size: row.get(5)?,
                path,
                deriver,
                signatures,
            })
        })?
        .collect::<Result<Vec<_>, _>>()
}
