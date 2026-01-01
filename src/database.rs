use rusqlite::{Connection, Result};

pub fn closure() -> Result<()> {
    let conn = Connection::open("/nix/var/nix/db/db.sqlite")?;

    // Get the closure of a path
    let mut statement = conn.prepare(
        "
WITH RECURSIVE closure(
  id, path, hash, registrationTime, deriver, narSize, ultimate, sigs, ca
) AS (
  -- seed row (bind :path or substitute literal)
  SELECT
    id, path, hash, registrationTime, deriver, narSize, ultimate, sigs, ca
  FROM ValidPaths
  WHERE path = '/nix/store/qg6nh6zf727nm87bkbn9jlkkslrm2wiw-lldb-20.1.6'

  UNION

  -- step: find rows that refer to any path already in the closure
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

    let closure_iter = statement.query_map([], |row| {
        let path: String = row.get(1)?;
        Ok(path)
        // Ok(ExportedPathInfo {
        //     closure_size: 0,
        //     nar_sha256: row.get(2)?,
        //     nar_size: row.get(4)?,
        //     path: StorePathRef::from_absolute_path(path.as_bytes().as_ref())
        //         .expect("Could not create path from database entry"),
        //     deriver: None,
        //     references: BTreeSet::new(),
        //     signatures: vec![],
        // })
    })?;

    for path in closure_iter {
        println!("Found path{:?}", path?);
    }
    Ok(())
}
