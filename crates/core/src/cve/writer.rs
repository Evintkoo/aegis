use super::record::{local_record, LOCAL_ASSIGNER_ORG_ID, LOCAL_ID_PREFIX};
use super::shard::{parse_cve_id, record_path};
use crate::finding::Finding;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Returned when a real CVE record can't be filed because its ID doesn't
/// parse as `CVE-YYYY-NNNN...` -- `write_real_cve` only ever receives IDs
/// an OSV hit's `aliases` array reported as `CVE-`-prefixed, so this is a
/// defensive check against a malformed alias, not an expected path.
#[derive(Debug)]
pub struct InvalidCveId(pub String);

impl std::fmt::Display for InvalidCveId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "not a well-formed CVE ID: {}", self.0)
    }
}

impl std::error::Error for InvalidCveId {}

/// Errors from `write_real_cve`. Kept distinct from `io::Error` (used by
/// `write_local`/`write_native_advisory`) since a malformed ID is a
/// distinct, non-I/O failure mode worth telling apart from a disk error.
#[derive(Debug)]
pub enum WriteRealCveError {
    InvalidId(InvalidCveId),
    /// The fetched record's top-level JSON value isn't an object (e.g. an
    /// array, string, number, or bool) -- indexing into it to attach our
    /// own `adp` container entry isn't possible without either panicking
    /// or silently discarding the record's own shape, so this is surfaced
    /// as an error instead.
    NotAnObject,
    Json(serde_json::Error),
    Io(io::Error),
}

impl std::fmt::Display for WriteRealCveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidId(e) => write!(f, "{e}"),
            Self::NotAnObject => write!(f, "fetched CVE record is not a JSON object"),
            Self::Json(e) => write!(f, "failed to serialize CVE record: {e}"),
            Self::Io(e) => write!(f, "failed to write CVE record: {e}"),
        }
    }
}

impl std::error::Error for WriteRealCveError {}

pub struct CveWriter {
    base_dir: PathBuf,
    year: u32,
    next_seq: AtomicU64,
}

impl CveWriter {
    pub fn new(base_dir: impl Into<PathBuf>, year: u32) -> io::Result<Self> {
        let base_dir = base_dir.into();
        let max_existing = Self::scan_max_seq(&base_dir, year)?;
        Ok(Self {
            base_dir,
            year,
            next_seq: AtomicU64::new(max_existing + 1),
        })
    }

    fn scan_max_seq(base_dir: &Path, year: u32) -> io::Result<u64> {
        let year_dir = base_dir.join(year.to_string());
        if !year_dir.exists() {
            return Ok(0);
        }
        let mut max_seq = 0u64;
        for bucket_entry in fs::read_dir(&year_dir)? {
            let bucket_entry = bucket_entry?;
            if !bucket_entry.file_type()?.is_dir() {
                continue;
            }
            for file_entry in fs::read_dir(bucket_entry.path())? {
                let file_entry = file_entry?;
                let name = file_entry.file_name();
                if let Some(seq) = parse_local_seq(&name.to_string_lossy(), year) {
                    max_seq = max_seq.max(seq);
                }
            }
        }
        Ok(max_seq)
    }

    pub fn write_local(&self, finding: &Finding) -> io::Result<PathBuf> {
        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
        let id_str = format!("{LOCAL_ID_PREFIX}-{}-{seq:06}", self.year);
        let record = local_record(finding, &id_str);
        let path = record_path(&self.base_dir, self.year, seq, &id_str);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&record).map_err(io::Error::other)?;
        fs::write(&path, json)?;
        Ok(path)
    }

    /// Writes a real CVE record fetched verbatim from `cvelistV5` (the
    /// literal source of truth -- see the spec's "Real CVE records:
    /// fetched verbatim, not reconstructed" rationale), enriched with our
    /// own detection context as an appended `adp` container entry. This is
    /// never a fabricated `PENTEST-LOCAL-*` ID -- `cve_id` must already be
    /// a real `CVE-YYYY-NNNN...` ID (from an OSV hit's `aliases`), or this
    /// returns `WriteRealCveError::InvalidId` rather than guessing a shard
    /// location.
    ///
    /// Uses `cve_id`'s own year/numeric parts for the shard path -- NOT
    /// `self.year`/`self.next_seq`, which are reserved for this writer's
    /// sequential local-finding IDs and never apply to a real CVE's own
    /// identity.
    pub fn write_real_cve(
        &self,
        cve_id: &str,
        mut record_json: serde_json::Value,
        x_pentest_context: serde_json::Value,
    ) -> Result<PathBuf, WriteRealCveError> {
        let (year, numeric_id) = parse_cve_id(cve_id).ok_or_else(|| WriteRealCveError::InvalidId(InvalidCveId(cve_id.to_string())))?;

        let adp_entry = serde_json::json!({
            "providerMetadata": { "orgId": LOCAL_ASSIGNER_ORG_ID },
            "x_pentest": x_pentest_context,
        });
        match record_json.get_mut("containers").and_then(|c| c.as_object_mut()) {
            Some(containers) => {
                let adp = containers.entry("adp").or_insert_with(|| serde_json::Value::Array(Vec::new()));
                match adp.as_array_mut() {
                    Some(arr) => arr.push(adp_entry),
                    None => *adp = serde_json::Value::Array(vec![adp_entry]),
                }
            }
            // The fetched record's own shape is unexpected/malformed --
            // still write it verbatim rather than dropping it, but ensure
            // our own detection context is never silently lost either.
            // `serde_json`'s `IndexMut<&str>` promotes `Value::Null` to an
            // object automatically but PANICS for any other non-object
            // top-level shape (array/string/number/bool) when indexed. We
            // reject every non-object shape here (Null included) rather
            // than relying on that promotion -- a record that isn't an
            // object to begin with was never a meaningful CVE record.
            None => {
                if !record_json.is_object() {
                    return Err(WriteRealCveError::NotAnObject);
                }
                record_json["containers"] = serde_json::json!({ "adp": [adp_entry] });
            }
        }

        let path = record_path(&self.base_dir, year, numeric_id, cve_id);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(WriteRealCveError::Io)?;
        }
        let json = serde_json::to_string_pretty(&record_json).map_err(WriteRealCveError::Json)?;
        fs::write(&path, json).map_err(WriteRealCveError::Io)?;
        Ok(path)
    }

    /// Writes an OSV advisory that has NO real `CVE-` alias (a GHSA/OSV-
    /// native ID) under its own native ID, keeping it inside the same
    /// `cve/` tree without colliding with `record_path`'s CVE-numeric
    /// sharding convention (which has no meaning for a non-CVE ID). Layout:
    /// `<base_dir>/<year>/other/<native_id>.json` -- `year` is the
    /// caller's job to derive (typically from the advisory's own
    /// `published` date), since date parsing doesn't belong in this crate.
    ///
    /// `native_id` is rejected if it isn't a plain filename-safe token
    /// (matches `[A-Za-z0-9._-]+`) -- it originates from an external HTTP
    /// response, so it's validated defensively before it ever reaches a
    /// filesystem path.
    pub fn write_native_advisory(&self, native_id: &str, year: u32, record_json: &serde_json::Value, x_pentest_context: serde_json::Value) -> io::Result<PathBuf> {
        if native_id.is_empty() || !native_id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("not a filename-safe advisory ID: {native_id}")));
        }
        // Same panic shape as `write_real_cve`'s `containers` indexing:
        // `out["x_pentest"] = ...` below would panic if `record_json` isn't
        // a JSON object at the top level (array/string/number/bool).
        if !record_json.is_object() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("advisory record for {native_id} is not a JSON object")));
        }

        let mut out = record_json.clone();
        out["x_pentest"] = x_pentest_context;

        let path = self.base_dir.join(year.to_string()).join("other").join(format!("{native_id}.json"));
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&out).map_err(io::Error::other)?;
        fs::write(&path, json)?;
        Ok(path)
    }
}

fn parse_local_seq(filename: &str, year: u32) -> Option<u64> {
    let stem = filename.strip_suffix(".json")?;
    let prefix = format!("{LOCAL_ID_PREFIX}-{year}-");
    stem.strip_prefix(&prefix)?.parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::severity::Severity;
    use std::sync::atomic::{AtomicU64 as GlobalCounter, Ordering as GlobalOrdering};

    static TEST_DIR_COUNTER: GlobalCounter = GlobalCounter::new(0);

    fn temp_test_dir() -> PathBuf {
        let n = TEST_DIR_COUNTER.fetch_add(1, GlobalOrdering::SeqCst);
        let dir = std::env::temp_dir().join(format!("pentest-core-cve-writer-test-{}-{n}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn writes_sequential_ids_at_the_correct_shard_path() {
        let dir = temp_test_dir();
        let writer = CveWriter::new(&dir, 2026).unwrap();
        let f = Finding::new("sqli", Severity::Critical, "title", "detail");

        let path1 = writer.write_local(&f).unwrap();
        let path2 = writer.write_local(&f).unwrap();

        assert_eq!(path1, dir.join("2026").join("0xxx").join("PENTEST-LOCAL-2026-000001.json"));
        assert_eq!(path2, dir.join("2026").join("0xxx").join("PENTEST-LOCAL-2026-000002.json"));
        assert!(path1.exists());
        let contents = fs::read_to_string(&path1).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&contents).unwrap();
        assert_eq!(parsed["cveMetadata"]["cveId"], "PENTEST-LOCAL-2026-000001");
    }

    #[test]
    fn a_new_writer_instance_continues_the_sequence_from_disk() {
        let dir = temp_test_dir();
        let f = Finding::new("xss", Severity::High, "title", "detail");
        {
            let writer = CveWriter::new(&dir, 2026).unwrap();
            writer.write_local(&f).unwrap();
            writer.write_local(&f).unwrap();
        }
        let writer2 = CveWriter::new(&dir, 2026).unwrap();
        let path3 = writer2.write_local(&f).unwrap();
        assert_eq!(path3, dir.join("2026").join("0xxx").join("PENTEST-LOCAL-2026-000003.json"));
    }

    #[test]
    fn write_real_cve_shards_by_the_cve_ids_own_year_and_number_not_the_writers() {
        let dir = temp_test_dir();
        // Writer is configured for 2026, but the real CVE is from 2021 --
        // the shard path must follow the ID's own year, never the writer's.
        let writer = CveWriter::new(&dir, 2026).unwrap();
        let fetched = serde_json::json!({
            "dataType": "CVE_RECORD",
            "cveMetadata": { "cveId": "CVE-2021-44228" },
            "containers": { "cna": { "descriptions": [{"lang": "en", "value": "Log4Shell"}] } },
        });
        let ctx = serde_json::json!({ "check": "recon", "component": "log4j-core", "version": "2.14.1" });

        let path = writer.write_real_cve("CVE-2021-44228", fetched, ctx).unwrap();

        assert_eq!(path, dir.join("2021").join("44xxx").join("CVE-2021-44228.json"));
        let parsed: serde_json::Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        // The original fetched record's own data survives untouched.
        assert_eq!(parsed["cveMetadata"]["cveId"], "CVE-2021-44228");
        assert_eq!(parsed["containers"]["cna"]["descriptions"][0]["value"], "Log4Shell");
        // Our detection context lands in an appended adp entry, not mixed
        // into the original cna container.
        assert_eq!(parsed["containers"]["adp"][0]["x_pentest"]["component"], "log4j-core");
        assert_eq!(parsed["containers"]["adp"][0]["providerMetadata"]["orgId"], LOCAL_ASSIGNER_ORG_ID);
    }

    #[test]
    fn write_real_cve_appends_to_an_existing_adp_array_rather_than_replacing_it() {
        let dir = temp_test_dir();
        let writer = CveWriter::new(&dir, 2026).unwrap();
        let fetched = serde_json::json!({
            "cveMetadata": { "cveId": "CVE-2021-44228" },
            "containers": {
                "cna": {},
                "adp": [{ "providerMetadata": { "orgId": "cisa.gov" }, "metrics": [] }],
            },
        });

        let path = writer.write_real_cve("CVE-2021-44228", fetched, serde_json::json!({})).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let adp = parsed["containers"]["adp"].as_array().unwrap();
        assert_eq!(adp.len(), 2, "the pre-existing CISA ADP entry must survive alongside ours");
        assert_eq!(adp[0]["providerMetadata"]["orgId"], "cisa.gov");
        assert_eq!(adp[1]["providerMetadata"]["orgId"], LOCAL_ASSIGNER_ORG_ID);
    }

    #[test]
    fn write_real_cve_rejects_an_id_that_is_not_cve_shaped() {
        let dir = temp_test_dir();
        let writer = CveWriter::new(&dir, 2026).unwrap();
        let result = writer.write_real_cve("GHSA-r9p9-mrjm-926w", serde_json::json!({}), serde_json::json!({}));
        assert!(matches!(result, Err(WriteRealCveError::InvalidId(_))));
    }

    #[test]
    fn write_real_cve_returns_an_error_instead_of_panicking_on_a_non_object_record() {
        // `serde_json`'s `IndexMut<&str>` panics when indexing into a
        // top-level array (or string/number/bool) -- this must be a
        // graceful, specific error instead.
        let dir = temp_test_dir();
        let writer = CveWriter::new(&dir, 2026).unwrap();
        let result = writer.write_real_cve("CVE-2021-44228", serde_json::json!([1, 2, 3]), serde_json::json!({}));
        assert!(matches!(result, Err(WriteRealCveError::NotAnObject)));
    }

    #[test]
    fn write_native_advisory_files_under_year_other_native_id() {
        let dir = temp_test_dir();
        let writer = CveWriter::new(&dir, 2026).unwrap();
        let record = serde_json::json!({ "id": "GHSA-r9p9-mrjm-926w", "summary": "example advisory" });

        let path = writer.write_native_advisory("GHSA-r9p9-mrjm-926w", 2024, &record, serde_json::json!({ "check": "recon" })).unwrap();

        assert_eq!(path, dir.join("2024").join("other").join("GHSA-r9p9-mrjm-926w.json"));
        let parsed: serde_json::Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(parsed["id"], "GHSA-r9p9-mrjm-926w");
        assert_eq!(parsed["x_pentest"]["check"], "recon");
    }

    #[test]
    fn write_native_advisory_rejects_a_path_unsafe_id() {
        let dir = temp_test_dir();
        let writer = CveWriter::new(&dir, 2026).unwrap();
        let result = writer.write_native_advisory("../../etc/passwd", 2024, &serde_json::json!({}), serde_json::json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn write_native_advisory_returns_an_error_instead_of_panicking_on_a_non_object_record() {
        // `out["x_pentest"] = ...` would panic if `record_json` is a
        // top-level array (or string/number/bool) -- this must be a
        // graceful `io::Error` instead.
        let dir = temp_test_dir();
        let writer = CveWriter::new(&dir, 2026).unwrap();
        let result = writer.write_native_advisory("GHSA-r9p9-mrjm-926w", 2024, &serde_json::json!([1, 2, 3]), serde_json::json!({}));
        let err = result.expect_err("a non-object record must not panic");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("not a JSON object"), "unexpected error message: {err}");
    }
}
