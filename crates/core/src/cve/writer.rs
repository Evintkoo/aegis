use super::record::{local_record, LOCAL_ID_PREFIX};
use super::shard::record_path;
use crate::finding::Finding;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

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
        let json = serde_json::to_string_pretty(&record)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
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
}
