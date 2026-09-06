//! Recursive source-tree walker. Simple, documented denylist for noise
//! directories -- not a general gitignore-parsing engine, matching this
//! project's existing pragmatic style (`discovery.rs`'s marker-list
//! approach to unsafe-path skipping, not a robots.txt engine).

use std::fs;
use std::path::{Path, PathBuf};

/// Directory names never descended into. Covers the noise this toolkit's
/// own supported stacks (Rust, TS/JS, Python) produce.
const SKIP_DIRS: &[&str] = &[".git", "node_modules", "target", "__pycache__", ".venv", "venv", "dist", "build", ".next", ".mypy_cache", ".pytest_cache"];

/// Collects every regular file under `root`, recursively, skipping
/// `SKIP_DIRS` by name at any depth. Returns paths in a stable (sorted)
/// order for deterministic scan output. A directory that can't be read
/// (permissions, race with deletion) is silently skipped, not an error --
/// matches this toolkit's established "best-effort scan" posture.
pub fn walk(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk_into(root, &mut out);
    out.sort();
    out
}

fn walk_into(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else { continue };
        if file_type.is_dir() {
            let name = entry.file_name();
            if SKIP_DIRS.iter().any(|skip| name == *skip) {
                continue;
            }
            walk_into(&path, out);
        } else if file_type.is_file() {
            out.push(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("pentest-sast-walker-test-{}-{n}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn walks_files_recursively_in_sorted_order() {
        let root = temp_dir();
        fs::write(root.join("b.py"), "").unwrap();
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::write(root.join("sub").join("a.rs"), "").unwrap();

        let files = walk(&root);

        assert_eq!(files, vec![root.join("b.py"), root.join("sub").join("a.rs")]);
    }

    #[test]
    fn skips_denylisted_directories() {
        let root = temp_dir();
        fs::create_dir_all(root.join("node_modules")).unwrap();
        fs::write(root.join("node_modules").join("evil.js"), "").unwrap();
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::write(root.join(".git").join("config"), "").unwrap();
        fs::write(root.join("real.js"), "").unwrap();

        let files = walk(&root);

        assert_eq!(files, vec![root.join("real.js")]);
    }

    #[test]
    fn returns_empty_for_a_nonexistent_root() {
        let files = walk(Path::new("/definitely/not/a/real/path/9182"));
        assert!(files.is_empty());
    }
}
