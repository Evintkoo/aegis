//! Recursive source-tree walker. Simple, documented denylist for noise
//! directories -- not a general gitignore-parsing engine, matching this
//! project's existing pragmatic style (`discovery.rs`'s marker-list
//! approach to unsafe-path skipping, not a robots.txt engine).

use std::fs;
use std::path::{Path, PathBuf};

/// Directory names never descended into. Covers the noise this toolkit's
/// own supported stacks (Rust, TS/JS, Python) produce.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".next",
    ".mypy_cache",
    ".pytest_cache",
];

/// Collects every regular file under `root`, recursively, skipping
/// `SKIP_DIRS` by name at any depth, plus anything whose canonicalized
/// path falls under one of `exclude`'s already-canonicalized paths (used
/// to keep a scan from re-walking its own prior output directory -- see
/// `scan`'s doc comment in `lib.rs`). Returns paths in a stable (sorted)
/// order for deterministic scan output. A directory that can't be read
/// (permissions, race with deletion) is silently skipped, not an error --
/// matches this toolkit's established "best-effort scan" posture.
pub fn walk(root: &Path, exclude: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk_into(root, exclude, &mut out);
    out.sort();
    out
}

/// True if `path`'s canonicalized form is contained within (or equal to)
/// any path in `exclude`. `exclude` is expected to already hold
/// canonicalized paths. If `path` itself can't be canonicalized (race
/// with deletion, dangling symlink), it is never treated as excluded --
/// only a path that demonstrably resolves inside an excluded tree is
/// skipped.
fn is_excluded(path: &Path, exclude: &[PathBuf]) -> bool {
    if exclude.is_empty() {
        return false;
    }
    let Ok(canon) = fs::canonicalize(path) else {
        return false;
    };
    exclude.iter().any(|ex| canon.starts_with(ex))
}

fn walk_into(dir: &Path, exclude: &[PathBuf], out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if is_excluded(&path, exclude) {
            continue;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            let name = entry.file_name();
            if SKIP_DIRS.iter().any(|skip| name == *skip) {
                continue;
            }
            walk_into(&path, exclude, out);
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
        let dir = std::env::temp_dir().join(format!(
            "pentest-sast-walker-test-{}-{n}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn walks_files_recursively_in_sorted_order() {
        let root = temp_dir();
        fs::write(root.join("b.py"), "").unwrap();
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::write(root.join("sub").join("a.rs"), "").unwrap();

        let files = walk(&root, &[]);

        assert_eq!(
            files,
            vec![root.join("b.py"), root.join("sub").join("a.rs")]
        );
    }

    #[test]
    fn skips_denylisted_directories() {
        let root = temp_dir();
        fs::create_dir_all(root.join("node_modules")).unwrap();
        fs::write(root.join("node_modules").join("evil.js"), "").unwrap();
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::write(root.join(".git").join("config"), "").unwrap();
        fs::write(root.join("real.js"), "").unwrap();

        let files = walk(&root, &[]);

        assert_eq!(files, vec![root.join("real.js")]);
    }

    #[test]
    fn returns_empty_for_a_nonexistent_root() {
        let files = walk(Path::new("/definitely/not/a/real/path/9182"), &[]);
        assert!(files.is_empty());
    }

    #[test]
    fn skips_an_excluded_directory_by_canonicalized_path() {
        let root = temp_dir();
        fs::write(root.join("real.js"), "").unwrap();
        fs::create_dir_all(root.join("cve")).unwrap();
        fs::write(root.join("cve").join("record.json"), "").unwrap();

        let excluded = fs::canonicalize(root.join("cve")).unwrap();
        let files = walk(&root, &[excluded]);

        assert_eq!(files, vec![root.join("real.js")]);
    }

    #[test]
    fn empty_exclude_list_excludes_nothing() {
        let root = temp_dir();
        fs::write(root.join("real.js"), "").unwrap();

        let files = walk(&root, &[]);

        assert_eq!(files, vec![root.join("real.js")]);
    }
}
