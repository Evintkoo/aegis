//! Per-extension language dispatch.
//!
//! `tree-sitter-typescript` exposes two distinct grammar entry points —
//! `LANGUAGE_TYPESCRIPT` and `LANGUAGE_TSX` — for the `.ts` and `.tsx`
//! extensions respectively; collapsing them into one is a real trap this
//! module deliberately avoids (verified by independently compiling both
//! against real `.ts`/`.tsx` fixtures, not just trusting the crate docs).

#![allow(dead_code)] // ts_language()'s first real consumer is query_rules.rs in Task 3; from_path()'s is lib.rs's scan() in Task 4

use std::ffi::OsStr;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Lang {
    Rust,
    JavaScript,
    TypeScript,
    Tsx,
    Python,
}

impl Lang {
    pub fn from_path(path: &Path) -> Option<Lang> {
        match path.extension().and_then(OsStr::to_str)? {
            "rs" => Some(Lang::Rust),
            "js" | "jsx" | "mjs" | "cjs" => Some(Lang::JavaScript),
            "ts" | "mts" | "cts" => Some(Lang::TypeScript),
            "tsx" => Some(Lang::Tsx),
            "py" | "pyw" => Some(Lang::Python),
            _ => None,
        }
    }

    pub fn ts_language(&self) -> tree_sitter::Language {
        match self {
            Lang::Rust => tree_sitter_rust::LANGUAGE.into(),
            Lang::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
            Lang::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Lang::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
            Lang::Python => tree_sitter_python::LANGUAGE.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatches_ts_and_tsx_to_distinct_grammars() {
        let ts = Lang::from_path(Path::new("app.ts")).unwrap();
        let tsx = Lang::from_path(Path::new("app.tsx")).unwrap();
        assert_eq!(ts, Lang::TypeScript);
        assert_eq!(tsx, Lang::Tsx);

        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&ts.ts_language()).unwrap();
        parser.set_language(&tsx.ts_language()).unwrap();

        assert_ne!(ts.ts_language(), tsx.ts_language());
    }

    #[test]
    fn unknown_extension_returns_none() {
        assert_eq!(Lang::from_path(Path::new("README.md")), None);
        assert_eq!(Lang::from_path(Path::new("Makefile")), None);
    }

    #[test]
    fn every_recognized_language_sets_language_successfully() {
        for lang in [Lang::Rust, Lang::JavaScript, Lang::TypeScript, Lang::Tsx, Lang::Python] {
            let mut parser = tree_sitter::Parser::new();
            parser.set_language(&lang.ts_language()).unwrap();
        }
    }
}
