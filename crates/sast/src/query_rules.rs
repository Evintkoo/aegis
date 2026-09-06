//! Tree-sitter-query-based rules (5 of the 6 SAST rules; the 6th,
//! hardcoded secrets, is deliberately regex-based -- see `secrets.rs`).
//!
//! Each rule carries a tree-sitter query per language it applies to. A
//! query's top-level capture MUST be named `@sink` -- that's the node
//! whose start line and source text become the finding's evidence. Rules
//! are pragmatically scoped to the languages where the underlying idiom
//! is real (e.g. Rust is skipped for "SQL string-concat", since
//! sqlx/diesel-style compile-time-checked queries make that pattern rare
//! and noisy there; Rust gets its own command-exec pattern instead, via
//! `Command::new("sh"/"bash"/...)`).

use crate::lang::Lang;
use pentest_core::{Finding, Severity};
use tree_sitter::{Parser, Query, QueryCursor, StreamingIterator};

pub struct QueryRule {
    pub check: &'static str,
    pub cwe: &'static str,
    pub severity: Severity,
    pub title: &'static str,
    pub remediation: &'static str,
    pub queries: &'static [(Lang, &'static str)],
}

pub fn all_rules() -> Vec<QueryRule> {
    vec![
        QueryRule {
            check: "sast_sqli_concat",
            cwe: "CWE-89",
            severity: Severity::High,
            title: "SQL query built via string concatenation",
            remediation: "Use parameterized queries / prepared statements; never build SQL by string concatenation.",
            queries: &[
                (
                    Lang::Python,
                    r#"(call
                        function: (attribute attribute: (identifier) @method)
                        arguments: (argument_list (binary_operator) @concat)
                        (#match? @method "^(execute|executemany)$")) @sink"#,
                ),
                (
                    Lang::JavaScript,
                    r#"(call_expression
                        function: (member_expression property: (property_identifier) @method)
                        arguments: (arguments (binary_expression operator: "+"))
                        (#match? @method "^(query|execute)$")) @sink"#,
                ),
                (
                    Lang::TypeScript,
                    r#"(call_expression
                        function: (member_expression property: (property_identifier) @method)
                        arguments: (arguments (binary_expression operator: "+"))
                        (#match? @method "^(query|execute)$")) @sink"#,
                ),
                (
                    Lang::Tsx,
                    r#"(call_expression
                        function: (member_expression property: (property_identifier) @method)
                        arguments: (arguments (binary_expression operator: "+"))
                        (#match? @method "^(query|execute)$")) @sink"#,
                ),
            ],
        },
        QueryRule {
            check: "sast_command_exec",
            cwe: "CWE-78",
            severity: Severity::Critical,
            title: "Dynamic command/code execution sink",
            remediation: "Avoid shells and eval; use exec with an argument array and an allow-list — never interpolate input.",
            queries: &[
                (
                    Lang::Python,
                    r#"(call
                        function: [
                          (identifier) @fn
                          (attribute attribute: (identifier) @fn)
                        ]
                        (#match? @fn "^(eval|exec|system|popen)$")) @sink"#,
                ),
                (
                    Lang::JavaScript,
                    r#"(call_expression
                        function: [
                          (identifier) @fn
                          (member_expression property: (property_identifier) @fn)
                        ]
                        (#match? @fn "^(eval|exec|execSync|execFile|execFileSync)$")) @sink"#,
                ),
                (
                    Lang::TypeScript,
                    r#"(call_expression
                        function: [
                          (identifier) @fn
                          (member_expression property: (property_identifier) @fn)
                        ]
                        (#match? @fn "^(eval|exec|execSync|execFile|execFileSync)$")) @sink"#,
                ),
                (
                    Lang::Tsx,
                    r#"(call_expression
                        function: [
                          (identifier) @fn
                          (member_expression property: (property_identifier) @fn)
                        ]
                        (#match? @fn "^(eval|exec|execSync|execFile|execFileSync)$")) @sink"#,
                ),
                (
                    Lang::Rust,
                    r#"(call_expression
                        function: (scoped_identifier name: (identifier) @method)
                        arguments: (arguments (string_literal) @arg)
                        (#eq? @method "new")
                        (#match? @arg "\"(sh|bash|cmd|cmd\\.exe|powershell)\"")) @sink"#,
                ),
            ],
        },
        QueryRule {
            check: "sast_unsafe_deserialize",
            cwe: "CWE-502",
            severity: Severity::High,
            title: "Unsafe deserialization of untrusted data",
            remediation: "Never unpickle/deserialize untrusted input; use a safe data format (JSON) with a schema, or a restricted-loader API.",
            queries: &[
                (
                    Lang::Python,
                    r#"(call
                        function: (attribute object: (identifier) @obj attribute: (identifier) @fn)
                        (#match? @obj "^(pickle|yaml)$")
                        (#match? @fn "^(loads|load)$")) @sink"#,
                ),
                (
                    Lang::JavaScript,
                    r#"(call_expression
                        function: (identifier) @fn
                        (#eq? @fn "unserialize")) @sink"#,
                ),
                (
                    Lang::TypeScript,
                    r#"(call_expression
                        function: (identifier) @fn
                        (#eq? @fn "unserialize")) @sink"#,
                ),
                (
                    Lang::Tsx,
                    r#"(call_expression
                        function: (identifier) @fn
                        (#eq? @fn "unserialize")) @sink"#,
                ),
            ],
        },
        QueryRule {
            check: "sast_weak_crypto",
            cwe: "CWE-327",
            severity: Severity::Medium,
            title: "Use of a broken or weak cryptographic hash",
            remediation: "Use a modern, non-broken hash (SHA-256+) or a dedicated password-hashing function (bcrypt/argon2/scrypt) for secrets.",
            queries: &[
                (
                    Lang::Python,
                    r#"(call
                        function: (attribute object: (identifier) @obj attribute: (identifier) @fn)
                        (#eq? @obj "hashlib")
                        (#match? @fn "^(md5|sha1)$")) @sink"#,
                ),
                (
                    Lang::JavaScript,
                    r#"(call_expression
                        function: (member_expression property: (property_identifier) @fn)
                        arguments: (arguments (string (string_fragment) @alg))
                        (#eq? @fn "createHash")
                        (#match? @alg "^(md5|sha1)$")) @sink"#,
                ),
                (
                    Lang::TypeScript,
                    r#"(call_expression
                        function: (member_expression property: (property_identifier) @fn)
                        arguments: (arguments (string (string_fragment) @alg))
                        (#eq? @fn "createHash")
                        (#match? @alg "^(md5|sha1)$")) @sink"#,
                ),
                (
                    Lang::Tsx,
                    r#"(call_expression
                        function: (member_expression property: (property_identifier) @fn)
                        arguments: (arguments (string (string_fragment) @alg))
                        (#eq? @fn "createHash")
                        (#match? @alg "^(md5|sha1)$")) @sink"#,
                ),
            ],
        },
        QueryRule {
            check: "sast_path_traversal",
            cwe: "CWE-22",
            severity: Severity::High,
            title: "File path built from concatenated input reaches a file-system sink",
            remediation: "Canonicalize paths and confine to a base dir (realpath + prefix check); never pass unsanitized input to file APIs.",
            queries: &[
                (
                    Lang::Python,
                    r#"(call
                        function: (identifier) @fn
                        arguments: (argument_list (binary_operator) @concat)
                        (#eq? @fn "open")) @sink"#,
                ),
                (
                    Lang::JavaScript,
                    r#"(call_expression
                        function: (member_expression property: (property_identifier) @fn)
                        arguments: (arguments (binary_expression operator: "+"))
                        (#match? @fn "^(readFile|readFileSync|writeFile|writeFileSync|createReadStream)$")) @sink"#,
                ),
                (
                    Lang::TypeScript,
                    r#"(call_expression
                        function: (member_expression property: (property_identifier) @fn)
                        arguments: (arguments (binary_expression operator: "+"))
                        (#match? @fn "^(readFile|readFileSync|writeFile|writeFileSync|createReadStream)$")) @sink"#,
                ),
                (
                    Lang::Tsx,
                    r#"(call_expression
                        function: (member_expression property: (property_identifier) @fn)
                        arguments: (arguments (binary_expression operator: "+"))
                        (#match? @fn "^(readFile|readFileSync|writeFile|writeFileSync|createReadStream)$")) @sink"#,
                ),
            ],
        },
    ]
}

/// Runs every applicable query rule against one already-parsed file and
/// appends a `Finding` per match. `path` and `source` are used only to
/// build evidence text (file:line + the matched snippet); no
/// dedicated file-path field exists on `Finding`.
pub fn scan_file(rules: &[QueryRule], lang: Lang, path: &std::path::Path, source: &[u8]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut parser = Parser::new();
    if parser.set_language(&lang.ts_language()).is_err() {
        return findings;
    }
    let Some(tree) = parser.parse(source, None) else {
        return findings;
    };

    for rule in rules {
        for (rule_lang, query_src) in rule.queries {
            if *rule_lang != lang {
                continue;
            }
            let Ok(query) = Query::new(&lang.ts_language(), query_src) else {
                continue;
            };
            let sink_ix = query.capture_index_for_name("sink");
            let mut cursor = QueryCursor::new();
            let mut matches = cursor.matches(&query, tree.root_node(), source);
            while let Some(m) = matches.next() {
                let Some(sink_ix) = sink_ix else { continue };
                let Some(cap) = m.captures().iter().find(|c| c.index == sink_ix) else { continue };
                let node = cap.node;
                let text = node.utf8_text(source).unwrap_or("").trim();
                let snippet: String = text.chars().take(120).collect();
                let line = node.start_position().row + 1;
                let mut f = Finding::new(rule.check, rule.severity, rule.title, format!("{} [{}]", rule.cwe, rule.check))
                    .with_evidence(format!("{}:{line}: {snippet}", path.display()));
                f.remediation = rule.remediation.to_string();
                findings.push(f);
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(check: &str) -> QueryRule {
        all_rules().into_iter().find(|r| r.check == check).unwrap()
    }

    fn run(check: &str, lang: Lang, source: &str) -> Vec<Finding> {
        let rules = vec![rule(check)];
        scan_file(&rules, lang, std::path::Path::new("fixture"), source.as_bytes())
    }

    #[test]
    fn sqli_flags_python_string_concat_execute() {
        let src = "cur.execute(\"SELECT * FROM users WHERE id = \" + user_id)";
        let findings = run("sast_sqli_concat", Lang::Python, src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn sqli_does_not_flag_python_parameterized_query() {
        let src = "cur.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))";
        let findings = run("sast_sqli_concat", Lang::Python, src);
        assert!(findings.is_empty());
    }

    #[test]
    fn sqli_flags_js_string_concat_query() {
        let src = "db.query(\"SELECT * FROM users WHERE id = \" + id, cb);";
        let findings = run("sast_sqli_concat", Lang::JavaScript, src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn sqli_does_not_flag_js_parameterized_query() {
        let src = "db.query(\"SELECT * FROM users WHERE id = ?\", [id], cb);";
        let findings = run("sast_sqli_concat", Lang::JavaScript, src);
        assert!(findings.is_empty());
    }

    #[test]
    fn command_exec_flags_python_eval() {
        let findings = run("sast_command_exec", Lang::Python, "eval(user_input)");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn command_exec_does_not_flag_python_print() {
        let findings = run("sast_command_exec", Lang::Python, "print(user_input)");
        assert!(findings.is_empty());
    }

    #[test]
    fn command_exec_flags_js_child_process_exec() {
        let findings = run("sast_command_exec", Lang::JavaScript, "child_process.exec(cmd);");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn command_exec_does_not_flag_js_array_spawn() {
        let findings = run("sast_command_exec", Lang::JavaScript, "spawn('ls', ['-la']);");
        assert!(findings.is_empty());
    }

    #[test]
    fn command_exec_flags_rust_shell_spawn() {
        let findings = run("sast_command_exec", Lang::Rust, r#"Command::new("sh").arg("-c").arg(user_input).output()"#);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn command_exec_does_not_flag_rust_argv_spawn() {
        let findings = run("sast_command_exec", Lang::Rust, r#"Command::new("ls").arg("-la").output()"#);
        assert!(findings.is_empty());
    }

    #[test]
    fn deserialize_flags_python_pickle_loads() {
        let findings = run("sast_unsafe_deserialize", Lang::Python, "pickle.loads(data)");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn deserialize_does_not_flag_python_json_loads() {
        let findings = run("sast_unsafe_deserialize", Lang::Python, "json.loads(data)");
        assert!(findings.is_empty());
    }

    #[test]
    fn weak_crypto_flags_python_md5() {
        let findings = run("sast_weak_crypto", Lang::Python, "hashlib.md5(password.encode())");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn weak_crypto_does_not_flag_python_sha256() {
        let findings = run("sast_weak_crypto", Lang::Python, "hashlib.sha256(password.encode())");
        assert!(findings.is_empty());
    }

    #[test]
    fn weak_crypto_flags_js_create_hash_md5() {
        let findings = run("sast_weak_crypto", Lang::JavaScript, "crypto.createHash('md5').update(pw).digest('hex');");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn weak_crypto_does_not_flag_js_create_hash_sha256() {
        let findings = run("sast_weak_crypto", Lang::JavaScript, "crypto.createHash('sha256').update(pw).digest('hex');");
        assert!(findings.is_empty());
    }

    #[test]
    fn path_traversal_flags_python_open_concat() {
        let findings = run("sast_path_traversal", Lang::Python, "open(base_dir + filename)");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn path_traversal_does_not_flag_python_open_literal() {
        let findings = run("sast_path_traversal", Lang::Python, "open(\"static/report.txt\")");
        assert!(findings.is_empty());
    }

    #[test]
    fn path_traversal_flags_js_readfile_concat() {
        let findings = run("sast_path_traversal", Lang::JavaScript, "fs.readFileSync(baseDir + '/' + name);");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn path_traversal_does_not_flag_js_readfile_literal() {
        let findings = run("sast_path_traversal", Lang::JavaScript, "fs.readFileSync('./static/report.txt');");
        assert!(findings.is_empty());
    }

    // --- TypeScript / additional-language coverage for query combinations
    // that had a query defined in `all_rules()` but no test exercising it
    // (found in review of commit 1b12bd8). Each TS source uses a real type
    // annotation so it only parses under the TypeScript grammar, not just
    // the JavaScript one -- proving the `Lang::TypeScript` query path
    // itself, not merely JS-compatible syntax dispatched to TS.

    #[test]
    fn sqli_flags_ts_string_concat_query() {
        let src = "const id: string = getId();\ndb.query(\"SELECT * FROM users WHERE id = \" + id, cb);";
        let findings = run("sast_sqli_concat", Lang::TypeScript, src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn sqli_does_not_flag_ts_parameterized_query() {
        let src = "const id: string = getId();\ndb.query(\"SELECT * FROM users WHERE id = ?\", [id], cb);";
        let findings = run("sast_sqli_concat", Lang::TypeScript, src);
        assert!(findings.is_empty());
    }

    #[test]
    fn command_exec_flags_ts_child_process_exec() {
        let src = "const cmd: string = getCmd();\nchild_process.exec(cmd);";
        let findings = run("sast_command_exec", Lang::TypeScript, src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn command_exec_does_not_flag_ts_array_spawn() {
        let src = "const args: string[] = ['-la'];\nspawn('ls', args);";
        let findings = run("sast_command_exec", Lang::TypeScript, src);
        assert!(findings.is_empty());
    }

    #[test]
    fn weak_crypto_flags_ts_create_hash_md5() {
        let src = "const pw: string = getPassword();\ncrypto.createHash('md5').update(pw).digest('hex');";
        let findings = run("sast_weak_crypto", Lang::TypeScript, src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn weak_crypto_does_not_flag_ts_create_hash_sha256() {
        let src = "const pw: string = getPassword();\ncrypto.createHash('sha256').update(pw).digest('hex');";
        let findings = run("sast_weak_crypto", Lang::TypeScript, src);
        assert!(findings.is_empty());
    }

    #[test]
    fn path_traversal_flags_ts_readfile_concat() {
        let src = "const name: string = getName();\nfs.readFileSync(baseDir + '/' + name);";
        let findings = run("sast_path_traversal", Lang::TypeScript, src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn path_traversal_does_not_flag_ts_readfile_literal() {
        let src = "const name: string = getName();\nfs.readFileSync('./static/report.txt');";
        let findings = run("sast_path_traversal", Lang::TypeScript, src);
        assert!(findings.is_empty());
    }

    #[test]
    fn deserialize_flags_js_unserialize() {
        let findings = run("sast_unsafe_deserialize", Lang::JavaScript, "unserialize(data);");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn deserialize_does_not_flag_js_json_parse() {
        let findings = run("sast_unsafe_deserialize", Lang::JavaScript, "JSON.parse(data);");
        assert!(findings.is_empty());
    }

    #[test]
    fn deserialize_flags_ts_unserialize() {
        let src = "const data: string = getData();\nunserialize(data);";
        let findings = run("sast_unsafe_deserialize", Lang::TypeScript, src);
        assert_eq!(findings.len(), 1);
    }

    // --- .tsx / Lang::Tsx coverage (bug fix: every rule's `queries` list
    // previously had a Lang::TypeScript entry but no Lang::Tsx entry, so
    // .tsx files got zero tree-sitter findings from any rule regardless of
    // how vulnerable their code was -- LANGUAGE_TSX and LANGUAGE_TYPESCRIPT
    // are genuinely distinct grammars, per lang.rs's own assert_ne! test).
    // Each fixture includes a real JSX element (`<div>...</div>`) so it
    // only parses cleanly under the TSX grammar, proving the Lang::Tsx
    // query path itself rather than merely TS-compatible syntax.

    #[test]
    fn sqli_flags_tsx_string_concat_query() {
        let src = "const el = <div>{1}</div>;\nconst id: string = getId();\ndb.query(\"SELECT * FROM users WHERE id = \" + id, cb);";
        let findings = run("sast_sqli_concat", Lang::Tsx, src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn sqli_does_not_flag_tsx_parameterized_query() {
        let src = "const el = <div>{1}</div>;\nconst id: string = getId();\ndb.query(\"SELECT * FROM users WHERE id = ?\", [id], cb);";
        let findings = run("sast_sqli_concat", Lang::Tsx, src);
        assert!(findings.is_empty());
    }

    #[test]
    fn command_exec_flags_tsx_child_process_exec() {
        let src = "const el = <div>{1}</div>;\nconst cmd: string = getCmd();\nchild_process.exec(cmd);";
        let findings = run("sast_command_exec", Lang::Tsx, src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn command_exec_does_not_flag_tsx_array_spawn() {
        let src = "const el = <div>{1}</div>;\nconst args: string[] = ['-la'];\nspawn('ls', args);";
        let findings = run("sast_command_exec", Lang::Tsx, src);
        assert!(findings.is_empty());
    }

    #[test]
    fn weak_crypto_flags_tsx_create_hash_md5() {
        let src = "const el = <div>{1}</div>;\nconst pw: string = getPassword();\ncrypto.createHash('md5').update(pw).digest('hex');";
        let findings = run("sast_weak_crypto", Lang::Tsx, src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn weak_crypto_does_not_flag_tsx_create_hash_sha256() {
        let src = "const el = <div>{1}</div>;\nconst pw: string = getPassword();\ncrypto.createHash('sha256').update(pw).digest('hex');";
        let findings = run("sast_weak_crypto", Lang::Tsx, src);
        assert!(findings.is_empty());
    }

    #[test]
    fn path_traversal_flags_tsx_readfile_concat() {
        let src = "const el = <div>{1}</div>;\nconst name: string = getName();\nfs.readFileSync(baseDir + '/' + name);";
        let findings = run("sast_path_traversal", Lang::Tsx, src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn path_traversal_does_not_flag_tsx_readfile_literal() {
        let src = "const el = <div>{1}</div>;\nconst name: string = getName();\nfs.readFileSync('./static/report.txt');";
        let findings = run("sast_path_traversal", Lang::Tsx, src);
        assert!(findings.is_empty());
    }

    #[test]
    fn deserialize_flags_tsx_unserialize() {
        let src = "const el = <div>{1}</div>;\nunserialize(data);";
        let findings = run("sast_unsafe_deserialize", Lang::Tsx, src);
        assert_eq!(findings.len(), 1);
    }
}
