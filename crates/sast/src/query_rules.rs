//! Tree-sitter-query-based rules (10 of the 11 SAST rules; the 11th,
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
        QueryRule {
            check: "sast_ssrf",
            cwe: "CWE-918",
            severity: Severity::High,
            title: "Outbound HTTP request URL built from non-literal input",
            remediation: "Allow-list outbound hosts/URLs and resolve them from config, never from user input; block internal/link-local ranges before requesting.",
            queries: &[
                (
                    Lang::Python,
                    r#"(call
                        function: (attribute object: (identifier) @obj attribute: (identifier) @fn)
                        arguments: (argument_list (binary_operator) @concat)
                        (#eq? @obj "requests")
                        (#match? @fn "^(get|post|put|delete|head|request)$")) @sink"#,
                ),
                (
                    Lang::JavaScript,
                    r#"(call_expression
                        function: [
                          (identifier) @fn
                          (member_expression property: (property_identifier) @fn)
                        ]
                        arguments: (arguments [
                          (template_string)
                          (binary_expression operator: "+")
                        ])
                        (#match? @fn "^(fetch|get|post|put|request)$")) @sink"#,
                ),
                (
                    Lang::TypeScript,
                    r#"(call_expression
                        function: [
                          (identifier) @fn
                          (member_expression property: (property_identifier) @fn)
                        ]
                        arguments: (arguments [
                          (template_string)
                          (binary_expression operator: "+")
                        ])
                        (#match? @fn "^(fetch|get|post|put|request)$")) @sink"#,
                ),
                (
                    Lang::Tsx,
                    r#"(call_expression
                        function: [
                          (identifier) @fn
                          (member_expression property: (property_identifier) @fn)
                        ]
                        arguments: (arguments [
                          (template_string)
                          (binary_expression operator: "+")
                        ])
                        (#match? @fn "^(fetch|get|post|put|request)$")) @sink"#,
                ),
                (
                    Lang::Rust,
                    r#"(call_expression
                        function: (scoped_identifier path: (identifier) @obj name: (identifier) @fn)
                        arguments: (arguments [
                          (macro_invocation)
                          (reference_expression (macro_invocation))
                        ])
                        (#eq? @obj "reqwest")
                        (#eq? @fn "get")) @sink"#,
                ),
            ],
        },
        QueryRule {
            check: "sast_open_redirect",
            cwe: "CWE-601",
            severity: Severity::Medium,
            title: "Redirect target derived from non-literal input",
            remediation: "Validate redirect targets against an allow-list of hosts/paths; never redirect to a URL taken verbatim from the request.",
            queries: &[
                (
                    Lang::Python,
                    r#"(call
                        function: (identifier) @fn
                        arguments: (argument_list [
                          (binary_operator)
                          (call)
                          (attribute)
                        ])
                        (#eq? @fn "redirect")) @sink"#,
                ),
                (
                    Lang::JavaScript,
                    r#"(call_expression
                        function: (member_expression property: (property_identifier) @fn)
                        arguments: (arguments [
                          (template_string)
                          (binary_expression operator: "+")
                          (call_expression)
                        ])
                        (#match? @fn "^(redirect|sendRedirect|http_redirect)$")) @sink"#,
                ),
                (
                    Lang::JavaScript,
                    r#"(call_expression
                        function: (member_expression property: (property_identifier) @fn)
                        arguments: (arguments
                          (member_expression
                            object: (member_expression object: (identifier) @reqid)
                            property: (property_identifier)))
                        (#match? @fn "^(redirect|sendRedirect|http_redirect)$")
                        (#match? @reqid "^(req|request)$")) @sink"#,
                ),
                (
                    Lang::TypeScript,
                    r#"(call_expression
                        function: (member_expression property: (property_identifier) @fn)
                        arguments: (arguments [
                          (template_string)
                          (binary_expression operator: "+")
                          (call_expression)
                        ])
                        (#match? @fn "^(redirect|sendRedirect|http_redirect)$")) @sink"#,
                ),
                (
                    Lang::TypeScript,
                    r#"(call_expression
                        function: (member_expression property: (property_identifier) @fn)
                        arguments: (arguments
                          (member_expression
                            object: (member_expression object: (identifier) @reqid)
                            property: (property_identifier)))
                        (#match? @fn "^(redirect|sendRedirect|http_redirect)$")
                        (#match? @reqid "^(req|request)$")) @sink"#,
                ),
                (
                    Lang::Tsx,
                    r#"(call_expression
                        function: (member_expression property: (property_identifier) @fn)
                        arguments: (arguments [
                          (template_string)
                          (binary_expression operator: "+")
                          (call_expression)
                        ])
                        (#match? @fn "^(redirect|sendRedirect|http_redirect)$")) @sink"#,
                ),
                (
                    Lang::Tsx,
                    r#"(call_expression
                        function: (member_expression property: (property_identifier) @fn)
                        arguments: (arguments
                          (member_expression
                            object: (member_expression object: (identifier) @reqid)
                            property: (property_identifier)))
                        (#match? @fn "^(redirect|sendRedirect|http_redirect)$")
                        (#match? @reqid "^(req|request)$")) @sink"#,
                ),
            ],
        },
        QueryRule {
            check: "sast_xss_sink",
            cwe: "CWE-79",
            severity: Severity::Medium,
            title: "HTML sink assigned non-literal content (DOM XSS)",
            remediation: "Assign untrusted data only via textContent / safe DOM APIs, or sanitize with DOMPurify; never innerHTML/document.write with dynamic strings.",
            queries: &[
                (
                    Lang::JavaScript,
                    r#"(assignment_expression
                        left: (member_expression property: (property_identifier) @prop)
                        right: [
                          (template_string)
                          (binary_expression operator: "+")
                        ]
                        (#match? @prop "^(innerHTML|outerHTML|insertAdjacentHTML)$")) @sink"#,
                ),
                (
                    Lang::JavaScript,
                    r#"(call_expression
                        function: (member_expression property: (property_identifier) @fn)
                        arguments: (arguments [
                          (template_string)
                          (binary_expression operator: "+")
                        ])
                        (#match? @fn "^(write|writeln)$")) @sink"#,
                ),
                (
                    Lang::TypeScript,
                    r#"(assignment_expression
                        left: (member_expression property: (property_identifier) @prop)
                        right: [
                          (template_string)
                          (binary_expression operator: "+")
                        ]
                        (#match? @prop "^(innerHTML|outerHTML|insertAdjacentHTML)$")) @sink"#,
                ),
                (
                    Lang::TypeScript,
                    r#"(call_expression
                        function: (member_expression property: (property_identifier) @fn)
                        arguments: (arguments [
                          (template_string)
                          (binary_expression operator: "+")
                        ])
                        (#match? @fn "^(write|writeln)$")) @sink"#,
                ),
                (
                    Lang::Tsx,
                    r#"(assignment_expression
                        left: (member_expression property: (property_identifier) @prop)
                        right: [
                          (template_string)
                          (binary_expression operator: "+")
                        ]
                        (#match? @prop "^(innerHTML|outerHTML|insertAdjacentHTML)$")) @sink"#,
                ),
                (
                    Lang::Tsx,
                    r#"(call_expression
                        function: (member_expression property: (property_identifier) @fn)
                        arguments: (arguments [
                          (template_string)
                          (binary_expression operator: "+")
                        ])
                        (#match? @fn "^(write|writeln)$")) @sink"#,
                ),
            ],
        },
        QueryRule {
            check: "sast_tls_verify_disabled",
            cwe: "CWE-295",
            severity: Severity::High,
            title: "TLS certificate verification disabled",
            remediation: "Never disable certificate verification in production; pin a custom CA or the expected leaf cert instead.",
            queries: &[
                (
                    Lang::Python,
                    r#"(keyword_argument
                        name: (identifier) @kw
                        value: (false)
                        (#eq? @kw "verify")) @sink"#,
                ),
                (
                    Lang::JavaScript,
                    r#"(pair
                        key: (property_identifier) @k
                        value: (false)
                        (#eq? @k "rejectUnauthorized")) @sink"#,
                ),
                (
                    Lang::TypeScript,
                    r#"(pair
                        key: (property_identifier) @k
                        value: (false)
                        (#eq? @k "rejectUnauthorized")) @sink"#,
                ),
                (
                    Lang::Tsx,
                    r#"(pair
                        key: (property_identifier) @k
                        value: (false)
                        (#eq? @k "rejectUnauthorized")) @sink"#,
                ),
                (
                    Lang::Rust,
                    r#"(call_expression
                        function: [
                          (field_expression field: (field_identifier) @m)
                          (scoped_identifier name: (identifier) @m)
                        ]
                        arguments: (arguments (boolean_literal))
                        (#match? @m "^(danger_accept_invalid_certs|danger_accept_invalid_hostnames)$")) @sink"#,
                ),
            ],
        },
        QueryRule {
            check: "sast_xpath_injection",
            cwe: "CWE-643",
            severity: Severity::High,
            title: "XPath query built via string concatenation",
            remediation: "Build XPath with parameterized/precompiled expressions; never concatenate input into the query string.",
            queries: &[
                (
                    Lang::Python,
                    r#"(call
                        function: (attribute attribute: (identifier) @fn)
                        arguments: (argument_list (binary_operator) @concat)
                        (#match? @fn "^(xpath|evaluate|find|findall|findtext)$")) @sink"#,
                ),
                (
                    Lang::JavaScript,
                    r#"(call_expression
                        function: (member_expression property: (property_identifier) @fn)
                        arguments: (arguments (binary_expression operator: "+"))
                        (#match? @fn "^(evaluate|select|select1|find)$")) @sink"#,
                ),
                (
                    Lang::TypeScript,
                    r#"(call_expression
                        function: (member_expression property: (property_identifier) @fn)
                        arguments: (arguments (binary_expression operator: "+"))
                        (#match? @fn "^(evaluate|select|select1|find)$")) @sink"#,
                ),
                (
                    Lang::Tsx,
                    r#"(call_expression
                        function: (member_expression property: (property_identifier) @fn)
                        arguments: (arguments (binary_expression operator: "+"))
                        (#match? @fn "^(evaluate|select|select1|find)$")) @sink"#,
                ),
            ],
        },
        QueryRule {
            check: "sast_ldap_injection",
            cwe: "CWE-90",
            severity: Severity::High,
            title: "LDAP filter built via string concatenation",
            remediation: "Escape LDAP special characters (RFC 4515) or use parameterized LDAP APIs; never concatenate input into a filter.",
            queries: &[
                (
                    Lang::Python,
                    r#"(call
                        function: (attribute attribute: (identifier) @fn)
                        arguments: (argument_list
                          (keyword_argument
                            name: (identifier) @kw
                            value: (binary_operator) @concat))
                        (#match? @fn "^(search|extend)$")
                        (#match? @kw "^(search_filter|filter|attributes)$")) @sink"#,
                ),
                (
                    Lang::JavaScript,
                    r#"(call_expression
                        function: (member_expression property: (property_identifier) @fn)
                        arguments: (arguments (binary_expression operator: "+"))
                        (#match? @fn "^(search|bind|add|modify)$")) @sink"#,
                ),
                (
                    Lang::TypeScript,
                    r#"(call_expression
                        function: (member_expression property: (property_identifier) @fn)
                        arguments: (arguments (binary_expression operator: "+"))
                        (#match? @fn "^(search|bind|add|modify)$")) @sink"#,
                ),
                (
                    Lang::Tsx,
                    r#"(call_expression
                        function: (member_expression property: (property_identifier) @fn)
                        arguments: (arguments (binary_expression operator: "+"))
                        (#match? @fn "^(search|bind|add|modify)$")) @sink"#,
                ),
            ],
        },
        QueryRule {
            check: "sast_weak_random",
            cwe: "CWE-338",
            severity: Severity::Medium,
            title: "Security value generated from a weak PRNG",
            remediation: "Use a cryptographically secure generator (secrets module in Python, crypto.randomBytes/WebCrypto in JS) for tokens, keys, and session identifiers.",
            queries: &[
                (
                    Lang::Python,
                    r#"(assignment
                        left: (identifier) @dest
                        right: (_) @rhs
                        (#match? @rhs "random\.(randint|randrange|random|choice|choices|getrandbits|uniform)")
                        (#match? @dest "(token|Token|TOKEN|secret|Secret|SECRET|password|Password|PASSWORD|passwd|otp|OTP|nonce|Nonce|salt|Salt|session|Session|csrf|Csrf|CSRF|api[_]?key|API[_]?KEY|Api[_]?Key)")) @sink"#,
                ),
                (
                    Lang::JavaScript,
                    r#"(variable_declarator
                        name: (identifier) @dest
                        value: (_) @rhs
                        (#match? @rhs "Math\.random")
                        (#match? @dest "(token|Token|TOKEN|secret|Secret|SECRET|password|Password|PASSWORD|otp|OTP|nonce|Nonce|salt|Salt|session|Session|csrf|Csrf|CSRF|api[_]?key|API[_]?KEY|Api[_]?Key)")) @sink"#,
                ),
                (
                    Lang::TypeScript,
                    r#"(variable_declarator
                        name: (identifier) @dest
                        value: (_) @rhs
                        (#match? @rhs "Math\.random")
                        (#match? @dest "(token|Token|TOKEN|secret|Secret|SECRET|password|Password|PASSWORD|otp|OTP|nonce|Nonce|salt|Salt|session|Session|csrf|Csrf|CSRF|api[_]?key|API[_]?KEY|Api[_]?Key)")) @sink"#,
                ),
                (
                    Lang::Tsx,
                    r#"(variable_declarator
                        name: (identifier) @dest
                        value: (_) @rhs
                        (#match? @rhs "Math\.random")
                        (#match? @dest "(token|Token|TOKEN|secret|Secret|SECRET|password|Password|PASSWORD|otp|OTP|nonce|Nonce|salt|Salt|session|Session|csrf|Csrf|CSRF|api[_]?key|API[_]?KEY|Api[_]?Key)")) @sink"#,
                ),
            ],
        },
    ]
}

/// Runs every applicable query rule against one already-parsed file and
/// appends a `Finding` per match. `path` and `source` are used only to
/// build evidence text (file:line + the matched snippet); no
/// dedicated file-path field exists on `Finding`.
pub fn scan_file(
    rules: &[QueryRule],
    lang: Lang,
    path: &std::path::Path,
    source: &[u8],
) -> Vec<Finding> {
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
                let Some(cap) = m.captures().iter().find(|c| c.index == sink_ix) else {
                    continue;
                };
                let node = cap.node;
                let text = node.utf8_text(source).unwrap_or("").trim();
                let snippet: String = text.chars().take(120).collect();
                let line = node.start_position().row + 1;
                let mut f = Finding::new(
                    rule.check,
                    rule.severity,
                    rule.title,
                    format!("{} [{}]", rule.cwe, rule.check),
                )
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
        scan_file(
            &rules,
            lang,
            std::path::Path::new("fixture"),
            source.as_bytes(),
        )
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
        let findings = run(
            "sast_command_exec",
            Lang::JavaScript,
            "child_process.exec(cmd);",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn command_exec_does_not_flag_js_array_spawn() {
        let findings = run(
            "sast_command_exec",
            Lang::JavaScript,
            "spawn('ls', ['-la']);",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn command_exec_flags_rust_shell_spawn() {
        let findings = run(
            "sast_command_exec",
            Lang::Rust,
            r#"Command::new("sh").arg("-c").arg(user_input).output()"#,
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn command_exec_does_not_flag_rust_argv_spawn() {
        let findings = run(
            "sast_command_exec",
            Lang::Rust,
            r#"Command::new("ls").arg("-la").output()"#,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn deserialize_flags_python_pickle_loads() {
        let findings = run(
            "sast_unsafe_deserialize",
            Lang::Python,
            "pickle.loads(data)",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn deserialize_does_not_flag_python_json_loads() {
        let findings = run("sast_unsafe_deserialize", Lang::Python, "json.loads(data)");
        assert!(findings.is_empty());
    }

    #[test]
    fn weak_crypto_flags_python_md5() {
        let findings = run(
            "sast_weak_crypto",
            Lang::Python,
            "hashlib.md5(password.encode())",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn weak_crypto_does_not_flag_python_sha256() {
        let findings = run(
            "sast_weak_crypto",
            Lang::Python,
            "hashlib.sha256(password.encode())",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn weak_crypto_flags_js_create_hash_md5() {
        let findings = run(
            "sast_weak_crypto",
            Lang::JavaScript,
            "crypto.createHash('md5').update(pw).digest('hex');",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn weak_crypto_does_not_flag_js_create_hash_sha256() {
        let findings = run(
            "sast_weak_crypto",
            Lang::JavaScript,
            "crypto.createHash('sha256').update(pw).digest('hex');",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn path_traversal_flags_python_open_concat() {
        let findings = run(
            "sast_path_traversal",
            Lang::Python,
            "open(base_dir + filename)",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn path_traversal_does_not_flag_python_open_literal() {
        let findings = run(
            "sast_path_traversal",
            Lang::Python,
            "open(\"static/report.txt\")",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn path_traversal_flags_js_readfile_concat() {
        let findings = run(
            "sast_path_traversal",
            Lang::JavaScript,
            "fs.readFileSync(baseDir + '/' + name);",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn path_traversal_does_not_flag_js_readfile_literal() {
        let findings = run(
            "sast_path_traversal",
            Lang::JavaScript,
            "fs.readFileSync('./static/report.txt');",
        );
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
        let src =
            "const id: string = getId();\ndb.query(\"SELECT * FROM users WHERE id = \" + id, cb);";
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
        let src =
            "const pw: string = getPassword();\ncrypto.createHash('md5').update(pw).digest('hex');";
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
        let findings = run(
            "sast_unsafe_deserialize",
            Lang::JavaScript,
            "unserialize(data);",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn deserialize_does_not_flag_js_json_parse() {
        let findings = run(
            "sast_unsafe_deserialize",
            Lang::JavaScript,
            "JSON.parse(data);",
        );
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
        let src =
            "const el = <div>{1}</div>;\nconst cmd: string = getCmd();\nchild_process.exec(cmd);";
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

    #[test]
    fn ssrf_flags_python_requests_concat_url() {
        let src = "requests.get(\"http://internal-svc/\" + user_host)";
        let findings = run("sast_ssrf", Lang::Python, src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ssrf_does_not_flag_python_requests_literal_url() {
        let src = "requests.get(\"https://api.example.com/v1/ping\")";
        let findings = run("sast_ssrf", Lang::Python, src);
        assert!(findings.is_empty());
    }

    #[test]
    fn ssrf_flags_js_fetch_template_literal() {
        let src = "fetch(`/api/users/${username}`);";
        let findings = run("sast_ssrf", Lang::JavaScript, src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ssrf_does_not_flag_js_fetch_literal() {
        let src = "fetch('/api/users');";
        let findings = run("sast_ssrf", Lang::JavaScript, src);
        assert!(findings.is_empty());
    }

    #[test]
    fn ssrf_flags_rust_reqwest_get_with_format_macro() {
        let src = "reqwest::get(&format!(\"http://{host}/fetch\"))";
        let findings = run("sast_ssrf", Lang::Rust, src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ssrf_does_not_flag_rust_reqwest_get_literal() {
        let src = "reqwest::get(\"https://api.example.com/ping\")";
        let findings = run("sast_ssrf", Lang::Rust, src);
        assert!(findings.is_empty());
    }

    #[test]
    fn open_redirect_flags_express_redirect_from_request() {
        let src = "app.get('/go', (req, res) => { res.redirect(req.query.next); });";
        let findings = run("sast_open_redirect", Lang::JavaScript, src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn open_redirect_does_not_flag_literal_redirect() {
        let src = "app.get('/old', (req, res) => { res.redirect('/home'); });";
        let findings = run("sast_open_redirect", Lang::JavaScript, src);
        assert!(findings.is_empty());
    }

    #[test]
    fn open_redirect_flags_python_redirect_of_request_args() {
        let src = "return redirect(request.args.get('next'))";
        let findings = run("sast_open_redirect", Lang::Python, src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn xss_sink_flags_innerhtml_template_assignment() {
        let src = "el.innerHTML = `<b>${location.hash}</b>`;";
        let findings = run("sast_xss_sink", Lang::JavaScript, src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn xss_sink_flags_document_write_concat() {
        let src = "document.write('<b>' + userInput + '</b>');";
        let findings = run("sast_xss_sink", Lang::JavaScript, src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn xss_sink_does_not_flag_textcontent_assignment() {
        let src = "el.textContent = userInput;";
        let findings = run("sast_xss_sink", Lang::JavaScript, src);
        assert!(findings.is_empty());
    }

    #[test]
    fn tls_verify_flags_js_reject_unauthorized_false() {
        let src = "const agent = new https.Agent({ rejectUnauthorized: false });";
        let findings = run("sast_tls_verify_disabled", Lang::JavaScript, src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn tls_verify_does_not_flag_reject_unauthorized_true() {
        let src = "const agent = new https.Agent({ rejectUnauthorized: true });";
        let findings = run("sast_tls_verify_disabled", Lang::JavaScript, src);
        assert!(findings.is_empty());
    }

    #[test]
    fn tls_verify_flags_python_verify_false() {
        let src = "requests.get(url, verify=False)";
        let findings = run("sast_tls_verify_disabled", Lang::Python, src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn tls_verify_flags_rust_danger_accept_invalid_certs() {
        let src = "ClientConfig::builder().danger_accept_invalid_certs(true)";
        let findings = run("sast_tls_verify_disabled", Lang::Rust, src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn tls_verify_does_not_flag_rust_certs_enabled_builder() {
        let src = "ClientConfig::builder().with_root_certificates(roots).with_no_client_auth()";
        let findings = run("sast_tls_verify_disabled", Lang::Rust, src);
        assert!(findings.is_empty());
    }

    #[test]
    fn xpath_flags_python_concat_findall() {
        let src = "root.findall(\"//user[name='\" + name + \"']\")";
        let findings = run("sast_xpath_injection", Lang::Python, src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn xpath_does_not_flag_python_literal_findall() {
        let src = "root.findall(\"//user[name='alice']\")";
        let findings = run("sast_xpath_injection", Lang::Python, src);
        assert!(findings.is_empty());
    }

    #[test]
    fn xpath_flags_js_evaluate_concat() {
        let src = "doc.evaluate(\"//user[name='\" + name + \"']\", doc, null, 0, null);";
        let findings = run("sast_xpath_injection", Lang::JavaScript, src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ldap_flags_python_search_filter_concat() {
        let src = "conn.search(search_base=\"dc=x\", search_filter=\"(cn=\" + user + \")\")";
        let findings = run("sast_ldap_injection", Lang::Python, src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ldap_does_not_flag_python_literal_filter() {
        let src = "conn.search(search_base=\"dc=x\", search_filter=\"(cn=alice)\")";
        let findings = run("sast_ldap_injection", Lang::Python, src);
        assert!(findings.is_empty());
    }

    #[test]
    fn ldap_flags_js_search_concat() {
        let src = "client.search(\"(cn=\" + user + \")\", cb);";
        let findings = run("sast_ldap_injection", Lang::JavaScript, src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn weak_random_flags_python_token_from_random() {
        let src = "import random\nsession_token = random.randint(100000, 999999)";
        let findings = run("sast_weak_random", Lang::Python, src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn weak_random_does_not_flag_python_unrelated_variable() {
        let src = "import random\ndice_roll = random.randint(1, 6)";
        let findings = run("sast_weak_random", Lang::Python, src);
        assert!(findings.is_empty());
    }

    #[test]
    fn weak_random_does_not_flag_python_secrets_module() {
        let src = "import secrets\nsession_token = secrets.token_hex(32)";
        let findings = run("sast_weak_random", Lang::Python, src);
        assert!(findings.is_empty());
    }

    #[test]
    fn weak_random_flags_js_math_random_token() {
        let src = "const csrfToken = Math.random().toString(36);";
        let findings = run("sast_weak_random", Lang::JavaScript, src);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn weak_random_does_not_flag_js_unrelated_variable() {
        let src = "const animationOffset = Math.random() * 100;";
        let findings = run("sast_weak_random", Lang::JavaScript, src);
        assert!(findings.is_empty());
    }
}
