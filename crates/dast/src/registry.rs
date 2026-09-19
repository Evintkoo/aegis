use pentest_core::{Finding, HttpClient};
use std::future::Future;
use std::pin::Pin;

use crate::opts::Opts;

/// A boxed, pinned future returning the findings a check produced.
pub type CheckFuture<'a> = Pin<Box<dyn Future<Output = Vec<Finding>> + Send + 'a>>;

/// A plain function pointer (not a trait — this avoids needing the
/// `async-trait` crate) that kicks off a check and returns its future.
/// The higher-ranked `for<'a>` bound lets one fn pointer type describe
/// every check regardless of how long its borrows of `client`/`opts` live.
///
/// IMPORTANT for every check function implemented against this type (this
/// task and every later one that adds a check): a plain
/// `fn run(client: &HttpClient, opts: &Opts) -> CheckFuture<'_>` will NOT
/// compile. With two distinct reference parameters and no `&self`, Rust's
/// lifetime elision rules require an explicit output lifetime — there's no
/// single input lifetime for `'_` to bind to. Every check function must be
/// written with one explicit lifetime shared by both parameters and the
/// return type: `fn run<'a>(client: &'a HttpClient, opts: &'a Opts) ->
/// CheckFuture<'a>`. This is not a style preference — the elided form is a
/// compile error, confirmed while writing this plan.
pub type CheckFn = for<'a> fn(&'a HttpClient, &'a Opts) -> CheckFuture<'a>;

#[derive(Clone, Copy)]
pub struct CheckEntry {
    pub name: &'static str,
    pub run: CheckFn,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pentest_core::{HttpClientConfig, Severity};

    fn fake_check<'a>(_client: &'a HttpClient, _opts: &'a Opts) -> CheckFuture<'a> {
        Box::pin(async move { vec![Finding::new("fake", Severity::Info, "t", "d")] })
    }

    #[tokio::test]
    async fn a_check_entry_can_be_invoked_through_the_fn_pointer() {
        let entry = CheckEntry {
            name: "fake",
            run: fake_check,
        };
        let client = HttpClient::new("http://127.0.0.1:1", HttpClientConfig::default());
        let opts = Opts::default();

        let findings = (entry.run)(&client, &opts).await;

        assert_eq!(entry.name, "fake");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "t");
    }
}
