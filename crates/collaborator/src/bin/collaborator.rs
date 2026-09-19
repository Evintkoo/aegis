//! Standalone OOB listener binary. Run this on a host the TARGET server
//! can reach, then point `pentest`'s `--collaborator`/blind_oob payloads
//! at `http://<this-host>:<port>/`. Port of `collaborator.py`'s `main()`.
use clap::Parser;
use pentest_collaborator::{bind, Collaborator};
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(about = "OOB interaction collaborator server.")]
struct Args {
    #[arg(long, default_value = "0.0.0.0")]
    host: String,
    #[arg(long, default_value_t = 9000)]
    port: u16,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let (listener, _addr) = bind(&args.host, args.port).await.unwrap_or_else(|e| {
        eprintln!("error: failed to bind {}:{}: {e}", args.host, args.port);
        std::process::exit(1);
    });

    println!(
        "[*] Collaborator listening on http://{}:{}",
        args.host, args.port
    );
    println!(
        "    Point blind payloads at http://<reachable-host>:{}/<token>/",
        args.port
    );
    println!("    Query hits: GET /__hits/<token>");

    let collab = Arc::new(Collaborator::new());
    tokio::select! {
        _ = collab.serve(listener) => {},
        _ = tokio::signal::ctrl_c() => {
            println!("\n[*] shutting down");
        }
    }
}
