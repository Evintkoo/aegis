use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "pentest", about = "Authorized web pentest toolkit")]
struct Cli {
    /// Print available checks and exit.
    #[arg(long)]
    list_checks: bool,

    /// Directory to write CVE-schema finding records under.
    #[arg(long, default_value = "cve")]
    cve_dir: String,
}

fn main() {
    let cli = Cli::parse();

    if cli.list_checks {
        println!("Available checks:");
        println!("  (none registered yet — see docs/superpowers/plans/ for the DAST engine plan)");
        return;
    }

    println!("pentest: no checks registered yet. Run with --list-checks to see current status.");
    println!("(--cve-dir is currently accepted but unused: {})", cli.cve_dir);
}
