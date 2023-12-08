use clap::Parser;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(long)]
    pub dev: String,
    #[arg(long)]
    pub duckdns_token: String,
    #[arg(required = true)]
    pub domains: Vec<String>,
}
