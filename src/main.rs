use anyhow::Result;
use clap::{Args, Parser, Subcommand};

use serde_json_path::JsonPath;

mod livebox;

#[derive(Debug, Parser)]
struct CliArgs {
    /// Livebox base url
    #[arg(long = "base-url", env, default_value = livebox::LIVEBOX_BASE_URL)]
    livebox_api_baseurl: String,

    /// Livebox administration username
    #[arg(short, long, default_value = "admin")]
    username: String,

    /// Livebox administration password
    #[arg(short, long)]
    password: String,

    #[command(subcommand)]
    command: Commands,

    /// json path expression to filter output (ex: `$.IPAddress`)
    #[arg(short, long)]
    query: Option<String>,

    /// output raw strings, not JSON text
    #[arg(short = 'r', long = "raw")]
    output_raw_strings: bool,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Invoke sysbus method
    Show {
        /// service name (ex: `NMC`)
        #[arg(short, long)]
        service: String,

        /// method name (ex: `getWANStatus`)
        #[arg(short, long)]
        method: String,
    },
    /// Edit firewall NAT rules
    Firewall {
        #[command(subcommand)]
        action: FirewallActions,
    },
}

#[derive(Debug, Subcommand)]
enum SysbusService {}

#[derive(Debug, Subcommand)]
enum FirewallActions {
    Add(FirewallRule),
    Enable(NamedFirewallRule),
    Disable(NamedFirewallRule),
    Remove(NamedFirewallRule),
}

#[derive(Debug, Args)]
struct FirewallRule {
    /// externalPort
    #[arg(short, long)]
    externalPort: i32,
    /// internalPort
    #[arg(short, long)]
    internalPort: i32,
}

#[derive(Debug, Args)]
struct NamedFirewallRule {
    /// rule name
    name: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    let args = CliArgs::parse();

    let client = livebox::ClientBuilder::default()
        .with_base_url(args.livebox_api_baseurl)
        .with_credentials(args.username, args.password)
        .build()
        .await?;

    let response = match args.command {
        Commands::Show { service, method } => client.execute(service, method).await?,
        Commands::Firewall { action } => todo!(),
    };
    client.logout().await?;

    if let Some(response) = response {
        let output = match args.query.map(|q| JsonPath::parse(q.as_str())) {
            Some(path) => path?.query(&response).exactly_one()?,
            None => &response,
        };
        let output = if args.output_raw_strings && output.is_string() {
            output.as_str().unwrap().to_string()
        } else {
            serde_json::to_string_pretty(output)?
        };

        println!("{}", output);
    }
    Ok(())
}
