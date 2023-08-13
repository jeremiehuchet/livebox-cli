use anyhow::{anyhow, Result};
use clap::{arg, builder::PossibleValue, Args, Parser, Subcommand, ValueEnum};

use livebox::SetPortFowardingParams;
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
    query: Option<JsonPath>,

    /// output raw strings, not JSON text
    #[arg(short = 'r', long = "raw")]
    output_raw_strings: bool,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Invoke sysbus method
    Exec {
        /// service name (ex: `NMC`)
        #[arg(short, long)]
        service: String,

        /// method name (ex: `getWANStatus`)
        #[arg(short, long)]
        method: String,
    },
    /// Edit NAT rules
    NAT {
        #[command(subcommand)]
        action: FirewallActions,
    },
}

#[derive(Debug, Subcommand)]
enum FirewallActions {
    List,
    Add(FirewallRule),
    Enable(NamedFirewallRule),
    Disable(NamedFirewallRule),
    Remove(NamedFirewallRule),
}

#[derive(Debug, Args)]
struct FirewallRule {
    /// A unique identifier
    #[arg(long)]
    id: String,

    /// A description
    #[arg(long)]
    description: String,

    /// The protocol to forward
    #[arg(short, long, value_enum)]
    protocol: Protocol,

    /// The allowed source hosts
    #[arg(long = "source")]
    source_host: Option<String>,

    /// The exposed port
    #[arg(long = "sport")]
    source_port: i16,

    /// The destination host
    #[arg(long = "destination")]
    destination_host: String,

    /// The destination port
    #[arg(long = "dport")]
    destination_port: i16,
}

impl Into<SetPortFowardingParams> for FirewallRule {
    fn into(self) -> SetPortFowardingParams {
        SetPortFowardingParams::new(
            self.id,
            self.description,
            self.protocol.into(),
            self.source_port.to_string(),
            self.destination_port.to_string(),
            self.destination_host,
        )
    }
}

#[derive(Debug, Clone)]
enum Protocol {
    TCP,
    UDP,
    ALL,
}

impl Into<livebox::Protocol> for Protocol {
    fn into(self) -> livebox::Protocol {
        match self {
            Protocol::TCP => livebox::Protocol::TCP,
            Protocol::UDP => livebox::Protocol::UDP,
            Protocol::ALL => livebox::Protocol::ALL,
        }
    }
}

impl ValueEnum for Protocol {
    fn value_variants<'a>() -> &'a [Self] {
        &[Protocol::TCP, Protocol::UDP, Protocol::ALL]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(match &self {
            Protocol::TCP => PossibleValue::new("tcp"),
            Protocol::UDP => PossibleValue::new("udp"),
            Protocol::ALL => PossibleValue::new("all"),
        })
    }
}

#[derive(Debug, Args)]
struct NamedFirewallRule {
    /// rule identifier
    id: String,
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
        Commands::Exec { service, method } => client.execute(service, method).await?,
        Commands::NAT { action } => match action {
            FirewallActions::List => client.list_nat_rules().await?,
            FirewallActions::Add(rule) => client.add_nat_rule(rule.into()).await?,
            FirewallActions::Enable(rule) => client.enable_nat_rule(rule.id).await?,
            FirewallActions::Disable(rule) => client.disable_nat_rule(rule.id).await?,
            FirewallActions::Remove(rule) => client.remove_nat_rule(rule.id).await?,
        },
    };
    client.logout().await?;

    let output = match args.query {
        Some(path) => path
            .query(&response)
            .exactly_one()
            .map_err(|err| anyhow!(err).context("No match for given JsonPath"))?,
        None => &response,
    };
    let output = if args.output_raw_strings && output.is_string() {
        output.as_str().unwrap().to_string()
    } else {
        serde_json::to_string_pretty(output)?
    };

    println!("{}", output);
    Ok(())
}
