use clap::{builder::PossibleValue, Args, Parser, Subcommand, ValueEnum};

use livebox::SetPortFowardingParams;
use serde_json_path::JsonPath;
use thiserror::Error;

mod livebox;

#[derive(Error, Debug)]
enum CliError {
    #[error("Livebox error: {0}")]
    Livebox(#[from] livebox::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("No match for given JsonPath")]
    JsonPathNoMatch,
}

type Result<T> = std::result::Result<T, CliError>;

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

    /// Allow insecure server connections when using SSL (default: false, verifies certificates)
    #[arg(short = 'k', long)]
    insecure: bool,

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
async fn main() -> Result<()> {
    env_logger::init();

    let args = CliArgs::parse();
    let output = run(args).await?;
    println!("{}", output);
    Ok(())
}

async fn run(args: CliArgs) -> Result<String> {
    let client = livebox::ClientBuilder::default()
        .with_base_url(args.livebox_api_baseurl)
        .with_credentials(args.username, args.password)
        .with_insecure(args.insecure)
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
            .map_err(|_| CliError::JsonPathNoMatch)?,
        None => &response,
    };
    let output = if args.output_raw_strings {
        match output {
            serde_json::Value::String(s) => s.clone(),
            _ => serde_json::to_string_pretty(output)?,
        }
    } else {
        serde_json::to_string_pretty(output)?
    };

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use mockito::Server;

    #[cfg(test)]
    struct MockLivebox {
        _m_login: mockito::Mock,
        _m_exec: mockito::Mock,
        _m_logout: mockito::Mock,
        server: mockito::ServerGuard,
    }

    impl MockLivebox {
        const DEFAULT_RESPONSE: &'static str = r#"{
  "data": {
    "ConnectionState": "Bound",
    "DNSServers": "163.134.239.9,59.50.158.77",
    "GponState": "O5_Operation",
    "IPAddress": "55.27.2.115",
    "IPv6Address": "4e95:624a:8079:0784:6922:e6e7:b878:5815",
    "IPv6DelegatedPrefix": "4e95:624a:8079:0784::/56",
    "LastConnectionError": "None",
    "LinkState": "up",
    "LinkType": "gpon",
    "MACAddress": "BA-D3-52-DA-DB-30",
    "Protocol": "dhcp",
    "RemoteGateway": "212.168.252.207",
    "WanState": "up"
  },
  "status": true
}"#;

        async fn new() -> Self {
            Self::with_response(Self::DEFAULT_RESPONSE).await
        }

        async fn with_response(mock_response_body: &'static str) -> Self {
            let mut server = Server::new_async().await;
            let _url = server.url();

            // Mock login
            let _m_login = server.mock("POST", "/ws")
                .match_header("Authorization", "X-Sah-Login")
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(r#"{"data":{"contextID":"dummy-context","groups":"admin","username":"admin"},"status":0}"#)
                .create_async().await;

            // Mock execution
            let _m_exec = server
                .mock("POST", "/ws")
                .match_header("x-context", "dummy-context")
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(mock_response_body)
                .create_async()
                .await;

            // Mock logout
            let _m_logout = server
                .mock("POST", "/ws")
                .match_header("Authorization", "X-Sah-Logout dummy-context")
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(r#"{"status":1}"#)
                .create_async()
                .await;

            Self {
                _m_login,
                _m_exec,
                _m_logout,
                server,
            }
        }

        fn url(&self) -> String {
            self.server.url()
        }
    }

    #[tokio::test]
    async fn should_return_original_server_response_body() {
        let mock = MockLivebox::new().await;

        let args = CliArgs::try_parse_from(&[
            "livebox-cli",
            "--base-url",
            &mock.url(),
            "--username",
            "admin",
            "--password",
            "secret",
            "exec",
            "--service",
            "NMC",
            "--method",
            "getWANStatus",
        ])
        .unwrap();

        let output_str = run(args).await.unwrap();

        // Parse both as Value to ignore formatting differences
        let actual_json: serde_json::Value = serde_json::from_str(&output_str).unwrap();
        let expected_json: serde_json::Value =
            serde_json::from_str(MockLivebox::DEFAULT_RESPONSE).unwrap();

        assert_eq!(actual_json, expected_json);
    }

    #[tokio::test]
    async fn should_extract_value_with_json_path_query() {
        let mock = MockLivebox::new().await;

        let args = CliArgs::try_parse_from(&[
            "livebox-cli",
            "--base-url",
            &mock.url(),
            "--username",
            "admin",
            "--password",
            "secret",
            "--query",
            "$.data.IPAddress",
            "exec",
            "--service",
            "NMC",
            "--method",
            "getWANStatus",
        ])
        .unwrap();

        let output_str = run(args).await.unwrap();

        assert_eq!(output_str.trim(), r#""55.27.2.115""#);
    }

    #[tokio::test]
    async fn should_extract_raw_value_with_json_path_query() {
        let mock = MockLivebox::new().await;

        let args = CliArgs::try_parse_from(&[
            "livebox-cli",
            "--base-url",
            &mock.url(),
            "--username",
            "admin",
            "--password",
            "secret",
            "--query",
            "$.data.IPAddress",
            "--raw",
            "exec",
            "--service",
            "NMC",
            "--method",
            "getWANStatus",
        ])
        .unwrap();

        let output_str = run(args).await.unwrap();

        assert_eq!(output_str, "55.27.2.115");
    }
}
