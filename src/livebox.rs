use std::{collections::HashMap, sync::Arc};

use anyhow::{anyhow, Ok, Result};

use log::{debug, warn};
use reqwest::{
    cookie::Jar,
    header::{HeaderMap, HeaderName, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE},
    Client as ReqwestClient, ClientBuilder as ReqwestClientBuilder,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(super) const LIVEBOX_BASE_URL: &str = "http://livebox.home";
const APPLICATION_NAME: &str = "livebox-cli";

const APPLICATION_SAH_WS_CALL: &str = "application/x-sah-ws-4-call+json";
const X_SAH_LOGIN: &str = "X-Sah-Login";
const X_SAH_LOGOUT: &str = "X-Sah-Logout";
const X_CONTEXT: &str = "x-context";

pub(super) struct ClientBuilder {
    base_url_ws: String,
    credentials: Option<(String, String)>,
    insecure: bool,
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self {
            base_url_ws: LIVEBOX_BASE_URL.to_string(),
            credentials: None,
            insecure: false,
        }
    }
}

impl ClientBuilder {
    pub fn with_base_url(mut self, base_url: String) -> Self {
        let base_url_no_trailing_slash = base_url.strip_suffix("/").unwrap_or(&base_url);
        self.base_url_ws = format!("{base_url_no_trailing_slash}/ws");
        self
    }

    pub fn with_credentials(mut self, username: String, password: String) -> Self {
        self.credentials = Some((username, password));
        self
    }

    pub fn with_insecure(mut self, insecure: bool) -> Self {
        self.insecure = insecure;
        self
    }

    pub async fn build(self) -> Result<Client> {
        let (username, password) = self.credentials.ok_or(anyhow!("missing credentials"))?;
        Client::login(self.base_url_ws, username, password, self.insecure).await
    }
}

pub(super) struct Client {
    http_client: ReqwestClient,
    base_url_ws: String,
    context_id: String,
}

impl Client {
    async fn login(
        base_url: String,
        username: String,
        password: String,
        insecure: bool,
    ) -> Result<Self> {
        let cookie_store = Arc::new(Jar::default());
        let http_client = ReqwestClientBuilder::default()
            .cookie_provider(cookie_store.clone())
            .danger_accept_invalid_certs(insecure)
            .build()
            .expect("error building HTTP client");

        let response = http_client
            .post(&base_url)
            .header(CONTENT_TYPE, APPLICATION_SAH_WS_CALL)
            .header(AUTHORIZATION, X_SAH_LOGIN)
            .json(&SysbusRequest::SahDeviceInformation(
                SahMethod::CreateContext {
                    parameters: LoginParameters {
                        application_name: APPLICATION_NAME.to_string(),
                        username,
                        password,
                    },
                },
            ))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await?;
            return Err(anyhow!("Authentication failed: {status}")
                .context(format!("Response body: {body}")));
        }

        let context_id = response.json::<LoginResponse>().await?.data.context_id;

        let context_headers = HeaderMap::from_iter(vec![
            (ACCEPT, HeaderValue::from_static(APPLICATION_SAH_WS_CALL)),
            (
                HeaderName::from_static(X_CONTEXT),
                HeaderValue::from_str(&context_id)?,
            ),
        ]);

        Ok(Client {
            http_client: ReqwestClientBuilder::default()
                .cookie_provider(cookie_store)
                .default_headers(context_headers)
                .danger_accept_invalid_certs(insecure)
                .build()
                .expect("error building HTTP client"),
            base_url_ws: base_url,
            context_id,
        })
    }

    pub async fn logout(&self) -> Result<()> {
        let req = SysbusRequest::SahDeviceInformation(SahMethod::ReleaseContext {
            parameters: LogoutParameters::default(),
        });
        debug!(
            ">>> POST {}\n{}",
            &self.base_url_ws,
            serde_json::to_string_pretty(&req)?
        );
        let response = self
            .http_client
            .post(&self.base_url_ws)
            .json(&req)
            .header(AUTHORIZATION, format!("{X_SAH_LOGOUT} {}", self.context_id))
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await?;
        debug!("<<< {status}\n{body}");
        if status.as_u16() != 401 {
            warn!("Logout error: {status}\n{body}")
        }
        let response = serde_json::from_str::<LogoutResponse>(&body)?;
        if response.status != 1 {
            warn!("Logout error: {body}")
        }
        Ok(())
    }

    async fn exec<R: Serialize>(&self, request: R) -> Result<Value> {
        debug!(
            ">>> POST {}\n{}",
            &self.base_url_ws,
            serde_json::to_string_pretty(&request)?
        );
        let response = self
            .http_client
            .post(&self.base_url_ws)
            .header(CONTENT_TYPE, APPLICATION_SAH_WS_CALL)
            .json(&request)
            .send()
            .await?;

        let status = response.status();
        let body = response.text().await?;
        debug!("<<< {status}\n{body}");
        if !status.is_success() {
            return Err(
                anyhow!("Execution failed: {status}").context(format!("Response body: {body}"))
            );
        }

        Ok(serde_json::from_str(&body)?)
    }

    pub async fn execute(&self, service: String, method: String) -> Result<Value> {
        self.execute_with_parameters(&service, &method, HashMap::new())
            .await
    }

    pub async fn execute_with_parameters(
        &self,
        service: &str,
        method: &str,
        parameters: HashMap<&str, &str>,
    ) -> Result<Value> {
        let req = GenericRequest {
            service,
            method,
            parameters,
        };
        Ok(self.exec(req).await?)
    }

    pub async fn list_nat_rules(&self) -> Result<Value> {
        Ok(self
            .exec(SysbusRequest::Firewall(FirewallMethod::GetPortForwarding {
                parameters: NoParameters {},
            }))
            .await?)
    }

    async fn structured_nat_rules(&self) -> Result<Vec<NatRuleView>> {
        let raw_rules = self.list_nat_rules().await?;
        let rules: Vec<NatRuleView> = raw_rules
            .get("status")
            .unwrap()
            .as_object()
            .unwrap()
            .values()
            .into_iter()
            .map(|value| serde_json::to_string(value).unwrap())
            .map(|str| serde_json::from_str(&str).unwrap())
            .collect();
        Ok(rules)
    }

    async fn update_nat_rule<F>(&self, rule_id: String, transform_rule: F) -> Result<Value>
    where
        F: FnOnce(&mut SetPortFowardingParams) -> (),
    {
        let actual_rules = self.structured_nat_rules().await?;
        let rule_to_edit = actual_rules
            .iter()
            .find(|rule| rule.id == rule_id)
            .ok_or_else(|| anyhow!("No rule with id {rule_id}"))?;
        let mut parameters: SetPortFowardingParams = rule_to_edit.into();
        transform_rule(&mut parameters);
        let result = self
            .exec(SysbusRequest::Firewall(FirewallMethod::SetPortForwarding {
                parameters,
            }))
            .await?;
        self.exec(SysbusRequest::Firewall(FirewallMethod::Commit {
            parameters: NoParameters {},
        }))
        .await?;
        Ok(result)
    }

    pub async fn add_nat_rule(&self, rule: SetPortFowardingParams) -> Result<Value> {
        let result = self
            .exec(SysbusRequest::Firewall(FirewallMethod::SetPortForwarding {
                parameters: rule,
            }))
            .await?;
        Ok(result)
    }

    pub async fn enable_nat_rule(&self, rule_id: String) -> Result<Value> {
        self.update_nat_rule(rule_id, |params| params.enable = true)
            .await
    }

    pub async fn disable_nat_rule(&self, rule_id: String) -> Result<Value> {
        self.update_nat_rule(rule_id, |params| params.enable = false)
            .await
    }

    pub async fn remove_nat_rule(&self, rule_id: String) -> Result<Value> {
        let actual_rules = self.structured_nat_rules().await?;
        let rule_to_delete = actual_rules
            .iter()
            .find(|rule| rule.id == rule_id)
            .ok_or_else(|| anyhow!("No rule with id {rule_id}"))?;
        let result = self
            .exec(SysbusRequest::Firewall(
                FirewallMethod::DeletePortForwarding {
                    parameters: rule_to_delete.into(),
                },
            ))
            .await?;
        self.exec(SysbusRequest::Firewall(FirewallMethod::Commit {
            parameters: NoParameters {},
        }))
        .await?;
        Ok(result)
    }
}

#[derive(Serialize)]
pub(super) struct GenericRequest<'a> {
    service: &'a str,
    method: &'a str,
    parameters: HashMap<&'a str, &'a str>,
}

#[derive(Deserialize)]
struct GenericResponse<S, D> {
    #[expect(unused)]
    status: S,
    data: D,
}

#[derive(Serialize)]
#[serde(tag = "service")]
enum SysbusRequest {
    #[serde(rename = "sah.Device.Information")]
    SahDeviceInformation(SahMethod),
    Firewall(FirewallMethod),
}

#[derive(Serialize)]
#[serde(tag = "method")]
enum SahMethod {
    #[serde(rename = "createContext")]
    CreateContext { parameters: LoginParameters },
    #[serde(rename = "releaseContext")]
    ReleaseContext { parameters: LogoutParameters },
}

#[derive(Serialize)]
struct LoginParameters {
    #[serde(rename = "applicationName")]
    application_name: String,
    username: String,
    password: String,
}

type LoginResponse = GenericResponse<i64, LoginContext>;

#[derive(Serialize)]
struct LogoutParameters {
    application_name: String,
}

impl Default for LogoutParameters {
    fn default() -> Self {
        Self {
            application_name: APPLICATION_NAME.to_string(),
        }
    }
}

#[derive(Deserialize)]
struct LogoutResponse {
    status: i64,
}

#[derive(Deserialize)]
#[expect(unused)]
struct LoginContext {
    #[serde(rename = "contextID")]
    context_id: String,
    groups: String,
    username: String,
}

#[derive(Serialize)]
#[serde(tag = "method")]
enum FirewallMethod {
    #[serde(rename = "getPortForwarding")]
    GetPortForwarding { parameters: NoParameters },
    #[serde(rename = "setPortForwarding")]
    SetPortForwarding { parameters: SetPortFowardingParams },
    #[serde(rename = "deletePortForwarding")]
    DeletePortForwarding {
        parameters: DeletePortForwardingParams,
    },
    #[serde(rename = "commit")]
    Commit { parameters: NoParameters },
}

#[derive(Serialize)]
struct NoParameters {}

#[derive(Serialize)]
pub struct SetPortFowardingParams {
    id: String,

    origin: String,

    description: String,

    #[serde(rename = "sourceInterface")]
    source_interface: String,

    protocol: Protocol,

    #[serde(rename = "externalPort")]
    external_port: String,

    #[serde(rename = "internalPort")]
    internal_port: String,

    #[serde(rename = "destinationIPAddress")]
    destination_ip_address: String,

    #[serde(rename = "destinationMACAddress")]
    destination_mac_address: String,

    enable: bool,

    persistent: bool,
}

impl SetPortFowardingParams {
    pub fn new(
        id: String,
        description: String,
        protocol: Protocol,
        external_port: String,
        internal_port: String,
        destination_ip_address: String,
    ) -> Self {
        SetPortFowardingParams {
            id,
            description,
            protocol: protocol,
            external_port,
            internal_port,
            destination_ip_address,
            ..Default::default()
        }
    }
}

impl Default for SetPortFowardingParams {
    fn default() -> Self {
        Self {
            id: Default::default(),
            origin: "webui".to_string(),
            description: Default::default(),
            source_interface: "data".to_string(),
            protocol: Protocol::TCP,
            external_port: Default::default(),
            internal_port: Default::default(),
            destination_ip_address: Default::default(),
            destination_mac_address: Default::default(),
            enable: true,
            persistent: true,
        }
    }
}

impl From<&NatRuleView> for SetPortFowardingParams {
    fn from(rule: &NatRuleView) -> Self {
        SetPortFowardingParams {
            id: rule.id.clone(),
            origin: rule.origin.clone(),
            description: rule.description.clone(),
            source_interface: rule.source_interface.clone(),
            protocol: rule.protocol.clone(),
            external_port: rule.external_port.clone(),
            internal_port: rule.internal_port.clone(),
            destination_ip_address: rule.destination_ip_address.clone(),
            destination_mac_address: rule.destination_mac_address.clone(),
            enable: rule.enable,
            persistent: true,
        }
    }
}
#[derive(Serialize)]
struct DeletePortForwardingParams {
    id: String,

    origin: String,

    #[serde(rename = "destinationIPAddress")]
    destination_ip_address: String,
}

impl From<&NatRuleView> for DeletePortForwardingParams {
    fn from(rule: &NatRuleView) -> Self {
        DeletePortForwardingParams {
            id: rule.id.clone(),
            origin: rule.origin.clone(),
            destination_ip_address: rule.destination_ip_address.clone(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub enum Protocol {
    #[serde(rename = "6")]
    TCP,
    #[serde(rename = "17")]
    UDP,
    #[serde(rename = "6,17")]
    ALL,
}

#[derive(Deserialize)]
#[expect(unused)]
pub struct NatRuleView {
    #[serde(rename = "Id")]
    id: String,

    #[serde(rename = "Origin")]
    origin: String,

    #[serde(rename = "Description")]
    description: String,

    #[serde(rename = "Status")]
    status: RuleStatus,

    #[serde(rename = "SourceInterface")]
    source_interface: String,

    #[serde(rename = "Protocol")]
    protocol: Protocol,

    #[serde(rename = "ExternalPort")]
    external_port: String,

    #[serde(rename = "InternalPort")]
    internal_port: String,

    #[serde(rename = "SourcePrefix")]
    source_prefix: String,

    #[serde(rename = "DestinationIPAddress")]
    destination_ip_address: String,

    #[serde(rename = "DestinationMACAddress")]
    destination_mac_address: String,

    #[serde(rename = "LeaseDuration")]
    lease_duration: i64,

    #[serde(rename = "HairpinNAT")]
    hairpin_nat: bool,

    #[serde(rename = "SymmetricSNAT")]
    symmetric_snat: bool,

    #[serde(rename = "UPnPV1Compat")]
    upnp_v1_compat: bool,

    #[serde(rename = "Enable")]
    enable: bool,
}

#[derive(Serialize, Deserialize)]
enum RuleStatus {
    Enabled,
    Disabled,
}
