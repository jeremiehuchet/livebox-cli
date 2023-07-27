use std::{collections::HashMap, sync::Arc};

use anyhow::{anyhow, Result};

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
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self {
            base_url_ws: LIVEBOX_BASE_URL.to_string(),
            credentials: None,
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

    pub async fn build(self) -> Result<Client> {
        let (username, password) = self.credentials.ok_or(anyhow!("missing credentials"))?;
        Client::login(self.base_url_ws, username, password).await
    }
}

pub(super) struct Client {
    http_client: ReqwestClient,
    base_url_ws: String,
    context_id: String,
}

impl Client {
    async fn login(base_url: String, username: String, password: String) -> Result<Self> {
        let cookie_store = Arc::new(Jar::default());
        let http_client = ReqwestClientBuilder::default()
            .cookie_provider(cookie_store.clone())
            .build()
            .expect("error building HTTP client");

        let response = http_client
            .post(&base_url)
            .header(CONTENT_TYPE, APPLICATION_SAH_WS_CALL)
            .header(AUTHORIZATION, X_SAH_LOGIN)
            .json(&LoginRequest::new(username, password))
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
                HeaderValue::from_str(&context_id).unwrap(),
            ),
        ]);

        Ok(Client {
            http_client: ReqwestClientBuilder::default()
                .cookie_provider(cookie_store)
                .default_headers(context_headers)
                .build()
                .expect("error building HTTP client"),
            base_url_ws: base_url,
            context_id,
        })
    }

    pub async fn logout(&self) -> Result<()> {
        let req = GenericRequest {
            service: "sah.Device.Information",
            method: "releaseContext",
            parameters: HashMap::from([("application_name", APPLICATION_NAME)]),
        };
        let response = self
            .http_client
            .post(&self.base_url_ws)
            .json(&req)
            .header(AUTHORIZATION, format!("{X_SAH_LOGOUT} {}", self.context_id))
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await?;
        if status.as_u16() != 401 {
            warn!("Logout error: {status}\n{body}")
        }
        let response = serde_json::from_str::<GenericResponse>(&body)?;
        if response.status != 1 && response.data == None {
            warn!("Logout error: {body}")
        }
        Ok(())
    }

    pub async fn execute(&self, service: String, method: String) -> Result<Option<Value>> {
        let body = GenericRequest::new(&service, &method);
        let response = self
            .http_client
            .post(&self.base_url_ws)
            .header(CONTENT_TYPE, APPLICATION_SAH_WS_CALL)
            .json(&body)
            .send()
            .await?;

        let status = response.status();
        let body = response.text().await?;
        debug!("Response: {status}\n{body}");
        if !status.is_success() {
            return Err(
                anyhow!("Execution failed: {status}").context(format!("Response body: {body}"))
            );
        }

        Ok(serde_json::from_str::<GenericResponse>(&body)?
            .data)
    }
}

#[derive(Serialize)]
struct GenericRequest<'a> {
    service: &'a str,
    method: &'a str,
    parameters: HashMap<&'a str, &'a str>,
}

impl<'a> GenericRequest<'a> {
    fn new(service: &'a str, method: &'a str) -> Self {
        GenericRequest {
            service,
            method,
            parameters: HashMap::new(),
        }
    }
}

#[derive(Deserialize)]
struct GenericResponse {
    status: Value,
    data: Option<Value>,
}

#[derive(Serialize)]
struct LoginRequest {
    service: String,
    method: String,
    parameters: LoginRequestParameters,
}

#[derive(Serialize)]
struct LoginRequestParameters {
    #[serde(rename = "applicationName")]
    application_name: String,
    username: String,
    password: String,
}

impl LoginRequest {
    fn new(username: String, password: String) -> Self {
        LoginRequest {
            service: "sah.Device.Information".to_string(),
            method: "createContext".to_string(),
            parameters: LoginRequestParameters {
                application_name: APPLICATION_NAME.to_string(),
                username,
                password,
            },
        }
    }
}

#[derive(Deserialize)]
struct LoginResponse {
    data: LoginContext,
    status: i64,
}

#[derive(Deserialize)]
struct LoginContext {
    #[serde(rename = "contextID")]
    context_id: String,
    groups: String,
    username: String,
}
