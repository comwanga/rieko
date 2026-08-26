use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;

use crate::error::BtcPayError;
use crate::models::{
    GreenfieldInvoice, GreenfieldLightningBalance, GreenfieldLightningChannel,
    GreenfieldLightningInfo, GreenfieldOnChainWallet, GreenfieldServerInfo,
};

/// Asynchronous REST client for BTCPay Server Greenfield API.
#[derive(Debug, Clone)]
pub struct BtcPayGreenfieldClient {
    base_url: String,
    api_key: String,
    http: Client,
}

impl BtcPayGreenfieldClient {
    /// Creates a new Greenfield API client.
    ///
    /// `base_url` e.g. `https://btcpay.example.com`
    /// `api_key` Greenfield API Key with Store permissions.
    pub fn new(
        base_url: impl Into<String>,
        api_key: impl Into<String>,
    ) -> Result<Self, BtcPayError> {
        Self::new_with_timeout(base_url, api_key, Duration::from_secs(10))
    }

    /// Creates a Greenfield client with a bounded per-request timeout.
    pub fn new_with_timeout(
        base_url: impl Into<String>,
        api_key: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self, BtcPayError> {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        let api_key = api_key.into().trim().to_string();

        if base_url.is_empty() {
            return Err(BtcPayError::Config(
                "BTCPay Server base URL cannot be empty".into(),
            ));
        }
        if api_key.is_empty() {
            return Err(BtcPayError::Config(
                "BTCPay Server API key cannot be empty".into(),
            ));
        }
        if timeout.is_zero() {
            return Err(BtcPayError::Config(
                "BTCPay Server request timeout must be greater than zero".into(),
            ));
        }

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let mut auth_val = HeaderValue::from_str(&format!("token {api_key}"))
            .map_err(|_| BtcPayError::Config("Invalid characters in API key".into()))?;
        auth_val.set_sensitive(true);
        headers.insert(AUTHORIZATION, auth_val);

        let http = Client::builder()
            .default_headers(headers)
            .timeout(timeout)
            .connect_timeout(timeout.min(Duration::from_secs(5)))
            .build()
            .map_err(BtcPayError::Http)?;

        Ok(Self {
            base_url,
            api_key,
            http,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn api_key(&self) -> &str {
        &self.api_key
    }

    /// Fetches server status and version from `GET /api/v1/server/info`.
    pub async fn get_server_info(&self) -> Result<GreenfieldServerInfo, BtcPayError> {
        let url = format!("{}/api/v1/server/info", self.base_url);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(BtcPayError::Http)?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(BtcPayError::Api {
                status: status.as_u16(),
                message: body,
            });
        }
        let info = resp
            .json::<GreenfieldServerInfo>()
            .await
            .map_err(BtcPayError::Http)?;
        Ok(info)
    }

    /// Fetches lightning node info for a store from `GET /api/v1/stores/{storeId}/lightning/{cryptoCode}/info`.
    pub async fn get_lightning_info(
        &self,
        store_id: &str,
        crypto_code: &str,
    ) -> Result<GreenfieldLightningInfo, BtcPayError> {
        let url = format!(
            "{}/api/v1/stores/{}/lightning/{}/info",
            self.base_url, store_id, crypto_code
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(BtcPayError::Http)?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(BtcPayError::Api {
                status: status.as_u16(),
                message: body,
            });
        }
        let info = resp
            .json::<GreenfieldLightningInfo>()
            .await
            .map_err(BtcPayError::Http)?;
        Ok(info)
    }

    /// Fetches lightning node balance for a store from `GET /api/v1/stores/{storeId}/lightning/{cryptoCode}/balance`.
    pub async fn get_lightning_balance(
        &self,
        store_id: &str,
        crypto_code: &str,
    ) -> Result<GreenfieldLightningBalance, BtcPayError> {
        let url = format!(
            "{}/api/v1/stores/{}/lightning/{}/balance",
            self.base_url, store_id, crypto_code
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(BtcPayError::Http)?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(BtcPayError::Api {
                status: status.as_u16(),
                message: body,
            });
        }
        let balance = resp
            .json::<GreenfieldLightningBalance>()
            .await
            .map_err(BtcPayError::Http)?;
        Ok(balance)
    }

    /// Fetches active/inactive channels for a store from `GET /api/v1/stores/{storeId}/lightning/{cryptoCode}/channels`.
    pub async fn get_lightning_channels(
        &self,
        store_id: &str,
        crypto_code: &str,
    ) -> Result<Vec<GreenfieldLightningChannel>, BtcPayError> {
        let url = format!(
            "{}/api/v1/stores/{}/lightning/{}/channels",
            self.base_url, store_id, crypto_code
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(BtcPayError::Http)?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(BtcPayError::Api {
                status: status.as_u16(),
                message: body,
            });
        }
        let channels = resp
            .json::<Vec<GreenfieldLightningChannel>>()
            .await
            .map_err(BtcPayError::Http)?;
        Ok(channels)
    }

    /// Fetches on-chain wallet summary for a store from `GET /api/v1/stores/{storeId}/onchain/{cryptoCode}/wallet`.
    pub async fn get_onchain_wallet(
        &self,
        store_id: &str,
        crypto_code: &str,
    ) -> Result<GreenfieldOnChainWallet, BtcPayError> {
        let url = format!(
            "{}/api/v1/stores/{}/onchain/{}/wallet",
            self.base_url, store_id, crypto_code
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(BtcPayError::Http)?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(BtcPayError::Api {
                status: status.as_u16(),
                message: body,
            });
        }
        let wallet = resp
            .json::<GreenfieldOnChainWallet>()
            .await
            .map_err(BtcPayError::Http)?;
        Ok(wallet)
    }

    /// Fetches recent invoices from `GET /api/v1/stores/{storeId}/invoices`.
    pub async fn get_invoices(
        &self,
        store_id: &str,
        status_filter: Option<&str>,
    ) -> Result<Vec<GreenfieldInvoice>, BtcPayError> {
        let mut url = format!("{}/api/v1/stores/{}/invoices", self.base_url, store_id);
        if let Some(status) = status_filter {
            url.push_str(&format!("?status={status}"));
        }
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(BtcPayError::Http)?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(BtcPayError::Api {
                status: status.as_u16(),
                message: body,
            });
        }
        let invoices = resp
            .json::<Vec<GreenfieldInvoice>>()
            .await
            .map_err(BtcPayError::Http)?;
        Ok(invoices)
    }
}
