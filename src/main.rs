use std::{net::SocketAddr, sync::Arc};

use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tower_http::services::{ServeDir, ServeFile};
use tracing::info;
use tracing_subscriber::EnvFilter;

// =====================
// kabu ステ API 型
// =====================

#[derive(Debug, Deserialize)]
struct TokenRes {
    #[serde(rename = "Token")]
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Wallet {
    #[serde(rename = "StockAccountWallet")]
    pub stock_account_wallet: Option<f64>,
    #[serde(rename = "AcbStockAccountWallet")]
    pub acb_stock_account_wallet: Option<f64>,
    #[serde(rename = "AuByStockAccountWallet")]
    pub au_by_stock_account_wallet: Option<f64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Position {
    #[serde(rename = "Symbol")]
    pub symbol: Option<String>,
    #[serde(rename = "SymbolName")]
    pub symbol_name: Option<String>,
    #[serde(rename = "LeavesQty")]
    pub leaves_qty: Option<i64>,
    #[serde(rename = "HoldQty")]
    pub hold_qty: Option<i64>,
    #[serde(rename = "Price")]
    pub price: Option<f64>,
    #[serde(rename = "ProfitLoss")]
    pub profit_loss: Option<f64>,
}

// =====================
// KabuClient（本番API呼び）
// =====================

#[derive(Debug, Clone)]
pub struct KabuClient {
    http: reqwest::Client,
    base: String,
}

impl KabuClient {
    pub fn new(base: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            base,
        }
    }

    pub async fn get_token(&self, password: &str) -> anyhow::Result<String> {
        let url = format!("{}/token", self.base);
        let body = serde_json::json!({ "APIPassword": password });

        // リクエスト送信
        let res = self.http.post(&url).json(&body).send().await?;
        let status = res.status();
        let text = res.text().await?;

        // ステータスコードチェック
        if !status.is_success() {
            // kabuステからのエラー内容をそのまま返す
            anyhow::bail!("token request failed: {} - {}", status, text);
        }

        // 成功時は TokenRes にパース
        let token = serde_json::from_str::<TokenRes>(&text)?.token;
        Ok(token)
    }


    pub async fn get_wallet_cash(&self, token: &str) -> anyhow::Result<Wallet> {
        let url = format!("{}/wallet/cash", self.base);
        let resp = self
            .http
            .get(&url)
            .header("X-API-KEY", token)
            .send()
            .await?
            .error_for_status()?
            .json::<Wallet>()
            .await?;
        Ok(resp)
    }

    pub async fn get_positions(&self, token: &str) -> anyhow::Result<Vec<Position>> {
        let url = format!("{}/positions?product=0", self.base);

        let res = self.http.get(&url)
            .header("X-API-KEY", token)
            .send().await?;

        let status = res.status();
        let text = res.text().await?;
        tracing::info!("GET /positions {} body={}", status, text);

        if !status.is_success() {
            anyhow::bail!("/positions failed: {} - {}", status, text);
        }

        // kabu の形に合わせてパース（配列 or ラップ）
        if text.trim_start().starts_with('[') {
            Ok(serde_json::from_str::<Vec<Position>>(&text)?)
        } else {
            #[derive(serde::Deserialize)]
            struct Wrap { #[serde(rename="Positions")] items: Vec<Position> }
            Ok(serde_json::from_str::<Wrap>(&text)?.items)
        }
    }


}

// =====================
// アプリ状態 & ハンドラ
// =====================

#[derive(Clone)]
struct AppState {
    kabu: KabuClient,
    token: String,
}

async fn get_wallet(
    State(gs): State<Arc<AppState>>,
) -> Result<Json<Wallet>, (StatusCode, String)> {
    gs.kabu
        .get_wallet_cash(&gs.token)
        .await
        .map(Json)
        .map_err(internal_err)
}

async fn get_positions(
    State(gs): State<Arc<AppState>>,
) -> Result<Json<Vec<Position>>, (StatusCode, String)> {
    gs.kabu
        .get_positions(&gs.token)
        .await
        .map(Json)
        .map_err(internal_err)
}

fn internal_err<E: ToString>(e: E) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

// =====================
// main
// =====================
fn load_env() { let _ = dotenvy::dotenv(); }

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    load_env();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // ---- 設定 ----
    let base = std::env::var("KABU_BASE")
        .unwrap_or_else(|_| "http://localhost:18080/kabusapi".into());
    let pass = std::env::var("KABU_API_PASSWORD").unwrap_or_else(|_| "password".into());
    println!("KABU_API_PASSWORD = {}", pass);

    // ---- 認証 ----
    let kabu = KabuClient::new(base);
    let token = kabu.get_token(&pass).await?;
    info!("Token OK");

    // ---- 状態 ----
    let state = Arc::new(AppState { kabu, token });

    // ---- 静的配信 ----
    let assets = ServeDir::new("web").fallback(ServeFile::new("web/index.html"));

    // ---- ルータ ----
    let app = Router::new()
        .route("/api/wallet", get(get_wallet))
        .route("/api/positions", get(get_positions))
        .with_state(state)
        .fallback_service(assets);

    // ---- サーバ起動 ----
    let addr: SocketAddr = "0.0.0.0:3000".parse().unwrap();
    info!("Listening on http://{addr}");
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

