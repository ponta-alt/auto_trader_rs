use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context;
use axum::{
    extract::State,
    http::{HeaderMap, Method, StatusCode},
    routing::get,
    Json, Router,
};
use reqwest::header::{HeaderMap as ReqHeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tower_http::{
    cors::{Any, CorsLayer},
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

// =====================
// 型定義（kabu ステ API 準拠）
// =====================

#[derive(Debug, Deserialize)]
struct TokenRes {
    #[serde(rename = "Token")]
    token: String,
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

// kabu が配列ではなく {"Positions":[...]} で返す場合に備えたラッパ
#[derive(Debug, Deserialize)]
struct PositionsWrap {
    #[serde(rename = "Positions")]
    items: Vec<Position>,
}

// =====================
// KabuClient（タイムアウト等の安定化含む）
// =====================

#[derive(Debug, Clone)]
pub struct KabuClient {
    http: reqwest::Client,
    base: String,
}

impl KabuClient {
    pub fn new(base: String) -> anyhow::Result<Self> {
        let mut default_headers = ReqHeaderMap::new();
        default_headers.insert(ACCEPT, HeaderValue::from_static("application/json"));

        let http = reqwest::Client::builder()
            .default_headers(default_headers)
            .timeout(Duration::from_secs(8))
            .tcp_keepalive(Some(Duration::from_secs(30)))
            .pool_idle_timeout(Some(Duration::from_secs(90)))
            .build()?;

        Ok(Self { http, base })
    }

    pub async fn get_token(&self, password: &str) -> anyhow::Result<String> {
        // localhost/127.0.0.1 両対応で試行
        let bases = if self.base.contains("localhost") {
            vec![self.base.clone(), self.base.replace("localhost", "127.0.0.1")]
        } else {
            vec![self.base.clone()]
        };

        for (i, base) in bases.iter().enumerate() {
            let url = format!("{}/token", base);
            // パスワードの生値は出さない（長さだけ）
            info!("POST {} (APIPassword len={}) [try {}/{}]", url, password.len(), i + 1, bases.len());

            let body = serde_json::json!({ "APIPassword": password });
            let res = self.http.post(&url)
                .header(CONTENT_TYPE, "application/json")
                .json(&body)
                .send()
                .await
                .with_context(|| format!("POST {} failed to send", url))?;

            let status = res.status();
            let text = res.text().await.unwrap_or_else(|_| "<body read error>".into());

            if !status.is_success() {
                warn!("token request failed: {} - {}", status, text);
            } else {
                let token = serde_json::from_str::<TokenRes>(&text)
                    .with_context(|| format!("parse token json failed: {}", text))?
                    .token;
                return Ok(token);
            }
        }

        anyhow::bail!("token request failed on all tried bases");
    }

    pub async fn get_wallet_cash(&self, token: &str) -> anyhow::Result<Wallet> {
        let url = format!("{}/wallet/cash", self.base);
        let res = self.http
            .get(&url)
            .header("X-API-KEY", token)
            .send()
            .await
            .with_context(|| format!("GET {} failed to send", url))?;

        let status = res.status();
        let text = res.text().await.unwrap_or_else(|_| "<body read error>".into());
        if !status.is_success() {
            anyhow::bail!("/wallet/cash failed: {} - {}", status, text);
        }
        let wallet = serde_json::from_str::<Wallet>(&text)
            .with_context(|| format!("parse wallet json failed: {}", text))?;
        Ok(wallet)
    }
    pub async fn get_positions(&self, token: &str) -> anyhow::Result<Vec<Position>> {
        use serde::Deserialize;

        // 1) 上流呼び出し
        let url = format!("{}/positions?product=0", self.base); // 全件
        let res = self.http
            .get(&url)
            .header("X-API-KEY", token)
            .send()
            .await
            .with_context(|| format!("GET {} failed to send", url))?;

        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        info!("GET /positions upstream={} body_len={}", status, text.len());

        if !status.is_success() {
            // 上流が 4xx/5xx のときはその本文を返す
            anyhow::bail!("/positions upstream failed: {} - {}", status, text);
        }

        // 2) 形状ゆらぎに全部対応（配列／ラップ／エラーオブジェクト）
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum PositionsApi {
            Array(Vec<Position>),
            Wrap { #[serde(rename = "Positions")] Positions: Vec<Position> },
            Error { Code: i64, Message: String },
        }

        let parsed: PositionsApi = serde_json::from_str(&text)
            .with_context(|| format!("parse positions json failed: {}", text))?;

        let items = match parsed {
            PositionsApi::Array(v) => v,
            PositionsApi::Wrap { Positions } => Positions,
            PositionsApi::Error { Code, Message } => {
                // kabu が 200 でエラーJSONを返すケースを人間にわかる形で返す
                anyhow::bail!("kabu positions error: {} - {}", Code, Message);
            }
        };

        Ok(items)
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

async fn handle_wallet(State(gs): State<Arc<AppState>>) -> Result<Json<Wallet>, (StatusCode, String)> {
    gs.kabu.get_wallet_cash(&gs.token).await.map(Json).map_err(internal_err)
}

async fn handle_positions(State(gs): State<Arc<AppState>>) -> Result<Json<Vec<Position>>, (StatusCode, String)> {
    gs.kabu.get_positions(&gs.token).await.map(Json).map_err(internal_err)
}

async fn handle_health() -> &'static str {
    "ok"
}

fn internal_err<E: ToString>(e: E) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

// =====================
// ルータ構築
// =====================

fn build_router(state: Arc<AppState>) -> Router {
    // 静的配信（/ → web/index.html）
    let assets = ServeDir::new("web").fallback(ServeFile::new("web/index.html"));

    // CORS（将来フロント別ポートでも困らない設定）
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_origin(Any)
        .allow_headers(Any);

    Router::new()
        .route("/healthz", get(handle_health))
        .route("/api/wallet", get(handle_wallet))
        .route("/api/positions", get(handle_positions))
        .with_state(state)
        .fallback_service(assets)
        .layer(TraceLayer::new_for_http())
        .layer(cors)
}

// =====================
// 公開エントリポイント（main から呼ぶ）
// =====================

pub async fn run() -> anyhow::Result<()> {
    // ログ初期化（RUST_LOG 未設定なら info を既定に）
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into());
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(filter))
        .with_target(false)
        .init();

    // ---- 設定 ----
    let base = std::env::var("KABU_BASE").unwrap_or_else(|_| "http://localhost:18080/kabusapi".into());
    let pass = std::env::var("KABU_API_PASSWORD").unwrap_or_else(|_| "password".into());
    info!("using KABU_BASE={}, PASS.len={}", base, pass.len()); // 値は出さない

    // ---- 認証 ----
    let kabu = KabuClient::new(base)?;
    let token = kabu.get_token(&pass).await?;
    info!("Token OK");

    // ---- ルータ ----
    let state = Arc::new(AppState { kabu, token });
    let app = build_router(state);

    // ---- サーバ起動（グレースフル）----
    let addr: SocketAddr = "0.0.0.0:3000".parse().unwrap();
    info!("Listening on http://{addr}");
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            info!("Shutting down...");
        })
        .await?;

    Ok(())
}
