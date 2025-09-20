#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // .env 読み込み（IDE/シェル差の吸収）
    let _ = dotenvy::dotenv();
    auto_trader_rs::run().await
}


