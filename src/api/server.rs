use tower_http::{cors::CorsLayer, trace::TraceLayer};

use crate::api::state::AppState;
use crate::config::Config;

pub async fn run(config: Config) -> anyhow::Result<()> {
    let state = AppState::new(config.clone())?;
    let app = crate::api::routes::create_router(state);

    let addr = format!("{}:{}", config.server.host, config.server.port);
    tracing::info!("Forge starting on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
