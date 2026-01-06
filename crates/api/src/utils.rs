use std::sync::Arc;

use axum::{body::Body, extract::Request, http::Response, middleware::Next};
use tokio::signal;
use tracing::info;

use crate::AppError;

// Future này sẽ chỉ hoàn thành khi nhận được tín hiệu Ctrl+C
pub async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Signal received, starting graceful shutdown...");
}


// Our middleware is responsible for logging error details internally
pub async fn log_app_errors(request: Request, next: Next) -> Response<Body> {
    let response = next.run(request).await;
    // If the response contains an AppError Extension, log it.
    if let Some(err) = response.extensions().get::<Arc<AppError>>() {
        tracing::error!(?err, "an unexpected error occurred inside a handler");
    }
    response
}