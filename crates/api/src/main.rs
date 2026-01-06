mod config;
mod service;
mod utils;
use crate::config::{configure_cors, HttpConfig, HttpCorsConfig, HttpTlsConfig};
use crate::service::address::*;
use crate::utils::{log_app_errors, shutdown_signal};
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, MatchedPath, Request, State};
use axum::handler::Handler;
use axum::middleware::from_fn;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use bitcoin_scan::db::{Database, ReadOnlyDatabase, ReadableDatabase, DEFAULT_DB_PATH};
use bitcoin_scan::logger::init_logger;
use serde::Serialize;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    signal,
};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::{error, info};
use tracing_subscriber::prelude::*;
// Make our own error that wraps `anyhow::Error`.

#[derive(FromRequest)]
#[from_request(via(axum::Json), rejection(AppError))]
struct AppJson<T>(T);

// The kinds of errors we can hit in our application.
#[derive(Debug)]
enum AppError {
    // The request body contained invalid JSON
    JsonRejection(JsonRejection),
}
impl<T> IntoResponse for AppJson<T>
where
    axum::Json<T>: IntoResponse,
{
    fn into_response(self) -> Response {
        axum::Json(self.0).into_response()
    }
}
// Tell axum how `AppError` should be converted into a response.
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // How we want errors responses to be serialized
        #[derive(Serialize)]
        struct ErrorResponse {
            message: String,
        }

        let (status, message) = match self {
            AppError::JsonRejection(rejection) => {
                // This error is caused by bad user input so don't log it
                (rejection.status(), rejection.body_text())
            }
        };

        (status, AppJson(ErrorResponse { message })).into_response()
    }
}

#[derive(Clone)]
struct AppState {
    db: Arc<Database>,
}
struct ApiServer {
    // You can add fields here if needed, e.g., for database connections
    state: AppState,
    config: HttpConfig,
    router: Router<AppState>,
}
impl ApiServer {
    pub fn new(config: HttpConfig, db: Database) -> Self {
        let state = AppState { db: Arc::new(db) };
        let router = Router::new()
            .route("/health", get(|| async { "OK" }))
            .with_state(state.clone());

        Self {
            router,
            config,
            state,
        }
    }

    pub async fn init(self) {
        let mut app = self.router;

        app = app
            .layer(
                TraceLayer::new_for_http()
                    // Create our own span for the request and include the matched path. The matched
                    // path is useful for figuring out which handler the request was routed to.
                    .make_span_with(|req: &Request| {
                        let method = req.method();
                        let uri = req.uri();

                        // axum automatically adds this extension.
                        let matched_path = req
                            .extensions()
                            .get::<MatchedPath>()
                            .map(|matched_path| matched_path.as_str());

                        tracing::debug_span!("request", %method, %uri, matched_path)
                    })
                    // By default `TraceLayer` will log 5xx responses but we're doing our specific
                    // logging of errors so disable that
                    .on_failure(()),
            )
            .layer(from_fn(log_app_errors));

        // Configure CORS if enabled
        if self.config.cors.enabled {
            let cors_layer = configure_cors(&self.config.cors);
            app = app.layer(cors_layer);
        }

        let listener = TcpListener::bind(&self.config.address)
            .await
            .expect("Failed to bind to address");

        info!("API Server listening on http://{}", self.config.address);

        axum::serve(listener, app.with_state(self.state))
            .with_graceful_shutdown(shutdown_signal()) // Hàm chờ tín hiệu chuẩn
            .await
            .unwrap();
    }
    // Generic Add Route: Chấp nhận bất kỳ Handler nào tương thích với AppState
    pub fn add_route<H, T>(&mut self, path: &str, handler: H)
    where
        // H: Handler<Args, State>
        H: Handler<T, AppState> + Clone + Send + 'static,
        T: 'static,
    {
        // Router của axum là immutable (mỗi lần gọi .route trả về instance mới)
        // Vì vậy ta clone router cũ (rất nhẹ vì nó chỉ chứa Arc), thêm route, rồi gán lại
        self.router = self.router.clone().route(
            &format!("{}/{}/{}", self.config.path, self.config.version, path),
            get(handler),
        );
        info!(
            "Route added: {}/{}/{}",
            self.config.path, self.config.version, path
        );
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 8)]
async fn main() {
    init_logger();
    let config = HttpConfig {
        address: "localhost:8082".to_owned(),
        path: "/api".to_owned(),
        cors: HttpCorsConfig::default(),
        tls: HttpTlsConfig::default(),
        version: "1.0".to_owned(),
    };

    let db = ReadOnlyDatabase::open(&DEFAULT_DB_PATH, true).expect("Cannot open DB");
    info!("Database opened successfully");
    let mut server = ApiServer::new(config, db);

    server.add_route("address/count", get(count_addresses));
    //use query parameters for pagination
    server.add_route("address/top", get(top_addresses));
    server.add_route("address/last", get(last_addresses));
    server.add_route("address/{address}", get(address_info));

    server.init().await;

    info!("API Server stopped successfully");
}
