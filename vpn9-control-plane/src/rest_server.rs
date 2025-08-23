use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::{fs, net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use tracing::{error, info};

#[derive(Debug, Clone)]
pub struct RestServerConfig {
    pub listen_addr: SocketAddr,
    pub jwt_public_key_path: String,
}

#[derive(Clone)]
struct AppState {
    jwt_public_key: DecodingKey,
    wireguard_manager: Arc<RwLock<crate::wireguard_manager::WireGuardManager>>,
}

#[derive(Debug, Deserialize)]
struct RegisterRequest {
    pubkey: String,
    token: String,
}

#[derive(Debug, Serialize)]
struct RegisterResponse {
    success: bool,
    message: String,
}

#[derive(Debug, Deserialize)]
struct Claims {
    sub: String,
    exp: i64,
    iat: i64,
}

pub struct RestServer {
    config: RestServerConfig,
    wireguard_manager: Arc<RwLock<crate::wireguard_manager::WireGuardManager>>,
}

impl RestServer {
    pub fn new(
        config: RestServerConfig,
        wireguard_manager: Arc<RwLock<crate::wireguard_manager::WireGuardManager>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            config,
            wireguard_manager,
        })
    }

    pub async fn run(self) -> Result<(), Box<dyn std::error::Error>> {
        let jwt_public_key_pem = fs::read_to_string(&self.config.jwt_public_key_path)
            .map_err(|e| format!("Failed to read JWT public key: {}", e))?;

        let jwt_public_key = DecodingKey::from_rsa_pem(jwt_public_key_pem.as_bytes())
            .map_err(|e| format!("Failed to parse JWT public key: {}", e))?;

        let state = AppState {
            jwt_public_key,
            wireguard_manager: self.wireguard_manager,
        };

        let app = Router::new()
            .route("/register", post(register_handler))
            .layer(CorsLayer::permissive())
            .with_state(state);

        let listener = tokio::net::TcpListener::bind(self.config.listen_addr).await?;
        info!("REST server listening on {}", self.config.listen_addr);

        axum::serve(listener, app).await?;

        Ok(())
    }
}

async fn register_handler(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> impl IntoResponse {
    let header = match decode_header(&payload.token) {
        Ok(h) => h,
        Err(e) => {
            error!("Failed to decode JWT header: {}", e);
            return (
                StatusCode::UNAUTHORIZED,
                Json(RegisterResponse {
                    success: false,
                    message: "Invalid token format".to_string(),
                }),
            );
        }
    };

    let alg = match header.alg {
        jsonwebtoken::Algorithm::RS256 => Algorithm::RS256,
        jsonwebtoken::Algorithm::RS384 => Algorithm::RS384,
        jsonwebtoken::Algorithm::RS512 => Algorithm::RS512,
        _ => {
            error!("Unsupported JWT algorithm: {:?}", header.alg);
            return (
                StatusCode::UNAUTHORIZED,
                Json(RegisterResponse {
                    success: false,
                    message: "Unsupported token algorithm".to_string(),
                }),
            );
        }
    };

    let mut validation = Validation::new(alg);
    validation.validate_exp = true;

    let token_data = match decode::<Claims>(&payload.token, &state.jwt_public_key, &validation) {
        Ok(data) => data,
        Err(e) => {
            error!("Failed to decode JWT: {}", e);
            return (
                StatusCode::UNAUTHORIZED,
                Json(RegisterResponse {
                    success: false,
                    message: "Invalid or expired token".to_string(),
                }),
            );
        }
    };

    info!("Valid token for subject: {}", token_data.claims.sub);

    let wg_manager = state.wireguard_manager.write().await;
    match wg_manager.add_peer(&payload.pubkey).await {
        Ok(_) => {
            info!("Successfully added peer with pubkey: {}", payload.pubkey);
            (
                StatusCode::OK,
                Json(RegisterResponse {
                    success: true,
                    message: "Peer registered successfully".to_string(),
                }),
            )
        }
        Err(e) => {
            error!("Failed to add peer: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(RegisterResponse {
                    success: false,
                    message: "Failed to register peer".to_string(),
                }),
            )
        }
    }
}