use anyhow::Result;
use axum::{
    Router,
    extract::{Json, Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put},
};
use log::{error, info};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;

use crate::core::engine::Engine;
use crate::core::rules::{Action, Direction, Rule};

/// REST service
#[derive(Clone)]
pub struct RestService {
    /// The firewall engine
    engine: Engine,
}

/// API error response
#[derive(Debug, Serialize)]
struct ErrorResponse {
    /// Error message
    message: String,
}

/// Rule request
#[derive(Debug, Deserialize)]
struct RuleRequest {
    /// Rule name
    name: String,

    /// Rule description
    description: Option<String>,

    /// Rule direction
    direction: String,

    /// Source IP address or network
    source: Option<String>,

    /// Destination IP address or network
    destination: Option<String>,

    /// Source port or port range
    source_port: Option<String>,

    /// Destination port or port range
    destination_port: Option<String>,

    /// Protocol (tcp, udp, icmp, etc.)
    protocol: Option<String>,

    /// Rule action
    action: String,

    /// Whether the rule is enabled
    enabled: Option<bool>,

    /// Rule priority
    priority: Option<i32>,
}

impl RestService {
    /// Create a new REST service
    pub fn new(engine: Engine) -> Self {
        Self { engine }
    }

    /// Run the service
    pub async fn run(self) -> Result<()> {
        let config = self.engine.get_config();

        if !config.services.rest.enabled {
            info!("REST API service is disabled");
            return Ok(());
        }

        let bind_address = &config.services.rest.bind_address;
        let port = config.services.rest.port;

        let addr = format!("{}:{}", bind_address, port)
            .parse::<SocketAddr>()
            .unwrap();

        info!("Starting REST API service on {}", addr);

        let app = Router::new()
            .route("/api/rules", get(Self::list_rules))
            .route("/api/rules", post(Self::add_rule))
            .route("/api/rules", delete(Self::reset_rules))
            .route("/api/rules/{id}", get(Self::get_rule))
            .route("/api/rules/{id}", put(Self::update_rule))
            .route("/api/rules/{id}", delete(Self::delete_rule))
            .layer(TraceLayer::new_for_http())
            .with_state(Arc::new(self.engine));

        let listener = TcpListener::bind(&addr).await.unwrap();
        axum::serve(listener, app).await.unwrap();

        Ok(())
    }

    /// List all rules
    async fn list_rules(State(engine): State<Arc<Engine>>) -> impl IntoResponse {
        match engine.list_rules() {
            Ok(rules) => (StatusCode::OK, Json(rules)).into_response(),
            Err(e) => {
                error!("Failed to list rules: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        message: e.to_string(),
                    }),
                )
                    .into_response()
            }
        }
    }

    /// Delete rules
    async fn reset_rules(State(engine): State<Arc<Engine>>) -> impl IntoResponse {
        match engine.reset_rules() {
            Ok(_) => (StatusCode::OK, Json(json!({"success": true}))).into_response(),
            Err(e) => {
                error!("Failed to reset rules: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        message: e.to_string(),
                    }),
                )
                    .into_response()
            }
        }
    }

    /// Add a rule
    async fn add_rule(
        State(engine): State<Arc<Engine>>,
        Json(rule_req): Json<RuleRequest>,
    ) -> impl IntoResponse {
        // Parse direction
        let direction = match rule_req.direction.to_lowercase().as_str() {
            "input" => Direction::Input,
            "output" => Direction::Output,
            "forward" => Direction::Forward,
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        message: format!("Invalid direction: {}", rule_req.direction),
                    }),
                )
                    .into_response();
            }
        };

        // Parse action
        let action = match rule_req.action.to_lowercase().as_str() {
            "accept" => Action::Accept,
            "drop" => Action::Drop,
            "reject" => Action::Reject,
            "log" => Action::Log,
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        message: format!("Invalid action: {}", rule_req.action),
                    }),
                )
                    .into_response();
            }
        };

        // Create the rule
        let mut rule = Rule::new(
            rule_req.name,
            direction,
            action,
            rule_req.priority.unwrap_or(0),
        );

        rule.description = rule_req.description;
        rule.source = rule_req.source;
        rule.destination = rule_req.destination;
        rule.source_port = rule_req.source_port;
        rule.destination_port = rule_req.destination_port;
        rule.protocol = rule_req.protocol;
        rule.enabled = rule_req.enabled.unwrap_or(true);

        // Add the rule
        match engine.add_rule(rule) {
            Ok(rule_id) => (StatusCode::CREATED, Json(json!({"id": rule_id}))).into_response(),
            Err(e) => {
                error!("Failed to add rule: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        message: e.to_string(),
                    }),
                )
                    .into_response()
            }
        }
    }

    /// Get a rule
    async fn get_rule(
        State(engine): State<Arc<Engine>>,
        Path(rule_id): Path<String>,
    ) -> impl IntoResponse {
        match engine.get_rule(&rule_id) {
            Ok(rule) => (StatusCode::OK, Json(rule)).into_response(),
            Err(e) => {
                error!("Failed to get rule {}: {}", rule_id, e);
                (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        message: e.to_string(),
                    }),
                )
                    .into_response()
            }
        }
    }

    /// Update a rule
    async fn update_rule(
        State(engine): State<Arc<Engine>>,
        Path(rule_id): Path<String>,
        Json(rule_req): Json<RuleRequest>,
    ) -> impl IntoResponse {
        // Get the existing rule
        let rule = match engine.get_rule(&rule_id) {
            Ok(rule) => rule,
            Err(e) => {
                error!("Failed to get rule {}: {}", rule_id, e);
                return (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        message: e.to_string(),
                    }),
                )
                    .into_response();
            }
        };

        // Parse direction
        let direction = match rule_req.direction.to_lowercase().as_str() {
            "input" => Direction::Input,
            "output" => Direction::Output,
            "forward" => Direction::Forward,
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        message: format!("Invalid direction: {}", rule_req.direction),
                    }),
                )
                    .into_response();
            }
        };

        // Parse action
        let action = match rule_req.action.to_lowercase().as_str() {
            "accept" => Action::Accept,
            "drop" => Action::Drop,
            "reject" => Action::Reject,
            "log" => Action::Log,
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        message: format!("Invalid action: {}", rule_req.action),
                    }),
                )
                    .into_response();
            }
        };

        // Update the rule
        let mut updated_rule = rule.clone();
        updated_rule.name = rule_req.name;
        updated_rule.description = rule_req.description;
        updated_rule.direction = direction;
        updated_rule.source = rule_req.source;
        updated_rule.destination = rule_req.destination;
        updated_rule.source_port = rule_req.source_port;
        updated_rule.destination_port = rule_req.destination_port;
        updated_rule.protocol = rule_req.protocol;
        updated_rule.action = action;
        updated_rule.enabled = rule_req.enabled.unwrap_or(true);
        updated_rule.priority = rule_req.priority.unwrap_or(0);

        // Apply the update
        match engine.update_rule(updated_rule) {
            Ok(_) => (StatusCode::OK, Json(json!({"success": true}))).into_response(),
            Err(e) => {
                error!("Failed to update rule {}: {}", rule_id, e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        message: e.to_string(),
                    }),
                )
                    .into_response()
            }
        }
    }

    /// Delete a rule
    async fn delete_rule(
        State(engine): State<Arc<Engine>>,
        Path(rule_id): Path<String>,
    ) -> impl IntoResponse {
        match engine.delete_rule(&rule_id) {
            Ok(_) => (StatusCode::OK, Json(json!({"success": true}))).into_response(),
            Err(e) => {
                error!("Failed to delete rule {}: {}", rule_id, e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        message: e.to_string(),
                    }),
                )
                    .into_response()
            }
        }
    }
}
