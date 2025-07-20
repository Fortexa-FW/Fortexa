use anyhow::Result;
use axum::{
    Router,
    extract::{Json, Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put},
};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tower_http::trace::TraceLayer;

use crate::core::engine::Engine;
use crate::core::rules::{Action, Direction, Rule};
use crate::modules::netshield;

/// REST service
pub struct RestService {
    /// The firewall engine
    engine: Arc<Engine>,
}

/// API error response
#[derive(Debug, Serialize)]
struct ErrorResponse {
    /// Error message
    message: String,
}

#[derive(Debug, Deserialize)]
pub struct NetshieldRuleRequest {
    pub id: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub direction: String,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub protocol: Option<String>,
    pub action: String,
    pub enabled: Option<bool>,
    pub priority: Option<i32>,
    pub parameters: Option<HashMap<String, String>>,
    pub group: Option<String>,
}

impl RestService {
    /// Create a new REST service
    pub fn new(engine: Arc<Engine>) -> Self {
        Self { engine }
    }

    /// Run the service
    pub async fn run(
        self,
        shutdown: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>,
    ) -> Result<()> {
        info!("[RestService] Entered run()");
        let config = self.engine.get_config();

        if !config.services.rest.enabled {
            info!("[RestService] REST API service is disabled");
            return Ok(());
        }

        let bind_address = &config.services.rest.bind_address;
        let port = config.services.rest.port;

        let addr = format!("{}:{}", bind_address, port)
            .parse::<std::net::SocketAddr>()
            .unwrap();

        info!("[RestService] Binding to address: {}", addr);

        let listener = match tokio::net::TcpListener::bind(&addr).await {
            Ok(l) => {
                info!("[RestService] Successfully bound to {}", addr);
                l
            }
            Err(e) => {
                error!("[RestService] Failed to bind to {}: {}", addr, e);
                return Err(e.into());
            }
        };

        debug!("[RestService] Starting axum::serve");
        let app = Router::new()
            .route("/api/netshield/rules", get(Self::list_netshield_rules))
            .route("/api/netshield/rules", post(Self::add_netshield_rule))
            .route("/api/netshield/rules", delete(Self::delete_netshield_rule))
            .route("/api/netshield/rules/{id}", get(Self::get_netshield_rule))
            .route(
                "/api/netshield/rules/{id}",
                put(Self::update_netshield_rule),
            )
            .route(
                "/api/netshield/rules/{id}",
                delete(Self::delete_netshield_rule_by_id),
            )
            .route("/api/netshield/groups", get(Self::list_netshield_groups))
            .route(
                "/api/netshield/groups/{group}/rules",
                get(Self::list_netshield_rules_by_group),
            )
            .layer(TraceLayer::new_for_http())
            .with_state(self.engine.clone());
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown)
            .await
            .unwrap();

        Ok(())
    }

    /// List all netshield rules
    async fn list_netshield_rules(State(_engine): State<Arc<Engine>>) -> impl IntoResponse {
        let rules = netshield::get_rules();
        (StatusCode::OK, Json(rules))
    }

    /// Add a netshield rule
    async fn add_netshield_rule(
        State(engine): State<Arc<Engine>>,
        Json(req): Json<NetshieldRuleRequest>,
    ) -> impl IntoResponse {
        let direction = match req.direction.to_lowercase().as_str() {
            "incoming" => netshield::Direction::Incoming,
            "outgoing" => netshield::Direction::Outgoing,
            "both" => netshield::Direction::Both,
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        message: "Invalid direction. Use 'incoming', 'outgoing', or 'both'.".to_string(),
                    }),
                )
                    .into_response();
            }
        };
        let action = match req.action.to_lowercase().as_str() {
            "block" => netshield::Action::Block,
            "allow" => netshield::Action::Allow,
            "log" => netshield::Action::Log,
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        message: "Invalid action".to_string(),
                    }),
                )
                    .into_response();
            }
        };
        let rule = netshield::NetshieldRule {
            id: req.id.unwrap_or_default(),
            name: req.name.clone(),
            description: req.description.clone(),
            direction,
            source: req.source.clone(),
            destination: req.destination.clone(),
            source_port: req.source_port,
            destination_port: req.destination_port,
            protocol: req.protocol.clone(),
            action,
            enabled: if req.enabled.unwrap_or(true) { 1 } else { 0 },
            priority: req.priority.unwrap_or(0),
            parameters: req.parameters.clone().unwrap_or_default(),
            group: req.group.clone(),
        };
        log::debug!("[REST] Received add_netshield_rule request: {:?}", rule);
        let mut module_manager = engine.module_manager().lock().unwrap();
        if let Some(module) = module_manager.get_module_mut("netshield") {
            if let Some(netshield) = module
                .as_any_mut()
                .downcast_mut::<netshield::NetshieldModule>()
            {
                log::debug!(
                    "[REST] Using NetshieldModule instance {:p} for add_rule",
                    netshield
                );
                match netshield::add_rule(netshield, rule.clone()) {
                    Ok(_) => {
                        log::debug!("[REST] Successfully added rule: {:?}", rule);
                        (StatusCode::CREATED, Json(json!({"success": true}))).into_response()
                    }
                    Err(e) => {
                        log::error!("[REST] Failed to add rule: {:?}, error: {}", rule, e);
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ErrorResponse { message: e }),
                        )
                            .into_response()
                    }
                }
            } else {
                log::error!("[REST] Netshield module downcast failed in add_netshield_rule");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        message: "Netshield module downcast failed".to_string(),
                    }),
                )
                    .into_response()
            }
        } else {
            log::error!("[REST] Netshield module not found in add_netshield_rule");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: "Netshield module not found".to_string(),
                }),
            )
                .into_response()
        }
    }

    /// Delete a netshield rule
    async fn delete_netshield_rule(
        State(engine): State<Arc<Engine>>,
        Json(req): Json<NetshieldRuleRequest>,
    ) -> impl IntoResponse {
        log::debug!(
            "[REST] Received delete_netshield_rule request: id={:?}",
            req.id
        );
        let mut module_manager = engine.module_manager().lock().unwrap();
        if let Some(module) = module_manager.get_module_mut("netshield") {
            if let Some(netshield) = module
                .as_any_mut()
                .downcast_mut::<netshield::NetshieldModule>()
            {
                log::debug!(
                    "[REST] Using NetshieldModule instance {:p} for delete_rule",
                    netshield
                );
                if let Some(id) = req.id {
                    match netshield::delete_rule(netshield, &id) {
                        Ok(_) => {
                            log::debug!("[REST] Successfully deleted rule id={}", id);
                            (StatusCode::OK, Json(json!({"success": true}))).into_response()
                        }
                        Err(e) => {
                            log::error!("[REST] Failed to delete rule id={}, error: {}", id, e);
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(ErrorResponse { message: e }),
                            )
                                .into_response()
                        }
                    }
                } else {
                    log::error!("[REST] Missing rule id for deletion");
                    (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse {
                            message: "Missing rule id for deletion".to_string(),
                        }),
                    )
                        .into_response()
                }
            } else {
                log::error!("[REST] Netshield module downcast failed in delete_netshield_rule");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        message: "Netshield module downcast failed".to_string(),
                    }),
                )
                    .into_response()
            }
        } else {
            log::error!("[REST] Netshield module not found in delete_netshield_rule");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: "Netshield module not found".to_string(),
                }),
            )
                .into_response()
        }
    }

    /// Get a netshield rule by id
    async fn get_netshield_rule(
        State(_engine): State<Arc<Engine>>,
        Path(id): Path<String>,
    ) -> impl IntoResponse {
        match netshield::get_rule(&id) {
            Some(rule) => (StatusCode::OK, Json(rule)).into_response(),
            None => (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    message: "Rule not found".to_string(),
                }),
            )
                .into_response(),
        }
    }

    /// Update a netshield rule by id
    async fn update_netshield_rule(
        State(engine): State<Arc<Engine>>,
        Path(id): Path<String>,
        Json(req): Json<NetshieldRuleRequest>,
    ) -> impl IntoResponse {
        log::debug!(
            "[REST] Received update_netshield_rule request: id={}, req={:?}",
            id,
            req
        );
        let direction = match req.direction.to_lowercase().as_str() {
            "incoming" => netshield::Direction::Incoming,
            "outgoing" => netshield::Direction::Outgoing,
            "both" => netshield::Direction::Both,
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        message: "Invalid direction".to_string(),
                    }),
                )
                    .into_response();
            }
        };
        let action = match req.action.to_lowercase().as_str() {
            "block" => netshield::Action::Block,
            "allow" => netshield::Action::Allow,
            "log" => netshield::Action::Log,
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        message: "Invalid action".to_string(),
                    }),
                )
                    .into_response();
            }
        };
        let updated = netshield::NetshieldRule {
            id: id.clone(),
            name: req.name.clone(),
            description: req.description.clone(),
            direction,
            source: req.source.clone(),
            destination: req.destination.clone(),
            source_port: req.source_port,
            destination_port: req.destination_port,
            protocol: req.protocol.clone(),
            action,
            enabled: if req.enabled.unwrap_or(true) { 1 } else { 0 },
            priority: req.priority.unwrap_or(0),
            parameters: req.parameters.clone().unwrap_or_default(),
            group: req.group.clone(),
        };
        let mut module_manager = engine.module_manager().lock().unwrap();
        if let Some(module) = module_manager.get_module_mut("netshield") {
            if let Some(netshield) = module
                .as_any_mut()
                .downcast_mut::<netshield::NetshieldModule>()
            {
                log::debug!(
                    "[REST] Using NetshieldModule instance {:p} for update_rule",
                    netshield
                );
                match netshield::update_rule(netshield, &id, updated.clone()) {
                    Ok(_) => {
                        log::debug!("[REST] Successfully updated rule: {:?}", updated);
                        (StatusCode::OK, Json(json!({"success": true}))).into_response()
                    }
                    Err(e) => {
                        log::error!("[REST] Failed to update rule id={}, error: {}", id, e);
                        (StatusCode::NOT_FOUND, Json(ErrorResponse { message: e })).into_response()
                    }
                }
            } else {
                log::error!("[REST] Netshield module downcast failed in update_netshield_rule");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        message: "Netshield module downcast failed".to_string(),
                    }),
                )
                    .into_response()
            }
        } else {
            log::error!("[REST] Netshield module not found in update_netshield_rule");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: "Netshield module not found".to_string(),
                }),
            )
                .into_response()
        }
    }

    /// Delete a netshield rule by id (path param)
    async fn delete_netshield_rule_by_id(
        State(engine): State<Arc<Engine>>,
        Path(id): Path<String>,
    ) -> impl IntoResponse {
        log::debug!(
            "[REST] Received delete_netshield_rule_by_id request: id={}",
            id
        );
        let mut module_manager = engine.module_manager().lock().unwrap();
        if let Some(module) = module_manager.get_module_mut("netshield") {
            if let Some(netshield) = module
                .as_any_mut()
                .downcast_mut::<netshield::NetshieldModule>()
            {
                log::debug!(
                    "[REST] Using NetshieldModule instance {:p} for delete_rule_by_id",
                    netshield
                );
                match netshield::delete_rule(netshield, &id) {
                    Ok(_) => {
                        log::debug!("[REST] Successfully deleted rule id={}", id);
                        (StatusCode::OK, Json(json!({"success": true}))).into_response()
                    }
                    Err(e) => {
                        log::error!("[REST] Failed to delete rule id={}, error: {}", id, e);
                        (StatusCode::NOT_FOUND, Json(ErrorResponse { message: e })).into_response()
                    }
                }
            } else {
                log::error!(
                    "[REST] Netshield module downcast failed in delete_netshield_rule_by_id"
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        message: "Netshield module downcast failed".to_string(),
                    }),
                )
                    .into_response()
            }
        } else {
            log::error!("[REST] Netshield module not found in delete_netshield_rule_by_id");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: "Netshield module not found".to_string(),
                }),
            )
                .into_response()
        }
    }

    /// List all netshield groups
    async fn list_netshield_groups(State(_engine): State<Arc<Engine>>) -> impl IntoResponse {
        let groups = netshield::get_groups();
        (StatusCode::OK, Json(groups))
    }

    /// List all netshield rules in a group
    async fn list_netshield_rules_by_group(
        State(_engine): State<Arc<Engine>>,
        Path(group): Path<String>,
    ) -> impl IntoResponse {
        let rules = netshield::get_rules_by_group(&group);
        (StatusCode::OK, Json(rules))
    }
}
