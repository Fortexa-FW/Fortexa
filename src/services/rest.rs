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

/// Rule request
#[derive(Debug, Deserialize, Clone)]
pub struct RuleRequest {
    /// Rule name
    pub name: String,

    /// Rule description
    pub description: Option<String>,

    /// Rule direction
    pub direction: String,

    /// Source IP address or network"""
    pub source: Option<String>,

    /// Destination IP address or network
    pub destination: Option<String>,

    /// Source port or port range
    pub source_port: Option<String>,

    /// Destination port or port range
    pub destination_port: Option<String>,

    /// Protocol (tcp, udp, icmp, etc.)
    pub protocol: Option<String>,

    /// Rule action
    pub action: String,

    /// Whether the rule is enabled
    pub enabled: Option<bool>,

    /// Rule priority
    pub priority: Option<i32>,

    /// If true, auto-create the chain if it does not exist
    pub auto_create_chain: Option<bool>,

    /// If auto_create_chain is true, reference the new chain from a built-in one (INPUT, OUTPUT, FORWARD)
    pub reference_from: Option<String>,
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
            .route("/api/filter/rules", get(Self::list_rules))
            .route("/api/filter/rules", post(Self::add_rule))
            .route("/api/filter/rules", delete(Self::reset_rules))
            .route("/api/filter/rules/{id}", get(Self::get_rule))
            .route("/api/filter/rules/{id}", put(Self::update_rule))
            .route("/api/filter/rules/{id}", delete(Self::delete_rule))
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

    /// List all rules
    async fn list_rules(State(engine): State<Arc<Engine>>) -> impl IntoResponse {
        match engine.list_rules("filter") {
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
        match engine.reset_rules("filter") {
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
        let rule = match rule_from_request(&rule_req) {
            Ok(r) => r,
            Err(msg) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse { message: msg }),
                )
                    .into_response();
            }
        };
        match engine.add_rule("filter", rule) {
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
        match engine.get_rule("filter", &rule_id) {
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
        let mut rule = match engine.get_rule("filter", &rule_id) {
            Ok(r) => r,
            Err(e) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        message: e.to_string(),
                    }),
                )
                    .into_response();
            }
        };
        let new_rule = match rule_from_request(&rule_req) {
            Ok(r) => r,
            Err(msg) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse { message: msg }),
                )
                    .into_response();
            }
        };
        // Overwrite all fields except id
        rule.name = new_rule.name;
        rule.description = new_rule.description;
        rule.direction = new_rule.direction;
        rule.source = new_rule.source;
        rule.destination = new_rule.destination;
        rule.source_port = new_rule.source_port;
        rule.destination_port = new_rule.destination_port;
        rule.protocol = new_rule.protocol;
        rule.action = new_rule.action;
        rule.enabled = new_rule.enabled;
        rule.priority = new_rule.priority;
        match engine.update_rule("filter", rule) {
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
        match engine.delete_rule("filter", &rule_id) {
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
            enabled: req.enabled.unwrap_or(true),
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
            enabled: req.enabled.unwrap_or(true),
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
                match netshield::update_rule(&id, updated.clone()) {
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

fn rule_from_request(rule_req: &RuleRequest) -> Result<Rule, String> {
    let direction = match rule_req.direction.to_lowercase().as_str() {
        "incoming" | "input" => Direction::Incoming,
        "outgoing" | "output" => Direction::Outgoing,
        _ => return Err(format!("Invalid direction: {}", rule_req.direction)),
    };
    let action = match rule_req.action.to_lowercase().as_str() {
        "block" => Action::Block,
        "allow" => Action::Allow,
        "log" => Action::Log,
        _ => return Err(format!("Invalid action: {}", rule_req.action)),
    };
    let enabled = if rule_req.enabled.unwrap_or(true) {
        1
    } else {
        0
    };
    let source_ip = rule_req.source.as_ref().map_or(0, |s| parse_ip(s));
    let destination_ip = rule_req.destination.as_ref().map_or(0, |s| parse_ip(s));
    let source_port_network = rule_req
        .source_port
        .as_ref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let destination_port_network = rule_req
        .destination_port
        .as_ref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let protocol_number = rule_req.protocol.as_ref().map_or(0, |p| parse_protocol(p));
    Ok(Rule {
        id: uuid::Uuid::new_v4().to_string(),
        enabled,
        direction,
        action,
        source_ip,
        destination_ip,
        source_port_network,
        destination_port_network,
        protocol_number,
        priority: rule_req.priority.unwrap_or(0),
        name: rule_req.name.clone(),
        description: rule_req.description.clone(),
        source: rule_req.source.clone(),
        destination: rule_req.destination.clone(),
        source_port: rule_req.source_port.clone(),
        destination_port: rule_req.destination_port.clone(),
        protocol: rule_req.protocol.clone(),
        parameters: std::collections::HashMap::new(),
    })
}

fn parse_ip(ip_str: &str) -> u32 {
    use std::net::Ipv4Addr;
    ip_str
        .parse::<Ipv4Addr>()
        .map(u32::from)
        .unwrap_or(0)
}

fn parse_protocol(proto: &str) -> u8 {
    match proto.to_lowercase().as_str() {
        "tcp" => 6,
        "udp" => 17,
        "icmp" => 1,
        _ => 0,
    }
}
