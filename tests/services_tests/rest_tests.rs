use crate::common::iptables::cleanup_test_chains;
use fortexa::core::config::{Config, GeneralConfig, ModuleConfig, RestConfig, ServiceConfig};
use fortexa::core::engine::Engine;
use fortexa::services::rest::RestService;
use portpicker;
use serde_json::json;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use tempfile::NamedTempFile;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_rest_api_add_list_delete_rule() {
    eprintln!("[debug] test_rest_api_add_list_delete_rule running");
    let rules_file = NamedTempFile::new().unwrap();
    let rules_path = rules_file.path().to_str().unwrap().to_string();
    eprintln!("[debug] Created temp rules file at: {}", rules_path);
    std::fs::write(&rules_path, b"[]").unwrap();
    let tmp_dir = env::temp_dir();
    let config_path: PathBuf = tmp_dir.join(format!("test_config_{}.toml", uuid::Uuid::new_v4()));
    eprintln!("[debug] Config path: {}", config_path.display());
    let chain_prefix = format!(
        "FORTEXA_TST_{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    eprintln!("[debug] Chain prefix: {}", chain_prefix);
    let mut modules = HashMap::new();
    modules.insert(
        "iptables".to_string(),
        ModuleConfig {
            enabled: true,
            settings: HashMap::from([(
                "chain_prefix".to_string(),
                serde_json::Value::String(chain_prefix.clone()),
            )]),
            custom_chains: None,
        },
    );
    modules.insert(
        "logging".to_string(),
        ModuleConfig {
            enabled: true,
            settings: HashMap::from([(
                "log_file".to_string(),
                serde_json::Value::String("/tmp/test_fw.log".to_string()),
            )]),
            custom_chains: None,
        },
    );
    let port = portpicker::pick_unused_port().expect("No ports free");
    eprintln!("[debug] Using port: {}", port);
    let config = Config {
        general: GeneralConfig {
            enabled: true,
            log_level: "info".to_string(),
            rules_path: rules_path.clone(),
        },
        modules,
        services: ServiceConfig {
            rest: RestConfig {
                enabled: true,
                bind_address: "127.0.0.1".to_string(),
                port,
            },
        },
    };
    let config_str = toml::to_string(&config).unwrap();
    fs::write(&config_path, config_str).unwrap();
    eprintln!("[debug] Config written");
    let engine = Engine::new(config_path.to_str().unwrap()).unwrap();
    engine.register_all_modules().unwrap();
    let rest_service = RestService::new(engine.clone());
    let (shutdown_tx, shutdown_rx_server) = tokio::sync::oneshot::channel::<()>();
    let server_handle = tokio::spawn(async move {
        if let Err(e) = rest_service
            .run(Box::pin(async move {
                shutdown_rx_server.await.ok();
            }))
            .await
        {
            eprintln!("[server error] REST service failed: {e:?}");
        }
    });
    eprintln!("[debug] Server task spawned");
    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{}/api/filter/rules", port);
    // Wait for server
    let mut started = false;
    for _ in 0..50 {
        if client.get(&base_url).send().await.is_ok() {
            started = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(started, "REST API did not start in time");
    eprintln!("[debug] REST API started");
    // Add a rule
    let rule_req = json!({
        "name": "api_test_rule",
        "direction": "input",
        "action": "accept",
        "priority": 1
    });
    eprintln!("[debug] Sending POST to add rule: {:?}", rule_req);
    let resp = client.post(&base_url).json(&rule_req).send().await.unwrap();
    eprintln!("[debug] POST response: {:?}", resp);
    assert!(resp.status().is_success());
    // List rules
    eprintln!("[debug] Listing rules...");
    let resp = client.get(&base_url).send().await.unwrap();
    assert!(resp.status().is_success());
    let rules: Vec<serde_json::Value> = resp.json().await.unwrap();
    eprintln!("[debug] Rules: {:?}", rules);
    assert!(rules.iter().any(|r| r["name"] == "api_test_rule"));
    // Delete the rule
    let rule_id = rules.iter().find(|r| r["name"] == "api_test_rule").unwrap()["id"]
        .as_str()
        .unwrap();
    eprintln!("[debug] Deleting rule with id: {}", rule_id);
    let delete_url = format!("{}/{}", base_url, rule_id);
    let resp = client.delete(&delete_url).send().await.unwrap();
    eprintln!("[debug] DELETE response: {:?}", resp);
    assert!(resp.status().is_success());
    // List rules again
    let resp = client.get(&base_url).send().await.unwrap();
    let rules: Vec<serde_json::Value> = resp.json().await.unwrap();
    eprintln!("[debug] Rules after deletion: {:?}", rules);
    assert!(!rules.iter().any(|r| r["name"] == "api_test_rule"));
    // Shutdown
    let _ = shutdown_tx.send(());
    let _ = server_handle.await;
    // Cleanup iptables chains
    cleanup_test_chains(&chain_prefix);
    eprintln!("[debug] test_rest_api_add_list_delete_rule completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_rest_api_add_rule_invalid_data() {
    eprintln!("[debug] test_rest_api_add_rule_invalid_data running");
    let rules_file = NamedTempFile::new().unwrap();
    let rules_path = rules_file.path().to_str().unwrap().to_string();
    std::fs::write(&rules_path, b"[]").unwrap();
    let tmp_dir = env::temp_dir();
    let config_path: PathBuf = tmp_dir.join(format!("test_config_{}.toml", uuid::Uuid::new_v4()));
    let chain_prefix = format!(
        "FORTEXA_TST_{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let mut modules = HashMap::new();
    modules.insert(
        "iptables".to_string(),
        ModuleConfig {
            enabled: true,
            settings: HashMap::from([(
                "chain_prefix".to_string(),
                serde_json::Value::String(chain_prefix.clone()),
            )]),
            custom_chains: None,
        },
    );
    modules.insert(
        "logging".to_string(),
        ModuleConfig {
            enabled: true,
            settings: HashMap::from([(
                "log_file".to_string(),
                serde_json::Value::String("/tmp/test_fw.log".to_string()),
            )]),
            custom_chains: None,
        },
    );
    let port = portpicker::pick_unused_port().expect("No ports free");
    let config = Config {
        general: GeneralConfig {
            enabled: true,
            log_level: "info".to_string(),
            rules_path: rules_path.clone(),
        },
        modules,
        services: ServiceConfig {
            rest: RestConfig {
                enabled: true,
                bind_address: "127.0.0.1".to_string(),
                port,
            },
        },
    };
    let config_str = toml::to_string(&config).unwrap();
    fs::write(&config_path, config_str).unwrap();
    let engine = Engine::new(config_path.to_str().unwrap()).unwrap();
    engine.register_all_modules().unwrap();
    let rest_service = RestService::new(engine.clone());
    let (shutdown_tx, shutdown_rx_server) = tokio::sync::oneshot::channel::<()>();
    let server_handle = tokio::spawn(async move {
        if let Err(e) = rest_service
            .run(Box::pin(async move {
                shutdown_rx_server.await.ok();
            }))
            .await
        {
            eprintln!("[server error] REST service failed: {e:?}");
        }
    });
    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{}/api/filter/rules", port);
    // Wait for server
    let mut started = false;
    for _ in 0..50 {
        if client.get(&base_url).send().await.is_ok() {
            started = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(started, "REST API did not start in time");
    // Add a rule with invalid direction
    let rule_req = json!({
        "name": "bad_rule",
        "direction": "sideways",
        "action": "accept",
        "priority": 1
    });
    let resp = client.post(&base_url).json(&rule_req).send().await.unwrap();
    assert_eq!(resp.status(), 400);
    // Add a rule with invalid action
    let rule_req = json!({
        "name": "bad_rule2",
        "direction": "input",
        "action": "explode",
        "priority": 1
    });
    let resp = client.post(&base_url).json(&rule_req).send().await.unwrap();
    assert_eq!(resp.status(), 400);
    // Shutdown
    let _ = shutdown_tx.send(());
    let _ = server_handle.await;
    // Cleanup iptables chains
    cleanup_test_chains(&chain_prefix);
    eprintln!("[debug] test_rest_api_add_rule_invalid_data completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_rest_api_get_nonexistent_rule() {
    eprintln!("[debug] test_rest_api_get_nonexistent_rule running");
    let rules_file = NamedTempFile::new().unwrap();
    let rules_path = rules_file.path().to_str().unwrap().to_string();
    std::fs::write(&rules_path, b"[]").unwrap();
    let tmp_dir = env::temp_dir();
    let config_path: PathBuf = tmp_dir.join(format!("test_config_{}.toml", uuid::Uuid::new_v4()));
    let chain_prefix = format!(
        "FORTEXA_TST_{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let mut modules = HashMap::new();
    modules.insert(
        "iptables".to_string(),
        ModuleConfig {
            enabled: true,
            settings: HashMap::from([(
                "chain_prefix".to_string(),
                serde_json::Value::String(chain_prefix.clone()),
            )]),
            custom_chains: None,
        },
    );
    modules.insert(
        "logging".to_string(),
        ModuleConfig {
            enabled: true,
            settings: HashMap::from([(
                "log_file".to_string(),
                serde_json::Value::String("/tmp/test_fw.log".to_string()),
            )]),
            custom_chains: None,
        },
    );
    let port = portpicker::pick_unused_port().expect("No ports free");
    let config = Config {
        general: GeneralConfig {
            enabled: true,
            log_level: "info".to_string(),
            rules_path: rules_path.clone(),
        },
        modules,
        services: ServiceConfig {
            rest: RestConfig {
                enabled: true,
                bind_address: "127.0.0.1".to_string(),
                port,
            },
        },
    };
    let config_str = toml::to_string(&config).unwrap();
    fs::write(&config_path, config_str).unwrap();
    let engine = Engine::new(config_path.to_str().unwrap()).unwrap();
    engine.register_all_modules().unwrap();
    let rest_service = RestService::new(engine.clone());
    let (shutdown_tx, shutdown_rx_server) = tokio::sync::oneshot::channel::<()>();
    let server_handle = tokio::spawn(async move {
        if let Err(e) = rest_service
            .run(Box::pin(async move {
                shutdown_rx_server.await.ok();
            }))
            .await
        {
            eprintln!("[server error] REST service failed: {e:?}");
        }
    });
    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{}/api/filter/rules", port);
    // Wait for server
    let mut started = false;
    for _ in 0..50 {
        if client.get(&base_url).send().await.is_ok() {
            started = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(started, "REST API did not start in time");
    // Try to get a nonexistent rule
    let resp = client
        .get(&format!("{}/nonexistent_id", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    // Shutdown
    let _ = shutdown_tx.send(());
    let _ = server_handle.await;
    // Cleanup iptables chains
    cleanup_test_chains(&chain_prefix);
    eprintln!("[debug] test_rest_api_get_nonexistent_rule completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_rest_api_update_rule() {
    eprintln!("[debug] test_rest_api_update_rule running");
    let rules_file = NamedTempFile::new().unwrap();
    let rules_path = rules_file.path().to_str().unwrap().to_string();
    std::fs::write(&rules_path, b"[]").unwrap();
    let tmp_dir = env::temp_dir();
    let config_path: PathBuf = tmp_dir.join(format!("test_config_{}.toml", uuid::Uuid::new_v4()));
    let chain_prefix = format!(
        "FORTEXA_TST_{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let mut modules = HashMap::new();
    modules.insert(
        "iptables".to_string(),
        ModuleConfig {
            enabled: true,
            settings: HashMap::from([(
                "chain_prefix".to_string(),
                serde_json::Value::String(chain_prefix.clone()),
            )]),
            custom_chains: None,
        },
    );
    modules.insert(
        "logging".to_string(),
        ModuleConfig {
            enabled: true,
            settings: HashMap::from([(
                "log_file".to_string(),
                serde_json::Value::String("/tmp/test_fw.log".to_string()),
            )]),
            custom_chains: None,
        },
    );
    let port = portpicker::pick_unused_port().expect("No ports free");
    let config = Config {
        general: GeneralConfig {
            enabled: true,
            log_level: "info".to_string(),
            rules_path: rules_path.clone(),
        },
        modules,
        services: ServiceConfig {
            rest: RestConfig {
                enabled: true,
                bind_address: "127.0.0.1".to_string(),
                port,
            },
        },
    };
    let config_str = toml::to_string(&config).unwrap();
    fs::write(&config_path, config_str).unwrap();
    let engine = Engine::new(config_path.to_str().unwrap()).unwrap();
    engine.register_all_modules().unwrap();
    let rest_service = RestService::new(engine.clone());
    let (shutdown_tx, shutdown_rx_server) = tokio::sync::oneshot::channel::<()>();
    let server_handle = tokio::spawn(async move {
        if let Err(e) = rest_service
            .run(Box::pin(async move {
                shutdown_rx_server.await.ok();
            }))
            .await
        {
            eprintln!("[server error] REST service failed: {e:?}");
        }
    });
    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{}/api/filter/rules", port);
    // Wait for server
    let mut started = false;
    for _ in 0..50 {
        if client.get(&base_url).send().await.is_ok() {
            started = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(started, "REST API did not start in time");
    // Add a rule
    let rule_req = json!({
        "name": "update_test_rule",
        "direction": "input",
        "action": "accept",
        "priority": 1
    });
    let resp = client.post(&base_url).json(&rule_req).send().await.unwrap();
    assert!(resp.status().is_success());
    // List rules
    let resp = client.get(&base_url).send().await.unwrap();
    let rules: Vec<serde_json::Value> = resp.json().await.unwrap();
    let rule_id = rules
        .iter()
        .find(|r| r["name"] == "update_test_rule")
        .unwrap()["id"]
        .as_str()
        .unwrap();
    // Update the rule
    let update_req = json!({
        "name": "update_test_rule",
        "direction": "input",
        "action": "log",
        "priority": 1
    });
    let update_url = format!("{}/{}", base_url, rule_id);
    let resp = client
        .put(&update_url)
        .json(&update_req)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    // List rules and check update
    let resp = client.get(&base_url).send().await.unwrap();
    let rules: Vec<serde_json::Value> = resp.json().await.unwrap();
    let updated_rule = rules.iter().find(|r| r["id"] == rule_id).unwrap();
    assert_eq!(
        updated_rule["action"].as_str().unwrap().to_lowercase(),
        "log"
    );
    // Shutdown
    let _ = shutdown_tx.send(());
    let _ = server_handle.await;
    // Cleanup iptables chains
    cleanup_test_chains(&chain_prefix);
    eprintln!("[debug] test_rest_api_update_rule completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_rest_api_reset_all_rules() {
    eprintln!("[debug] test_rest_api_reset_all_rules running");
    let rules_file = NamedTempFile::new().unwrap();
    let rules_path = rules_file.path().to_str().unwrap().to_string();
    std::fs::write(&rules_path, b"[]").unwrap();
    let tmp_dir = env::temp_dir();
    let config_path: PathBuf = tmp_dir.join(format!("test_config_{}.toml", uuid::Uuid::new_v4()));
    let chain_prefix = format!(
        "FORTEXA_TST_{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let mut modules = HashMap::new();
    modules.insert(
        "iptables".to_string(),
        ModuleConfig {
            enabled: true,
            settings: HashMap::from([(
                "chain_prefix".to_string(),
                serde_json::Value::String(chain_prefix.clone()),
            )]),
            custom_chains: None,
        },
    );
    modules.insert(
        "logging".to_string(),
        ModuleConfig {
            enabled: true,
            settings: HashMap::from([(
                "log_file".to_string(),
                serde_json::Value::String("/tmp/test_fw.log".to_string()),
            )]),
            custom_chains: None,
        },
    );
    let port = portpicker::pick_unused_port().expect("No ports free");
    let config = Config {
        general: GeneralConfig {
            enabled: true,
            log_level: "info".to_string(),
            rules_path: rules_path.clone(),
        },
        modules,
        services: ServiceConfig {
            rest: RestConfig {
                enabled: true,
                bind_address: "127.0.0.1".to_string(),
                port,
            },
        },
    };
    let config_str = toml::to_string(&config).unwrap();
    fs::write(&config_path, config_str).unwrap();
    let engine = Engine::new(config_path.to_str().unwrap()).unwrap();
    engine.register_all_modules().unwrap();
    let rest_service = RestService::new(engine.clone());
    let (shutdown_tx, shutdown_rx_server) = tokio::sync::oneshot::channel::<()>();
    let server_handle = tokio::spawn(async move {
        if let Err(e) = rest_service
            .run(Box::pin(async move {
                shutdown_rx_server.await.ok();
            }))
            .await
        {
            eprintln!("[server error] REST service failed: {e:?}");
        }
    });
    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{}/api/filter/rules", port);
    // Wait for server
    let mut started = false;
    for _ in 0..50 {
        if client.get(&base_url).send().await.is_ok() {
            started = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(started, "REST API did not start in time");
    // Add two rules
    let rule1 = json!({
        "name": "reset_test_rule1",
        "direction": "input",
        "action": "accept",
        "priority": 1
    });
    let rule2 = json!({
        "name": "reset_test_rule2",
        "direction": "output",
        "action": "accept",
        "priority": 2
    });
    let resp = client.post(&base_url).json(&rule1).send().await.unwrap();
    assert!(resp.status().is_success());
    let resp = client.post(&base_url).json(&rule2).send().await.unwrap();
    assert!(resp.status().is_success());
    // List rules
    let resp = client.get(&base_url).send().await.unwrap();
    let rules: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert!(rules.iter().any(|r| r["name"] == "reset_test_rule1"));
    assert!(rules.iter().any(|r| r["name"] == "reset_test_rule2"));
    // Reset all rules
    let resp = client.delete(&base_url).send().await.unwrap();
    assert!(resp.status().is_success());
    // List rules again
    let resp = client.get(&base_url).send().await.unwrap();
    let rules: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert!(rules.is_empty());
    // Shutdown
    let _ = shutdown_tx.send(());
    let _ = server_handle.await;
    // Cleanup iptables chains
    cleanup_test_chains(&chain_prefix);
    eprintln!("[debug] test_rest_api_reset_all_rules completed");
}
