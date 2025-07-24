mod common;
use crate::common::{TEST_CONFIG_TOML, cleanup_test_ebpf};
use fortexa::core::engine::Engine;
use fortexa::core::rules::{Action, Direction, Rule};
use fortexa::services::rest::RestService;
use portpicker;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::NamedTempFile;
use uuid::Uuid;

#[tokio::test]
async fn test_engine_end_to_end() {
    // Create temp config and rules files
    let rules_file = NamedTempFile::new().unwrap();
    let rules_path = rules_file.path().to_str().unwrap().to_string();
    std::fs::write(&rules_path, b"[]").unwrap();
    let tmp_dir = env::temp_dir();
    let config_path: PathBuf = tmp_dir.join(format!("test_config_{}.toml", Uuid::new_v4()));
    let test_id = format!("engine_test_{}", &Uuid::new_v4().simple().to_string()[..8]);
    let port = portpicker::pick_unused_port().expect("No ports free");
    let config_toml = TEST_CONFIG_TOML
        .replace("{rules_path}", &rules_path)
        .replace("{port}", &port.to_string());
    fs::write(&config_path, config_toml).unwrap();
    eprintln!("[test] config_path: {}", config_path.to_str().unwrap());
    eprintln!("[test] rules_path: {}", rules_path);
    let engine = Arc::new(match Engine::new(config_path.to_str().unwrap()) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("[test error] Engine::new failed: {e:?}");
            panic!("Engine::new failed");
        }
    });
    if let Err(e) = engine.register_all_modules() {
        eprintln!("[test error] register_all_modules failed: {e:?}");
        panic!("register_all_modules failed");
    }
    let rule = Rule::new("test_rule".to_string(), Direction::Incoming, Action::Allow, 1);
    let rule_id = engine.add_rule("netshield", rule.clone()).unwrap();
    let rules = engine.list_rules("netshield").unwrap();
    assert!(rules.iter().any(|r| r.id == rule_id));
    engine.reset_rules("netshield").unwrap();
    let rules = engine.list_rules("netshield").unwrap();
    assert!(rules.is_empty());
    cleanup_test_ebpf(&test_id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_rest_api_end_to_end() {
    eprintln!("[test] test_rest_api_end_to_end started");
    let rules_file = NamedTempFile::new().unwrap();
    let rules_path = rules_file.path().to_str().unwrap().to_string();
    std::fs::write(&rules_path, b"[]").unwrap();
    let tmp_dir = env::temp_dir();
    let config_path: PathBuf = tmp_dir.join(format!("test_config_{}.toml", Uuid::new_v4()));
    let test_id = format!("rest_test_{}", &Uuid::new_v4().simple().to_string()[..8]);
    let port = portpicker::pick_unused_port().expect("No ports free");
    let config_toml = TEST_CONFIG_TOML
        .replace("{rules_path}", &rules_path)
        .replace("{port}", &port.to_string());
    fs::write(&config_path, config_toml).unwrap();
    eprintln!("[test] Starting REST server on port {}", port);
    eprintln!("[test] About to spawn REST server task");
    let engine = Arc::new(Engine::new(config_path.to_str().unwrap()).unwrap());
    engine.register_all_modules().unwrap();
    let rest_service = RestService::new(engine.clone());
    let (shutdown_tx, shutdown_rx_server) = tokio::sync::oneshot::channel::<()>();
    let server_handle = tokio::spawn(async move {
        eprintln!("[test] Inside REST server task");
        if let Err(e) = rest_service
            .run(Box::pin(async move {
                shutdown_rx_server.await.ok();
            }))
            .await
        {
            eprintln!("[server error] REST service failed: {e:?}");
        }
    });
    eprintln!("[test] Server task spawned");
    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{}/api/netshield/rules", port);
    let mut started = false;
    for i in 0..50 {
        match client.get(base_url.as_str()).send().await {
            Ok(_) => {
                started = true;
                break;
            }
            Err(e) => {
                eprintln!("[wait {}] REST API not up yet: {}", i, e);
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(started, "REST API did not start in time");
    let rule_req = serde_json::json!({
        "name": "api_test_rule",
        "direction": "input",
        "action": "accept",
        "priority": 1
    });
    let resp = client
        .post(base_url.as_str())
        .json(&rule_req)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let resp = client.get(base_url.as_str()).send().await.unwrap();
    assert!(resp.status().is_success());
    let rules: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert!(rules.iter().any(|r| r["name"] == "api_test_rule"));
    let resp = client.delete(base_url.as_str()).send().await.unwrap();
    assert!(resp.status().is_success());
    let _ = shutdown_tx.send(());
    let _ = server_handle.await;
    cleanup_test_ebpf(&test_id);
}
