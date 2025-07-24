use crate::common::{TEST_CONFIG_TOML, cleanup_test_ebpf};
use fortexa::core::engine::Engine;
use fortexa::services::rest::RestService;
use portpicker;
use serde_json::json;
use std::fs;
use std::sync::Arc;

fn setup_test_paths() -> (String, String, String, u16) {
    let test_dir = "/tmp/fortexa_test";
    fs::create_dir_all(test_dir).unwrap();
    let port = portpicker::pick_unused_port().expect("No ports free");
    let rules_path = format!("{}/rules_{}.json", test_dir, port);
    let config_path = format!("{}/config_{}.toml", test_dir, port);
    let test_id = format!("test_{}", port);
    fs::write(&rules_path, b"[]").unwrap();
    (rules_path, config_path, test_id, port)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_rest_api_add_list_delete_rule() {
    eprintln!("[debug] test_rest_api_add_list_delete_rule running");
    let (rules_path, config_path, test_id, port) = setup_test_paths();
    let config_toml = TEST_CONFIG_TOML
        .replace("{rules_path}", &rules_path)
        .replace("{port}", &port.to_string());
    fs::write(&config_path, config_toml).unwrap();
    eprintln!("[debug] Config path: {}", config_path);
    let engine = Arc::new(Engine::new(&config_path).unwrap());
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
    let base_url = format!("http://127.0.0.1:{}/api/netshield/rules", port);
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
        "name": "api_test_rule",
        "direction": "incoming",
        "action": "allow",
        "priority": 1
    });
    let resp = client.post(&base_url).json(&rule_req).send().await.unwrap();
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_else(|_| "Failed to read body".to_string());
        eprintln!("[debug] POST failed with status: {}, body: {}", status, body);
    }
    assert!(status.is_success());
    // List rules
    let resp = client.get(&base_url).send().await.unwrap();
    assert!(resp.status().is_success());
    let rules: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert!(rules.iter().any(|r| r["name"] == "api_test_rule"));
    // Delete the rule
    let rule_id = rules.iter().find(|r| r["name"] == "api_test_rule").unwrap()["id"]
        .as_str()
        .unwrap();
    let delete_url = format!("{}/{}", base_url, rule_id);
    let resp = client.delete(&delete_url).send().await.unwrap();
    assert!(resp.status().is_success());
    // List rules again
    let resp = client.get(&base_url).send().await.unwrap();
    let rules: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert!(!rules.iter().any(|r| r["name"] == "api_test_rule"));
    // Shutdown
    let _ = shutdown_tx.send(());
    let _ = server_handle.await;
    // Cleanup eBPF
    cleanup_test_ebpf(&test_id);
    eprintln!("[debug] test_rest_api_add_list_delete_rule completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_rest_api_add_rule_invalid_data() {
    eprintln!("[debug] test_rest_api_add_rule_invalid_data running");
    let (rules_path, config_path, test_id, port) = setup_test_paths();
    let config_toml = TEST_CONFIG_TOML
        .replace("{rules_path}", &rules_path)
        .replace("{port}", &port.to_string());
    fs::write(&config_path, config_toml).unwrap();
    eprintln!("[debug] Config path: {}", config_path);
    let engine = Arc::new(Engine::new(&config_path).unwrap());
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
    let base_url = format!("http://127.0.0.1:{}/api/netshield/rules", port);
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
        "action": "allow",
        "priority": 1
    });
    let resp = client.post(&base_url).json(&rule_req).send().await.unwrap();
    assert_eq!(resp.status(), 400);
    // Add a rule with invalid action
    let rule_req = json!({
        "name": "bad_rule2",
        "direction": "incoming",
        "action": "explode",
        "priority": 1
    });
    let resp = client.post(&base_url).json(&rule_req).send().await.unwrap();
    assert_eq!(resp.status(), 400);
    // Shutdown
    let _ = shutdown_tx.send(());
    let _ = server_handle.await;
    // Cleanup eBPF
    cleanup_test_ebpf(&test_id);
    eprintln!("[debug] test_rest_api_add_rule_invalid_data completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_rest_api_get_nonexistent_rule() {
    eprintln!("[debug] test_rest_api_get_nonexistent_rule running");
    let (rules_path, config_path, test_id, port) = setup_test_paths();
    let config_toml = TEST_CONFIG_TOML
        .replace("{rules_path}", &rules_path)
        .replace("{port}", &port.to_string());
    fs::write(&config_path, config_toml).unwrap();
    eprintln!("[debug] Config path: {}", config_path);
    let engine = Arc::new(Engine::new(&config_path).unwrap());
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
    let base_url = format!("http://127.0.0.1:{}/api/netshield/rules", port);
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
    // Cleanup eBPF
    cleanup_test_ebpf(&test_id);
    eprintln!("[debug] test_rest_api_get_nonexistent_rule completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_rest_api_update_rule() {
    eprintln!("[debug] test_rest_api_update_rule running");
    let (rules_path, config_path, test_id, port) = setup_test_paths();
    let config_toml = TEST_CONFIG_TOML
        .replace("{rules_path}", &rules_path)
        .replace("{port}", &port.to_string());
    fs::write(&config_path, config_toml).unwrap();
    eprintln!("[debug] Config path: {}", config_path);
    let engine = Arc::new(Engine::new(&config_path).unwrap());
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
    let base_url = format!("http://127.0.0.1:{}/api/netshield/rules", port);
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
        "direction": "incoming",
        "action": "allow",
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
        "direction": "incoming",
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
    // Cleanup eBPF
    cleanup_test_ebpf(&test_id);
    eprintln!("[debug] test_rest_api_update_rule completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_rest_api_reset_all_rules() {
    eprintln!("[debug] test_rest_api_reset_all_rules running");
    let (rules_path, config_path, test_id, port) = setup_test_paths();
    let config_toml = TEST_CONFIG_TOML
        .replace("{rules_path}", &rules_path)
        .replace("{port}", &port.to_string());
    fs::write(&config_path, config_toml).unwrap();
    eprintln!("[debug] Config path: {}", config_path);
    let engine = Arc::new(Engine::new(&config_path).unwrap());
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
    let base_url = format!("http://127.0.0.1:{}/api/netshield/rules", port);
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
        "direction": "incoming",
        "action": "allow",
        "priority": 1
    });
    let rule2 = json!({
        "name": "reset_test_rule2",
        "direction": "outgoing",
        "action": "allow",
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
    // Cleanup eBPF
    cleanup_test_ebpf(&test_id);
    eprintln!("[debug] test_rest_api_reset_all_rules completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_rest_api_ebpf_rule_limits() {
    eprintln!("[debug] test_rest_api_ebpf_rule_limits running");
    let (rules_path, config_path, test_id, port) = setup_test_paths();
    let config_toml = TEST_CONFIG_TOML
        .replace("{rules_path}", &rules_path)
        .replace("{port}", &port.to_string());
    fs::write(&config_path, config_toml).unwrap();
    eprintln!("[debug] Config path: {}", config_path);
    let engine = Arc::new(Engine::new(&config_path).unwrap());
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
    let base_url = format!("http://127.0.0.1:{}/api/netshield/rules", port);
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
    
    // Test adding multiple rules (eBPF secure version supports 3 rules max)
    for i in 1..=3 {
        let rule_req = json!({
            "name": format!("ebpf_test_rule_{}", i),
            "direction": "incoming",
            "action": "allow",
            "priority": i
        });
        let resp = client.post(&base_url).json(&rule_req).send().await.unwrap();
        assert!(resp.status().is_success(), "Failed to add rule {}", i);
    }
    
    // List rules to verify all were added
    let resp = client.get(&base_url).send().await.unwrap();
    let rules: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert_eq!(rules.len(), 3, "Expected 3 rules in eBPF map");
    
    // Shutdown
    let _ = shutdown_tx.send(());
    let _ = server_handle.await;
    // Cleanup eBPF
    cleanup_test_ebpf(&test_id);
    eprintln!("[debug] test_rest_api_ebpf_rule_limits completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_rest_api_ebpf_ip_filtering() {
    eprintln!("[debug] test_rest_api_ebpf_ip_filtering running");
    let (rules_path, config_path, test_id, port) = setup_test_paths();
    let config_toml = TEST_CONFIG_TOML
        .replace("{rules_path}", &rules_path)
        .replace("{port}", &port.to_string());
    fs::write(&config_path, config_toml).unwrap();
    eprintln!("[debug] Config path: {}", config_path);
    let engine = Arc::new(Engine::new(&config_path).unwrap());
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
    let base_url = format!("http://127.0.0.1:{}/api/netshield/rules", port);
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
    
    // Add an IP-based blocking rule
    let rule_req = json!({
        "name": "block_test_ip",
        "direction": "incoming",
        "source_ip": "192.168.1.100",
        "action": "block",
        "priority": 1
    });
    let resp = client.post(&base_url).json(&rule_req).send().await.unwrap();
    assert!(resp.status().is_success());
    
    // Add an IP-based allow rule
    let rule_req = json!({
        "name": "allow_test_ip",
        "direction": "incoming", 
        "source_ip": "10.0.0.1",
        "action": "allow",
        "priority": 2
    });
    let resp = client.post(&base_url).json(&rule_req).send().await.unwrap();
    assert!(resp.status().is_success());
    
    // List rules and verify they were added with correct IP addresses
    let resp = client.get(&base_url).send().await.unwrap();
    let rules: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert!(rules.iter().any(|r| r["name"] == "block_test_ip" && r["source_ip"] == "192.168.1.100"));
    assert!(rules.iter().any(|r| r["name"] == "allow_test_ip" && r["source_ip"] == "10.0.0.1"));
    
    // Shutdown
    let _ = shutdown_tx.send(());
    let _ = server_handle.await;
    // Cleanup eBPF
    cleanup_test_ebpf(&test_id);
    eprintln!("[debug] test_rest_api_ebpf_ip_filtering completed");
}
