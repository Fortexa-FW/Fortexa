use crate::common::TEST_CONFIG_TOML;
use crate::common::iptables::cleanup_test_chains;
use fortexa::core::engine::Engine;
use fortexa::services::rest::RestService;
use portpicker;
use serde_json::json;
use std::fs;

fn setup_test_paths() -> (String, String, String, String, u16) {
    let test_dir = "/tmp/fortexa_test";
    fs::create_dir_all(test_dir).unwrap();
    let port = portpicker::pick_unused_port().expect("No ports free");
    let chains_path = format!("{}/chains_{}.json", test_dir, port);
    let rules_path = format!("{}/rules_{}.json", test_dir, port);
    let config_path = format!("{}/config_{}.toml", test_dir, port);
    let chain_prefix = format!(
        "FORTEXA_TST_{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    fs::write(&chains_path, b"[]").unwrap();
    fs::write(&rules_path, b"[]").unwrap();
    (chains_path, rules_path, config_path, chain_prefix, port)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_rest_api_add_list_delete_rule() {
    eprintln!("[debug] test_rest_api_add_list_delete_rule running");
    let (chains_path, rules_path, config_path, chain_prefix, port) = setup_test_paths();
    let config_toml = TEST_CONFIG_TOML
        .replace("{rules_path}", &rules_path)
        .replace("{chains_path}", &chains_path)
        .replace("{chain_prefix}", &chain_prefix)
        .replace("{port}", &port.to_string());
    fs::write(&config_path, config_toml).unwrap();
    eprintln!("[debug] Config path: {}", config_path);
    let engine = Engine::new(&config_path).unwrap();
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
        "name": "api_test_rule",
        "direction": "input",
        "action": "accept",
        "priority": 1
    });
    let resp = client.post(&base_url).json(&rule_req).send().await.unwrap();
    assert!(resp.status().is_success());
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
    // Cleanup iptables chains
    cleanup_test_chains(&chain_prefix);
    eprintln!("[debug] test_rest_api_add_list_delete_rule completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_rest_api_add_rule_invalid_data() {
    eprintln!("[debug] test_rest_api_add_rule_invalid_data running");
    let (chains_path, rules_path, config_path, chain_prefix, port) = setup_test_paths();
    let config_toml = TEST_CONFIG_TOML
        .replace("{rules_path}", &rules_path)
        .replace("{chains_path}", &chains_path)
        .replace("{chain_prefix}", &chain_prefix)
        .replace("{port}", &port.to_string());
    fs::write(&config_path, config_toml).unwrap();
    eprintln!("[debug] Config path: {}", config_path);
    let engine = Engine::new(&config_path).unwrap();
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
    let (chains_path, rules_path, config_path, chain_prefix, port) = setup_test_paths();
    let config_toml = TEST_CONFIG_TOML
        .replace("{rules_path}", &rules_path)
        .replace("{chains_path}", &chains_path)
        .replace("{chain_prefix}", &chain_prefix)
        .replace("{port}", &port.to_string());
    fs::write(&config_path, config_toml).unwrap();
    eprintln!("[debug] Config path: {}", config_path);
    let engine = Engine::new(&config_path).unwrap();
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
    let (chains_path, rules_path, config_path, chain_prefix, port) = setup_test_paths();
    let config_toml = TEST_CONFIG_TOML
        .replace("{rules_path}", &rules_path)
        .replace("{chains_path}", &chains_path)
        .replace("{chain_prefix}", &chain_prefix)
        .replace("{port}", &port.to_string());
    fs::write(&config_path, config_toml).unwrap();
    eprintln!("[debug] Config path: {}", config_path);
    let engine = Engine::new(&config_path).unwrap();
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
    let (chains_path, rules_path, config_path, chain_prefix, port) = setup_test_paths();
    let config_toml = TEST_CONFIG_TOML
        .replace("{rules_path}", &rules_path)
        .replace("{chains_path}", &chains_path)
        .replace("{chain_prefix}", &chain_prefix)
        .replace("{port}", &port.to_string());
    fs::write(&config_path, config_toml).unwrap();
    eprintln!("[debug] Config path: {}", config_path);
    let engine = Engine::new(&config_path).unwrap();
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_rest_api_create_custom_chain() {
    eprintln!("[debug] test_rest_api_create_custom_chain running");
    let (chains_path, rules_path, config_path, chain_prefix, port) = setup_test_paths();
    let config_toml = TEST_CONFIG_TOML
        .replace("{rules_path}", &rules_path)
        .replace("{chains_path}", &chains_path)
        .replace("{chain_prefix}", &chain_prefix)
        .replace("{port}", &port.to_string());
    std::fs::write(&config_path, config_toml).unwrap();
    std::fs::write(&chains_path, b"[]").unwrap();

    let engine = Engine::new(&config_path).unwrap();
    let rest_service = RestService::new(engine.clone());
    let _server = tokio::spawn(async move {
        rest_service
            .run(Box::pin(async {
                std::future::pending::<()>().await;
            }))
            .await
            .unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/api/filter/custom_chain", port);
    let chain_name = format!("{}_MYCHAIN", chain_prefix);
    let body = serde_json::json!({
        "name": chain_name,
        "reference_from": "INPUT"
    });
    let resp = client.post(&url).json(&body).send().await.unwrap();
    assert!(resp.status().is_success());
    eprintln!("[debug] Custom chain created via API");

    // Wait for the server to update the chains file
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    // Check that the chain is in the chains file
    let chains_data = std::fs::read_to_string(&chains_path).unwrap();
    assert!(chains_data.contains("MYCHAIN"));
    eprintln!("[debug] Custom chain found in chains file");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_rest_api_delete_custom_chain() {
    eprintln!("[debug] test_rest_api_delete_custom_chain running");
    let (chains_path, rules_path, config_path, chain_prefix, port) = setup_test_paths();
    let config_toml = TEST_CONFIG_TOML
        .replace("{rules_path}", &rules_path)
        .replace("{chains_path}", &chains_path)
        .replace("{chain_prefix}", &chain_prefix)
        .replace("{port}", &port.to_string());
    std::fs::write(&config_path, config_toml).unwrap();
    std::fs::write(&chains_path, b"[]").unwrap();

    let engine = Engine::new(&config_path).unwrap();
    let rest_service = RestService::new(engine.clone());
    let _server = tokio::spawn(async move {
        rest_service
            .run(Box::pin(async {
                std::future::pending::<()>().await;
            }))
            .await
            .unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/api/filter/custom_chain", port);
    let chain_name = format!("{}_MYCHAIN", chain_prefix);
    let body = serde_json::json!({
        "name": chain_name,
        "reference_from": "INPUT"
    });
    // First, create the chain via API
    let resp = client.post(&url).json(&body).send().await.unwrap();
    assert!(resp.status().is_success());
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let chains_data = std::fs::read_to_string(&chains_path).unwrap();
    assert!(chains_data.contains("MYCHAIN"));
    // Now, delete the custom chain via the API
    let resp = client
        .delete(&url)
        .json(&serde_json::json!({ "name": chain_name, "reference_from": "INPUT" }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    eprintln!("[debug] Custom chain deleted via API");
    // Wait for the server to update the chains file
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    // Check that the chain is no longer in the chains file
    let chains_data = std::fs::read_to_string(&chains_path).unwrap();
    assert!(!chains_data.contains("MYCHAIN"));
    eprintln!("[debug] Custom chain removed from chains file");
}
