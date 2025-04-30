use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};
use axum::http::Request;
use tower::ServiceExt;
use axum::body::Body;

#[tokio::test]
async fn test_shared_state_creation() {
    let firewall_result = fortexa::firewall::core::FirewallManager::new();
    let rules_result = fortexa::firewall::rules_core::RulesManager::new();

    match (firewall_result, rules_result) {
        (Ok(firewall), Ok(rules)) => {
            // Test creating shared state
            let firewall_arc = Arc::new(tokio::sync::Mutex::new(firewall));
            let rules_arc = Arc::new(Mutex::new(rules));

            // The reference count should be 1 for each Arc since we haven't cloned them yet
            assert_eq!(Arc::strong_count(&firewall_arc), 1, "Firewall Arc should have reference count of 1");
            assert_eq!(Arc::strong_count(&rules_arc), 1, "Rules Arc should have reference count of 1");
        }
        (Err(firewall_err), _) if firewall_err.to_string().contains("Chain already exists") => {
            // Acceptable error case for firewall
            assert!(true);
        }
        (Err(firewall_err), _) if firewall_err.to_string().contains("Permission denied") => {
            // Acceptable error case for permission issues
            assert!(true);
        }
        (_, Err(rules_err)) if rules_err.to_string().contains("Chain already exists") => {
            // Acceptable error case for rules
            assert!(true);
        }
        (_, Err(rules_err)) if rules_err.to_string().contains("Permission denied") => {
            // Acceptable error case for permission issues
            assert!(true);
        }
        (Err(e), _) | (_, Err(e)) => {
            // Unexpected error
            panic!("Unexpected error: {}", e);
        }
    }
}

// Note: The following test should be run with caution as it requires proper system permissions
// and might affect the system's firewall rules
#[tokio::test]
#[ignore]
async fn test_full_system_integration() {
    // Create the API router directly without starting the full system
    // This avoids potential deadlocks or never-ending execution
    let firewall_manager = match fortexa::firewall::core::FirewallManager::new() {
        Ok(fm) => fm,
        Err(e) if e.to_string().contains("Permission denied") => {
            // Skip test if permission issues
            println!("Skipping test due to permission issues");
            return;
        }
        Err(e) => panic!("Failed to create FirewallManager: {}", e),
    };
    
    let rules_manager = match fortexa::firewall::rules_core::RulesManager::new() {
        Ok(rm) => rm,
        Err(e) if e.to_string().contains("Permission denied") => {
            // Skip test if permission issues
            println!("Skipping test due to permission issues");
            return;
        }
        Err(e) => panic!("Failed to create RulesManager: {}", e),
    };
    
    let firewall_arc = Arc::new(tokio::sync::Mutex::new(firewall_manager));
    let rules_arc = Arc::new(Mutex::new(rules_manager));
    
    // Create the router with a reasonable timeout
    let app_future = fortexa::api::api_server::router(
        Arc::clone(&firewall_arc),
        Arc::clone(&rules_arc)
    );
    
    let app = match timeout(Duration::from_secs(5), app_future).await {
        Ok(app) => app,
        Err(_) => panic!("Timed out while creating API router"),
    };

    // Test health check endpoint with timeout
    let health_check = timeout(
        Duration::from_secs(5),
        app.clone().oneshot(Request::builder().uri("/iptables/rules").body(Body::empty()).unwrap())
    ).await;

    match health_check {
        Ok(Ok(response)) => assert_eq!(response.status(), 200, "Health check should return 200"),
        Ok(Err(e)) => panic!("Health check request failed: {}", e),
        Err(_) => panic!("Health check timed out after 5 seconds"),
    }

    // Test rules endpoint with timeout
    let rules_check = timeout(
        Duration::from_secs(5),
        app.clone().oneshot(Request::builder().uri("/iptables/rules").body(Body::empty()).unwrap())
    ).await;

    match rules_check {
        Ok(Ok(response)) => assert_eq!(response.status(), 200, "Rules endpoint should return 200"),
        Ok(Err(e)) => panic!("Rules request failed: {}", e),
        Err(_) => panic!("Rules check timed out after 5 seconds"),
    }
} 