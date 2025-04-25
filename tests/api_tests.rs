use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;
use fortexa::{
    api::api_server::router,
    firewall::iptables::{FirewallManager, IPTablesInterface, MockIPTablesInterface},
    rules::FirewallRuleSet
};
use std::sync::Arc;
use tokio::sync::Mutex;

// Helper to create mock firewall manager
fn create_mock_firewall() -> Arc<Mutex<FirewallManager<MockIPTablesInterface>>> {
    let mut mock_ipt = MockIPTablesInterface::new(false);
    
    // Mock expectations for basic initialization
    mock_ipt.expect_new_chain()
        .returning(|_, _| Ok(()));
    mock_ipt.expect_insert()
        .returning(|_, _, _, _| Ok(()));
    
    Arc::new(Mutex::new(
        FirewallManager::new("filter", false, mock_ipt).unwrap()
    ))
}

#[tokio::test]
async fn test_get_rules_empty() {
    let firewall = create_mock_firewall();
    let rules = Arc::new(Mutex::new(FirewallRuleSet::default()));
    
    let app = router(firewall, rules.clone());

    let response = app
        .oneshot(Request::builder().uri("/rules").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test] 
async fn test_append_rules() {
    let firewall = create_mock_firewall();
    let rules = Arc::new(Mutex::new(FirewallRuleSet::default()));
    let app = router(firewall, rules.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/rules/append")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{ "input": { "blocked_ips": ["192.168.1.100/32"] } }"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    
    // Verify rules were updated
    let locked_rules = rules.lock().await;
    assert_eq!(locked_rules.input.blocked_ips.len(), 1);
}

#[tokio::test]
async fn test_get_rules() {
    let firewall = create_mock_firewall();
    let mut initial_rules = FirewallRuleSet::default();
    initial_rules.input.blocked_ips.insert("10.0.0.0/24".parse().unwrap());
    let rules = Arc::new(Mutex::new(initial_rules));

    let app = router(firewall, rules.clone());

    let response = app
        .oneshot(Request::builder().uri("/rules").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    
}
