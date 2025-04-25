use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use fortexa::{
    api::api_server::router,
    firewall::iptables::{FirewallManager, IPTablesInterface, IPTablesWrapper},
    rules::FirewallRuleSet,
};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;

struct TestEnvironment {
    _chain: TestChain,
    firewall: Arc<Mutex<FirewallManager<IPTablesWrapper>>>,
    rules: Arc<Mutex<FirewallRuleSet>>,
}

impl TestEnvironment {
    async fn new(table: &str, chain: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let test_chain = TestChain::new(table, chain)?;
        let ipt = IPTablesWrapper::new(false)?;
        let firewall = Arc::new(Mutex::new(
            FirewallManager::new(table, false, ipt)?.chain(chain)?,
        ));
        let rules = Arc::new(Mutex::new(FirewallRuleSet::default()));

        Ok(Self {
            _chain: test_chain,
            firewall,
            rules,
        })
    }

    async fn app(&self) -> axum::Router {
        router(self.firewall.clone(), self.rules.clone())
    }
}

#[tokio::test]
#[ignore = "requires iptables access and root privileges"]
async fn test_get_rules_empty() -> Result<(), Box<dyn std::error::Error>> {
    let env = TestEnvironment::new("filter", "fortexa_api_empty_test").await?;

    let response = env
        .app()
        .await
        .oneshot(Request::builder().uri("/rules").body(Body::empty())?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    // Verify actual firewall state
    let firewall = env.firewall.lock().await;
    let current_rules = firewall.list_rules()?;
    assert!(current_rules.is_empty(), "Firewall should have no rules");

    Ok(())
}

#[tokio::test]
#[ignore = "requires iptables access and root privileges"]
async fn test_append_rules() -> Result<(), Box<dyn std::error::Error>> {
    let env = TestEnvironment::new("filter", "fortexa_api_append_test").await?;

    let response = env
        .app()
        .await
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/rules/append")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{ "input": { "blocked_ips": ["192.168.1.100/32"] } }"#,
                ))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    // Verify in-memory rules
    let locked_rules = env.rules.lock().await;
    assert_eq!(locked_rules.input.blocked_ips.len(), 1);

    // Verify actual firewall rules
    let firewall = env.firewall.lock().await;
    let current_rules = firewall.list_rules()?;
    assert!(
        current_rules.iter().any(|r| r.contains("192.168.1.100/32")),
        "Firewall should contain block rule"
    );

    Ok(())
}

#[tokio::test]
#[ignore = "requires iptables access and root privileges"]
async fn test_get_rules() -> Result<(), Box<dyn std::error::Error>> {
    let env = TestEnvironment::new("filter", "fortexa_api_get_test").await?;

    // Set initial rules
    let mut initial_rules = FirewallRuleSet::default();
    initial_rules
        .input
        .blocked_ips
        .insert("10.0.0.0/24".parse()?);
    *env.rules.lock().await = initial_rules.clone();

    let response = env
        .app()
        .await
        .oneshot(Request::builder().uri("/rules").body(Body::empty())?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    // Verify response body contains the rules
    let body = to_bytes(response.into_body()).await?;
    let response_rules: FirewallRuleSet = serde_json::from_slice(&body)?;
    assert_eq!(
        response_rules.input.blocked_ips,
        initial_rules.input.blocked_ips
    );

    Ok(())
}

// Reuse TestChain implementation from previous examples
