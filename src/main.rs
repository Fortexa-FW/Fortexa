use anyhow::Result;
use fortexa::core::engine::Engine;
use fortexa::services::rest::RestService;
use log::info;
use std::sync::Arc;

const DEFAULT_CONFIG_PATH: &str = "/etc/fortexa/config.toml";

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    info!("Fortexa Firewall starting...");
    log::debug!("[DEBUG] Environment logger initialized");

    // Initialize the engine
    log::debug!(
        "[DEBUG] Initializing engine with config: {}",
        DEFAULT_CONFIG_PATH
    );
    let engine = Arc::new(Engine::new(DEFAULT_CONFIG_PATH)?);
    log::info!("[DEBUG] Engine initialized successfully");

    // Register all modules
    log::debug!("[DEBUG] Starting module registration...");
    engine.register_all_modules()?;
    log::info!("[DEBUG] All modules registered successfully");

    // Apply rules from rules.json to iptables and netshield at startup
    log::debug!("[DEBUG] Starting rule application...");
    engine.apply_rules()?;
    log::info!("[DEBUG] Rules applied successfully");

    // Start services in foreground
    log::debug!("[DEBUG] Starting services...");
    run_services(engine).await?;

    log::info!("[DEBUG] Fortexa Firewall shutting down");
    Ok(())
}

async fn run_services(engine: Arc<Engine>) -> Result<()> {
    log::debug!("[DEBUG] Creating REST API service...");

    // Start the REST API service
    let rest_service = RestService::new(engine.clone());
    log::info!("[DEBUG] REST API service created successfully");

    log::debug!("[DEBUG] Spawning REST API service task...");
    let rest_handle = tokio::spawn(async move {
        log::debug!("[DEBUG] REST API service task started");
        let result = rest_service.run(Box::pin(std::future::pending())).await;
        log::debug!(
            "[DEBUG] REST API service task completed with result: {:?}",
            result
        );
        result
    });
    log::info!("[DEBUG] REST API service task spawned");

    // Wait for the services to exit
    log::debug!("[DEBUG] Waiting for services to complete...");
    rest_handle.await??; // Use ?? to handle both the JoinError and the inner Result
    log::info!("[DEBUG] All services completed");

    Ok(())
}
