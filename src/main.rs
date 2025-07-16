use anyhow::Result;
use fortexa::core::engine::Engine;
use fortexa::modules::netshield::{self, NetshieldModule};
use fortexa::services::rest::RestService;
use log::info;
use std::sync::Arc;

const DEFAULT_CONFIG_PATH: &str = "/etc/fortexa/config.toml";

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    info!("Fortexa Firewall starting...");

    // Initialize the engine
    let engine = Arc::new(Engine::new(DEFAULT_CONFIG_PATH)?);

    // Register all modules
    engine.register_all_modules()?;

    // Apply rules from rules.json to iptables at startup
    engine.apply_rules()?;

    // Apply all Netshield rules at startup
    log::info!("[Startup] Applying all Netshield rules to eBPF/XDP map");
    let mut module = NetshieldModule::new();
    match netshield::apply_all_rules(&mut module) {
        Ok(_) => log::info!("[Startup] Netshield rules applied successfully."),
        Err(e) => log::error!("[Startup] Failed to apply Netshield rules: {}", e),
    }

    // Start services in foreground
    run_services(engine).await?;

    Ok(())
}

async fn run_services(engine: Arc<Engine>) -> Result<()> {
    // Start the REST API service
    let rest_service = RestService::new(engine.clone());
    let rest_handle =
        tokio::spawn(async move { rest_service.run(Box::pin(std::future::pending())).await });

    // Wait for the services to exit
    let _ = rest_handle.await?;

    Ok(())
}
