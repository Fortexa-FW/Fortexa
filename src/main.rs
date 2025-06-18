use anyhow::Result;
use fortexa::core::engine::Engine;
use fortexa::services::rest::RestService;
use log::info;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    info!("Fortexa Firewall starting...");

    // Initialize the engine
    let engine = Engine::new("/etc/fortexa/config.toml")?;

    // Register all modules
    engine.register_all_modules()?;

    // Start services in foreground
    run_services(engine).await?;

    Ok(())
}

async fn run_services(engine: Engine) -> Result<()> {
    // Start the REST API service
    let rest_service = RestService::new(engine.clone());
    let rest_handle = tokio::spawn(async move { rest_service.run().await });

    // Wait for the services to exit
    let _ = rest_handle.await?;

    Ok(())
}
