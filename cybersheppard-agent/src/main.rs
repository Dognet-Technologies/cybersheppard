// ============================================================================
// CyberSheppard Agent - Main Entry Point
// ============================================================================

mod collectors;
mod commands;
mod compression;
mod config;
mod connection;

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info};

use crate::config::AgentConfig;
use crate::connection::AgentConnection;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into())
        )
        .init();

    info!("CyberSheppard Agent v{} starting...", env!("CARGO_PKG_VERSION"));

    // Parse command line arguments
    let config_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(AgentConfig::default_path);

    // Load configuration
    let config = AgentConfig::load(&config_path)
        .with_context(|| format!("Failed to load configuration from {:?}", config_path))?;

    info!(
        "Configuration loaded: backend={}, target_id={}, collection_interval={}s",
        config.backend_url,
        config.target_id,
        config.collection_interval
    );

    // Create agent connection
    let connection = Arc::new(Mutex::new(
        AgentConnection::new(config.clone())
    ));

    // Run agent (with auto-reconnect)
    loop {
        match run_agent(Arc::clone(&connection)).await {
            Ok(_) => {
                info!("Agent stopped gracefully");
                break;
            }
            Err(e) => {
                error!("Agent error: {:#}", e);
                info!("Restarting agent in 5 seconds...");
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        }
    }

    Ok(())
}

async fn run_agent(connection: Arc<Mutex<AgentConnection>>) -> Result<()> {
    // Connect to backend
    {
        let mut conn = connection.lock().await;
        conn.connect().await?;
    }

    info!("Connected to backend, starting collection loops");

    // Spawn collection and send loops
    let collection_handle = {
        let connection = Arc::clone(&connection);
        tokio::spawn(async move {
            collection_loop(connection).await
        })
    };

    let send_handle = {
        let connection = Arc::clone(&connection);
        tokio::spawn(async move {
            send_loop(connection).await
        })
    };

    let health_handle = {
        let connection = Arc::clone(&connection);
        tokio::spawn(async move {
            health_check_loop(connection).await
        })
    };

    let command_handle = {
        let connection = Arc::clone(&connection);
        tokio::spawn(async move {
            command_receive_loop(connection).await
        })
    };

    // Wait for any task to complete (or error)
    tokio::select! {
        res = collection_handle => {
            error!("Collection loop ended: {:?}", res);
        }
        res = send_handle => {
            error!("Send loop ended: {:?}", res);
        }
        res = health_handle => {
            error!("Health check loop ended: {:?}", res);
        }
        res = command_handle => {
            error!("Command loop ended: {:?}", res);
        }
    }

    Ok(())
}

async fn collection_loop(connection: Arc<Mutex<AgentConnection>>) -> Result<()> {
    let config = connection.lock().await.config.clone();
    let mut interval = tokio::time::interval(
        tokio::time::Duration::from_secs(config.collection_interval)
    );

    loop {
        interval.tick().await;

        info!("Starting metrics collection");

        match collectors::collect_all(&config).await {
            Ok(metrics) => {
                let mut conn = connection.lock().await;
                conn.buffer_metrics(metrics);
                info!("Metrics collected and buffered");
            }
            Err(e) => {
                error!("Collection error: {:#}", e);
            }
        }
    }
}

async fn send_loop(connection: Arc<Mutex<AgentConnection>>) -> Result<()> {
    let config = connection.lock().await.config.clone();
    let mut interval = tokio::time::interval(
        tokio::time::Duration::from_secs(config.send_interval)
    );

    loop {
        interval.tick().await;

        let mut conn = connection.lock().await;

        if conn.buffer_size() > 0 {
            info!("Sending buffered metrics (count: {})", conn.buffer_size());

            match conn.send_buffered().await {
                Ok(_) => {
                    info!("Metrics sent successfully");
                }
                Err(e) => {
                    error!("Send error: {:#}", e);
                }
            }
        }
    }
}

async fn health_check_loop(connection: Arc<Mutex<AgentConnection>>) -> Result<()> {
    let mut interval = tokio::time::interval(
        tokio::time::Duration::from_secs(60)
    );

    loop {
        interval.tick().await;

        let conn = connection.lock().await;

        if !conn.is_connected() {
            error!("Connection lost, triggering reconnect");
            drop(conn);

            // Try to reconnect
            let mut conn = connection.lock().await;
            if let Err(e) = conn.reconnect().await {
                error!("Reconnection failed: {:#}", e);
            }
        } else {
            info!("Health check: OK");
        }
    }
}

async fn command_receive_loop(connection: Arc<Mutex<AgentConnection>>) -> Result<()> {
    loop {
        let mut conn = connection.lock().await;

        if !conn.is_connected() {
            drop(conn);
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            continue;
        }

        // Handle incoming commands
        match conn.handle_commands().await {
            Ok(_) => {
                info!("Command handler returned normally");
            }
            Err(e) => {
                error!("Command handler error: {:#}", e);
            }
        }

        drop(conn);
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}
