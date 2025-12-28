// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - PostgreSQL Connection
// ============================================================================

use sqlx::{postgres::PgPoolOptions, PgPool};
use std::time::Duration;

pub type PostgresPool = PgPool;

/// Initialize PostgreSQL connection pool
pub async fn init_pool() -> Result<PostgresPool, sqlx::Error> {
    let database_url = get_database_url();

    let pool = PgPoolOptions::new()
        .max_connections(20)
        .min_connections(5)
        .acquire_timeout(Duration::from_secs(10))
        .idle_timeout(Duration::from_secs(600))
        .max_lifetime(Duration::from_secs(1800))
        .connect(&database_url)
        .await?;

    tracing::info!("🐘 PostgreSQL connection pool created");

    // Run pending migrations
    run_migrations(&pool).await?;

    Ok(pool)
}

/// Get database URL from environment variables
fn get_database_url() -> String {
    let host = std::env::var("POSTGRES_HOST").unwrap_or_else(|_| "localhost".to_string());
    let port = std::env::var("POSTGRES_PORT").unwrap_or_else(|_| "5432".to_string());
    let user = std::env::var("POSTGRES_USER").unwrap_or_else(|_| "cybersheppard".to_string());
    let password = std::env::var("POSTGRES_PASSWORD").expect("POSTGRES_PASSWORD must be set");
    let database = std::env::var("POSTGRES_DB").unwrap_or_else(|_| "cybersheppard".to_string());

    format!(
        "postgres://{}:{}@{}:{}/{}",
        user, password, host, port, database
    )
}

/// Run database migrations
async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::Error> {
    tracing::info!("🔄 Running database migrations...");

    sqlx::migrate!("./migrations")
        .run(pool)
        .await?;

    tracing::info!("✅ Migrations completed");

    Ok(())
}
