use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use crate::config::DatabaseConfig;
use crate::error::Result;

/// Create a connection pool from config.
pub async fn connect(config: &DatabaseConfig) -> Result<PgPool> {
    let url = config.url.resolve()?;
    let pool = PgPoolOptions::new()
        .max_connections(config.max_connections)
        .connect(&url)
        .await?;
    Ok(pool)
}

/// Run embedded migrations.
pub async fn migrate(pool: &PgPool) -> Result<()> {
    sqlx::migrate!("../../migrations").run(pool).await?;
    Ok(())
}
