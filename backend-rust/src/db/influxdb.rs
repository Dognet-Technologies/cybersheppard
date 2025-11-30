// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - InfluxDB Connection
// ============================================================================

use influxdb::{Client, InfluxDbWriteable};

#[derive(Clone)]
pub struct InfluxDbClient {
    pub client: Client,
    pub bucket_metrics: String,
    pub bucket_logs: String,
    pub bucket_correlations: String,
}

impl InfluxDbClient {
    /// Initialize InfluxDB client
    pub async fn init() -> Result<Self, Box<dyn std::error::Error>> {
        let url = std::env::var("INFLUXDB_URL").unwrap_or_else(|_| "http://localhost:8086".to_string());
        let token = std::env::var("INFLUXDB_TOKEN").expect("INFLUXDB_TOKEN must be set");
        let org = std::env::var("INFLUXDB_ORG").unwrap_or_else(|_| "cybersheppard".to_string());

        let bucket_metrics = std::env::var("INFLUXDB_BUCKET_METRICS")
            .unwrap_or_else(|_| "metrics".to_string());
        let bucket_logs = std::env::var("INFLUXDB_BUCKET_LOGS")
            .unwrap_or_else(|_| "logs".to_string());
        let bucket_correlations = std::env::var("INFLUXDB_BUCKET_CORRELATIONS")
            .unwrap_or_else(|_| "correlations".to_string());

        let client = Client::new(url, &org).with_token(&token);

        // Test connection
        client.ping().await?;

        tracing::info!("📊 InfluxDB connection established");

        Ok(Self {
            client,
            bucket_metrics,
            bucket_logs,
            bucket_correlations,
        })
    }

    /// Write metrics to InfluxDB
    pub async fn write_metrics<T: InfluxDbWriteable>(
        &self,
        data: T,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.client
            .query(&data.into_query(&self.bucket_metrics))
            .await?;
        Ok(())
    }

    /// Write logs to InfluxDB
    pub async fn write_logs<T: InfluxDbWriteable>(
        &self,
        data: T,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.client
            .query(&data.into_query(&self.bucket_logs))
            .await?;
        Ok(())
    }

    /// Write correlations to InfluxDB
    pub async fn write_correlations<T: InfluxDbWriteable>(
        &self,
        data: T,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.client
            .query(&data.into_query(&self.bucket_correlations))
            .await?;
        Ok(())
    }
}

/// Convenience function to initialize client
pub async fn init_client() -> Result<InfluxDbClient, Box<dyn std::error::Error>> {
    InfluxDbClient::init().await
}
