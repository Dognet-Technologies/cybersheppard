// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Notification Service
// ============================================================================

use crate::db::postgresql::PostgresPool;
use reqwest::Client;
use serde_json::json;

#[derive(Clone)]
pub struct NotificationService {
    pg_pool: PostgresPool,
    http_client: Client,
}

#[derive(Debug, Clone)]
pub struct NotificationConfig {
    pub email_enabled: bool,
    pub email_recipients: Vec<String>,
    pub smtp_host: String,
    pub smtp_port: i32,
    pub smtp_user: String,
    pub smtp_password: Option<String>,
    pub smtp_from_email: String,

    pub slack_enabled: bool,
    pub slack_webhook_url: Option<String>,

    pub discord_enabled: bool,
    pub discord_webhook_url: Option<String>,
}

impl NotificationService {
    pub fn new(pg_pool: PostgresPool) -> Self {
        Self {
            pg_pool,
            http_client: Client::new(),
        }
    }

    /// Load notification configuration from database
    pub async fn load_config(&self) -> Result<NotificationConfig, sqlx::Error> {
        let row = sqlx::query!(
            r#"
            SELECT
                email_enabled, email_recipients, smtp_host, smtp_port,
                smtp_user, smtp_password, smtp_from_email,
                slack_enabled, slack_webhook_url,
                discord_enabled, discord_webhook_url
            FROM notification_config
            WHERE id = 1
            "#
        )
        .fetch_one(&self.pg_pool)
        .await?;

        let email_recipients: Vec<String> = row.email_recipients
            .as_ref()
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        Ok(NotificationConfig {
            email_enabled: row.email_enabled.unwrap_or(false),
            email_recipients,
            smtp_host: row.smtp_host.unwrap_or_else(|| "localhost".to_string()),
            smtp_port: row.smtp_port.unwrap_or(587),
            smtp_user: row.smtp_user.unwrap_or_else(|| "cybersheppard".to_string()),
            smtp_password: row.smtp_password,
            smtp_from_email: row.smtp_from_email.unwrap_or_else(|| "cybersheppard@localhost".to_string()),
            slack_enabled: row.slack_enabled.unwrap_or(false),
            slack_webhook_url: row.slack_webhook_url,
            discord_enabled: row.discord_enabled.unwrap_or(false),
            discord_webhook_url: row.discord_webhook_url,
        })
    }

    /// Send violation alert
    pub async fn send_violation_alert(
        &self,
        violation_id: i64,
        target_hostname: &str,
        metric_name: &str,
        severity: &str,
        details: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let config = self.load_config().await?;

        let subject = format!(
            "[{}] Compliance Violation: {}",
            severity.to_uppercase(),
            metric_name
        );

        let message = format!(
            "Target: {}\nMetric: {}\nSeverity: {}\n\nDetails:\n{}",
            target_hostname, metric_name, severity, details
        );

        // Send notifications based on configuration
        if config.email_enabled {
            self.send_email(&config, &subject, &message).await?;
        }

        if config.slack_enabled {
            if let Some(webhook_url) = &config.slack_webhook_url {
                self.send_slack(webhook_url, &subject, &message, severity).await?;
            }
        }

        if config.discord_enabled {
            if let Some(webhook_url) = &config.discord_webhook_url {
                self.send_discord(webhook_url, &subject, &message, severity).await?;
            }
        }

        // Log notification
        self.log_notification(
            "alert",
            severity,
            target_hostname,
            &subject,
            &message,
        )
        .await?;

        Ok(())
    }

    /// Send Email notification
    async fn send_email(
        &self,
        config: &NotificationConfig,
        subject: &str,
        body: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use lettre::transport::smtp::authentication::Credentials;
        use lettre::{Message, SmtpTransport, Transport};
        use lettre::message::header::ContentType;

        // Skip if no recipients
        if config.email_recipients.is_empty() {
            tracing::warn!("No email recipients configured, skipping email notification");
            return Ok(());
        }

        // Build SMTP transport
        let creds = Credentials::new(
            config.smtp_user.clone(),
            config.smtp_password.clone().unwrap_or_default(),
        );

        let mailer = SmtpTransport::relay(&config.smtp_host)?
            .credentials(creds)
            .port(config.smtp_port as u16)
            .build();

        // Send to all recipients
        for recipient in &config.email_recipients {
            let email = Message::builder()
                .from(config.smtp_from_email.parse()?)
                .to(recipient.parse()?)
                .subject(subject)
                .header(ContentType::TEXT_PLAIN)
                .body(body.to_string())?;

            match mailer.send(&email) {
                Ok(_) => {
                    tracing::info!("Email notification sent to {}: {}", recipient, subject);
                }
                Err(e) => {
                    tracing::error!("Failed to send email to {}: {:?}", recipient, e);
                    // Continue with other recipients even if one fails
                }
            }
        }

        Ok(())
    }

    /// Send Slack notification
    async fn send_slack(
        &self,
        webhook_url: &str,
        subject: &str,
        message: &str,
        severity: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let color = match severity {
            "critical" => "#DC2626",
            "high" => "#EA580C",
            "medium" => "#F59E0B",
            _ => "#6B7280",
        };

        let payload = json!({
            "attachments": [{
                "color": color,
                "title": subject,
                "text": message,
                "footer": "CyberSheppard MicroSIEM",
                "ts": chrono::Utc::now().timestamp()
            }]
        });

        self.http_client
            .post(webhook_url)
            .json(&payload)
            .send()
            .await?;

        tracing::info!("Slack notification sent: {}", subject);
        Ok(())
    }

    /// Send Discord notification
    async fn send_discord(
        &self,
        webhook_url: &str,
        subject: &str,
        message: &str,
        severity: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let color = match severity {
            "critical" => 14423100,  // Red
            "high" => 15761472,      // Orange
            "medium" => 16098851,    // Yellow
            _ => 7039851,            // Gray
        };

        let payload = json!({
            "embeds": [{
                "title": subject,
                "description": message,
                "color": color,
                "footer": {
                    "text": "CyberSheppard MicroSIEM"
                },
                "timestamp": chrono::Utc::now().to_rfc3339()
            }]
        });

        self.http_client
            .post(webhook_url)
            .json(&payload)
            .send()
            .await?;

        tracing::info!("Discord notification sent: {}", subject);
        Ok(())
    }

    /// Log notification to database
    async fn log_notification(
        &self,
        notification_type: &str,
        severity: &str,
        target_hostname: &str,
        subject: &str,
        message: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            INSERT INTO notification_logs
                (notification_type, alert_type, severity, target_hostname, subject, message, success)
            VALUES ($1, $2, $3, $4, $5, $6, true)
            "#,
            notification_type,
            "compliance_violation",
            severity,
            target_hostname,
            subject,
            message
        )
        .execute(&self.pg_pool)
        .await?;

        Ok(())
    }
}
