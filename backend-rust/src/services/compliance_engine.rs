// ============================================================================
// CYBERSHEPPARD - Compliance Engine Service
// ============================================================================

use sqlx::PgPool;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use bigdecimal::BigDecimal;

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct ComplianceFramework {
    pub id: i32,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub version: Option<String>,
    pub category: Option<String>,
    pub enabled: Option<bool>,  // Changed from bool
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct ComplianceAssessment {
    pub id: i32,
    pub target_id: i32,
    pub framework_id: i32,
    pub assessment_date: DateTime<Utc>,
    pub total_controls: i32,
    pub passed_controls: i32,
    pub failed_controls: i32,
    pub not_applicable: i32,
    pub compliance_score: Option<BigDecimal>,  // Changed from f32
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ComplianceOverview {
    pub target_id: i32,
    pub hostname: String,
    pub frameworks_assessed: i64,
    pub avg_compliance_score: Option<BigDecimal>,  // Changed from f32
    pub critical_violations: i64,
    pub high_violations: i64,
    pub last_assessment_date: Option<DateTime<Utc>>,
}

pub struct ComplianceEngine {
    pg_pool: PgPool,
}

impl ComplianceEngine {
    pub fn new(pg_pool: PgPool) -> Self {
        Self { pg_pool }
    }

    pub async fn get_frameworks(&self) -> Result<Vec<ComplianceFramework>, Box<dyn std::error::Error + Send + Sync>> {
        let frameworks = sqlx::query_as!(
            ComplianceFramework,
            r#"
            SELECT id, name, display_name, description, version, category, enabled
            FROM compliance_frameworks
            WHERE enabled = true
            ORDER BY category, display_name
            "#
        )
        .fetch_all(&self.pg_pool)
        .await?;

        Ok(frameworks)
    }

    pub async fn get_framework(&self, framework_id: i32) -> Result<ComplianceFramework, Box<dyn std::error::Error + Send + Sync>> {
        let framework = sqlx::query_as!(
            ComplianceFramework,
            r#"
            SELECT id, name, display_name, description, version, category, enabled
            FROM compliance_frameworks
            WHERE id = $1
            "#,
            framework_id
        )
        .fetch_one(&self.pg_pool)
        .await?;

        Ok(framework)
    }

    pub async fn get_target_assessments(&self, target_id: i32) -> Result<Vec<ComplianceAssessment>, Box<dyn std::error::Error + Send + Sync>> {
        let assessments = sqlx::query_as!(
            ComplianceAssessment,
            r#"
            SELECT
                id, target_id, framework_id, assessment_date,
                total_controls, passed_controls, failed_controls,
                not_applicable, compliance_score, status
            FROM compliance_assessments
            WHERE target_id = $1
            ORDER BY assessment_date DESC
            "#,
            target_id
        )
        .fetch_all(&self.pg_pool)
        .await?;

        Ok(assessments)
    }

    pub async fn get_compliance_overview(&self) -> Result<Vec<ComplianceOverview>, Box<dyn std::error::Error + Send + Sync>> {
        let overview = sqlx::query_as!(
            ComplianceOverview,
            r#"
            SELECT
                target_id,
                hostname,
                frameworks_assessed,
                avg_compliance_score,
                critical_violations,
                high_violations,
                last_assessment_date
            FROM target_compliance_overview
            ORDER BY avg_compliance_score ASC NULLS LAST, critical_violations DESC
            "#
        )
        .fetch_all(&self.pg_pool)
        .await?;

        Ok(overview)
    }

    pub async fn create_assessment(
        &self,
        target_id: i32,
        framework_id: i32,
        total_controls: i32,
    ) -> Result<i32, Box<dyn std::error::Error + Send + Sync>> {
        let result = sqlx::query!(
            r#"
            INSERT INTO compliance_assessments (
                target_id, framework_id, assessment_date,
                total_controls, passed_controls, failed_controls,
                not_applicable, status
            ) VALUES ($1, $2, NOW(), $3, 0, 0, 0, 'in_progress')
            RETURNING id
            "#,
            target_id,
            framework_id,
            total_controls
        )
        .fetch_one(&self.pg_pool)
        .await?;

        Ok(result.id)
    }

    pub async fn update_assessment_results(
        &self,
        assessment_id: i32,
        passed: i32,
        failed: i32,
        not_applicable: i32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        sqlx::query!(
            r#"
            UPDATE compliance_assessments
            SET
                passed_controls = $1,
                failed_controls = $2,
                not_applicable = $3,
                status = 'completed'
            WHERE id = $4
            "#,
            passed,
            failed,
            not_applicable,
            assessment_id
        )
        .execute(&self.pg_pool)
        .await?;

        Ok(())
    }

    pub async fn get_framework_summary(&self) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error + Send + Sync>> {
        let summary = sqlx::query!(
            r#"
            SELECT
                framework_id as id,
                framework_name,
                category,
                targets_assessed,
                avg_compliance_score,
                total_controls,
                automated_controls
            FROM framework_compliance_summary
            ORDER BY framework_name
            "#
        )
        .fetch_all(&self.pg_pool)
        .await?;

        let result: Vec<serde_json::Value> = summary
            .into_iter()
            .map(|row| {
                serde_json::json!({
                    "id": row.id,
                    "framework_name": row.framework_name,
                    "category": row.category,
                    "targets_assessed": row.targets_assessed,
                    "avg_compliance_score": row.avg_compliance_score,
                    "total_controls": row.total_controls,
                    "automated_controls": row.automated_controls,
                })
            })
            .collect();

        Ok(result)
    }
}
