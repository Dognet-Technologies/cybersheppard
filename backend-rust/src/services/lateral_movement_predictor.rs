// ============================================================================
// Lateral Movement Predictor - Markov Chain & Bayesian Network
// ============================================================================

use anyhow::Result;
use chrono::{Duration, Utc};
use serde_json::json;
use sqlx::PgPool;
use std::collections::HashMap;
use tracing::info;
use uuid::Uuid;

use crate::utils::{BigDecimalExt, ToBigDecimal};

/// Markov Chain state transition matrix for lateral movement prediction
#[derive(Debug, Clone)]
pub struct MarkovChain {
    /// State transition probabilities: P[from_host][to_host] = probability
    transition_matrix: HashMap<String, HashMap<String, f64>>,
    /// State visit counts for learning
    state_counts: HashMap<String, usize>,
    /// Total observations
    total_observations: usize,
}

impl MarkovChain {
    pub fn new() -> Self {
        Self {
            transition_matrix: HashMap::new(),
            state_counts: HashMap::new(),
            total_observations: 0,
        }
    }

    /// Train the Markov Chain from historical lateral movement data
    pub async fn train_from_history(db: &PgPool, days: i32) -> Result<Self> {
        info!("Training Markov Chain from {} days of historical data", days);

        let rows = sqlx::query!(
            r#"
            WITH auth_sequences AS (
                SELECT
                    user_name,
                    source_host as from_host,
                    LEAD(source_host) OVER (PARTITION BY user_name ORDER BY timestamp) as to_host,
                    timestamp,
                    LEAD(timestamp) OVER (PARTITION BY user_name ORDER BY timestamp) as next_timestamp
                FROM security_events
                WHERE timestamp > NOW() - INTERVAL '1 day' * $1
                  AND event_category IN ('authentication', 'network')
                  AND user_name IS NOT NULL
                  AND source_host IS NOT NULL
            )
            SELECT
                from_host,
                to_host,
                COUNT(*) as transition_count
            FROM auth_sequences
            WHERE to_host IS NOT NULL
              AND from_host != to_host
              AND EXTRACT(EPOCH FROM (next_timestamp - timestamp)) < 3600
            GROUP BY from_host, to_host
            ORDER BY transition_count DESC
            "#,
            days as f64
        )
        .fetch_all(db)
        .await?;

        let mut chain = Self::new();

        // Build transition counts
        for row in rows {
            let from_host = row.from_host;
            let to_host = row.to_host.unwrap_or_else(|| "unknown".to_string());
            let count = row.transition_count.unwrap_or(0) as usize;

            chain.add_transition(&from_host, &to_host, count);
        }

        // Normalize to probabilities
        chain.normalize();

        info!(
            "Trained Markov Chain: {} states, {} transitions",
            chain.state_counts.len(),
            chain.total_observations
        );

        Ok(chain)
    }

    /// Add a transition observation
    fn add_transition(&mut self, from_host: &str, to_host: &str, count: usize) {
        *self.state_counts.entry(from_host.to_string()).or_insert(0) += count;

        self.transition_matrix
            .entry(from_host.to_string())
            .or_insert_with(HashMap::new)
            .entry(to_host.to_string())
            .and_modify(|c| *c += count as f64)
            .or_insert(count as f64);

        self.total_observations += count;
    }

    /// Normalize transition counts to probabilities
    fn normalize(&mut self) {
        for (from_host, transitions) in &mut self.transition_matrix {
            let total_transitions: f64 = transitions.values().sum();

            if total_transitions > 0.0 {
                for probability in transitions.values_mut() {
                    *probability /= total_transitions;
                }
            }
        }
    }

    /// Predict next k most likely hosts from current host
    pub fn predict_next_hosts(&self, current_host: &str, k: usize) -> Vec<(String, f64)> {
        if let Some(transitions) = self.transition_matrix.get(current_host) {
            let mut predictions: Vec<(String, f64)> = transitions
                .iter()
                .map(|(host, prob)| (host.clone(), *prob))
                .collect();

            // Sort by probability descending
            predictions.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

            // Return top k
            predictions.into_iter().take(k).collect()
        } else {
            vec![]
        }
    }

    /// Calculate probability of a specific path
    pub fn calculate_path_probability(&self, path: &[String]) -> f64 {
        if path.len() < 2 {
            return 0.0;
        }

        let mut probability = 1.0;

        for window in path.windows(2) {
            if let Some(transitions) = self.transition_matrix.get(&window[0]) {
                if let Some(prob) = transitions.get(&window[1]) {
                    probability *= prob;
                } else {
                    return 0.0; // Path impossible
                }
            } else {
                return 0.0; // Path impossible
            }
        }

        probability
    }

    /// Get transition probability from one host to another
    pub fn get_transition_probability(&self, from_host: &str, to_host: &str) -> f64 {
        self.transition_matrix
            .get(from_host)
            .and_then(|transitions| transitions.get(to_host))
            .copied()
            .unwrap_or(0.0)
    }
}

/// Lateral Movement Predictor Service
pub struct LateralMovementPredictor {
    db: PgPool,
    markov_chain: Option<MarkovChain>,
}

impl LateralMovementPredictor {
    pub fn new(db: PgPool) -> Self {
        Self {
            db,
            markov_chain: None,
        }
    }

    /// Initialize and train the predictor
    pub async fn initialize(&mut self, training_days: i32) -> Result<()> {
        info!("Initializing Lateral Movement Predictor");

        // Train Markov Chain
        let chain = MarkovChain::train_from_history(&self.db, training_days).await?;
        self.markov_chain = Some(chain);

        Ok(())
    }

    /// Predict lateral movement targets for a compromised host
    pub async fn predict_lateral_movement(
        &self,
        correlation_id: Uuid,
        current_host: &str,
        current_user: Option<&str>,
        attack_stage: &str,
    ) -> Result<Vec<LateralMovementTarget>> {
        let chain = self.markov_chain.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Markov Chain not initialized"))?;

        info!("Predicting lateral movement from host: {}", current_host);

        // Get top 5 most likely next targets
        let predictions = chain.predict_next_hosts(current_host, 5);

        let mut targets = Vec::new();

        for (target_host, probability) in predictions {
            // Get target host information
            let host_info = self.get_host_info(&target_host).await?;

            // Calculate risk score
            let risk_score = self.calculate_target_risk_score(
                probability,
                host_info.criticality,
                host_info.is_server,
            );

            // Estimate timeframe based on historical data
            let timeframe_minutes = self.estimate_timeframe(current_host, &target_host).await?;

            // Generate reasoning
            let reasoning = self.generate_reasoning(
                &target_host,
                probability,
                &host_info,
            );

            // Generate recommended actions
            let recommended_actions = self.generate_recommended_actions(
                &target_host,
                risk_score,
                &host_info,
            );

            targets.push(LateralMovementTarget {
                action: "lateral_movement".to_string(),
                target_host: target_host.clone(),
                target_ip: host_info.ip,
                probability,
                timeframe_minutes,
                risk_score,
                reasoning,
                recommended_actions,
                criticality: host_info.criticality,
                is_server: host_info.is_server,
                typical_services: host_info.typical_services,
            });
        }

        // Sort by risk score
        targets.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap());

        // Save predictions to database
        self.save_predictions(correlation_id, current_host, current_user, attack_stage, &targets).await?;

        Ok(targets)
    }

    /// Calculate risk score for a target
    fn calculate_target_risk_score(
        &self,
        probability: f64,
        criticality: i32,
        is_server: bool,
    ) -> f64 {
        let mut risk_score = probability * 100.0;

        // Increase risk for critical assets
        risk_score += criticality as f64 * 5.0;

        // Increase risk for servers
        if is_server {
            risk_score += 20.0;
        }

        risk_score.min(100.0)
    }

    /// Get host information
    async fn get_host_info(&self, host_name: &str) -> Result<HostInfo> {
        let row = sqlx::query!(
            r#"
            SELECT
                h.host_name,
                h.asset_criticality,
                h.is_server,
                h.expected_services,
                t.ip_address as "ip_address?"
            FROM host_behavior_baselines h
            LEFT JOIN targets t ON t.hostname = h.host_name OR t.ip_address::TEXT = h.host_name
            WHERE h.host_name = $1
            LIMIT 1
            "#,
            host_name
        )
        .fetch_optional(&self.db)
        .await?;

        if let Some(row) = row {
            Ok(HostInfo {
                host_name: row.host_name,
                ip: row.ip_address.map(|n| n.ip().to_string()),
                criticality: row.asset_criticality.unwrap_or(5),
                is_server: row.is_server.unwrap_or(false),
                typical_services: row.expected_services.unwrap_or_default(),
            })
        } else {
            // Default if not found
            Ok(HostInfo {
                host_name: host_name.to_string(),
                ip: None,
                criticality: 5,
                is_server: false,
                typical_services: vec![],
            })
        }
    }

    /// Estimate timeframe for lateral movement
    async fn estimate_timeframe(&self, from_host: &str, to_host: &str) -> Result<i32> {
        let row = sqlx::query!(
            r#"
            SELECT AVG(EXTRACT(EPOCH FROM time_diff)) / 60 as avg_minutes
            FROM (
                SELECT
                    timestamp - LAG(timestamp) OVER (PARTITION BY user_name ORDER BY timestamp) as time_diff
                FROM security_events
                WHERE source_host IN ($1, $2)
                  AND timestamp > NOW() - INTERVAL '30 days'
                  AND event_category IN ('authentication', 'network')
                LIMIT 100
            ) time_diffs
            WHERE time_diff IS NOT NULL
            "#,
            from_host,
            to_host
        )
        .fetch_one(&self.db)
        .await?;

        Ok(row.avg_minutes.map(|d| d.to_f64()).unwrap_or(30.0) as i32)
    }

    /// Generate reasoning text
    fn generate_reasoning(
        &self,
        target_host: &str,
        probability: f64,
        info: &HostInfo,
    ) -> String {
        let mut reasons = Vec::new();

        reasons.push(format!(
            "Historical pattern shows {:.1}% probability of movement to {}",
            probability * 100.0,
            target_host
        ));

        if info.is_server {
            reasons.push("Target is a server (high value)".to_string());
        }

        if info.criticality >= 7 {
            reasons.push(format!(
                "Critical asset (criticality: {})",
                info.criticality
            ));
        }

        if !info.typical_services.is_empty() {
            reasons.push(format!(
                "Running services: {}",
                info.typical_services.join(", ")
            ));
        }

        reasons.join("; ")
    }

    /// Generate recommended actions
    fn generate_recommended_actions(
        &self,
        target_host: &str,
        risk_score: f64,
        info: &HostInfo,
    ) -> Vec<String> {
        let mut actions = Vec::new();

        if risk_score > 70.0 {
            actions.push(format!("Isolate {} from network immediately", target_host));
            actions.push("Enable enhanced monitoring".to_string());
        }

        actions.push(format!("Monitor all connections to {}", target_host));

        if info.is_server {
            actions.push("Review and restrict server access".to_string());
            actions.push("Enable MFA for all admin accounts".to_string());
        }

        actions.push("Review firewall rules".to_string());
        actions.push("Check for unauthorized accounts".to_string());

        actions
    }

    /// Save predictions to database
    async fn save_predictions(
        &self,
        correlation_id: Uuid,
        current_host: &str,
        current_user: Option<&str>,
        attack_stage: &str,
        targets: &[LateralMovementTarget],
    ) -> Result<()> {
        let predictions_json = serde_json::to_value(targets)?;

        sqlx::query!(
            r#"
            INSERT INTO lateral_movement_predictions (
                correlation_id,
                current_compromised_host,
                current_compromised_user,
                current_attack_stage,
                predictions,
                model_name,
                model_version,
                model_confidence,
                status,
                expires_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
            )
            "#,
            correlation_id,
            current_host,
            current_user,
            attack_stage,
            predictions_json,
            "markov_chain",
            "1.0",
            (if targets.is_empty() { 0.0 } else { targets[0].probability }).to_bigdecimal(),
            "active",
            Utc::now() + Duration::hours(24)
        )
        .execute(&self.db)
        .await?;

        info!(
            "Saved {} lateral movement predictions for host {}",
            targets.len(),
            current_host
        );

        Ok(())
    }

    /// Get active predictions
    pub async fn get_active_predictions(&self, limit: i64) -> Result<Vec<serde_json::Value>> {
        let rows = sqlx::query!(
            r#"
            SELECT
                id,
                correlation_id,
                current_compromised_host,
                current_compromised_user,
                current_attack_stage,
                predictions,
                model_confidence,
                created_at,
                expires_at
            FROM lateral_movement_predictions
            WHERE status = 'active'
              AND expires_at > NOW()
            ORDER BY model_confidence DESC, created_at DESC
            LIMIT $1
            "#,
            limit
        )
        .fetch_all(&self.db)
        .await?;

        let predictions = rows
            .into_iter()
            .map(|row| {
                json!({
                    "id": row.id,
                    "correlation_id": row.correlation_id,
                    "current_host": row.current_compromised_host,
                    "current_user": row.current_compromised_user,
                    "attack_stage": row.current_attack_stage,
                    "predictions": row.predictions,
                    "confidence": row.model_confidence,
                    "created_at": row.created_at,
                    "expires_at": row.expires_at,
                })
            })
            .collect();

        Ok(predictions)
    }
}

/// Host information for prediction
#[derive(Debug, Clone)]
struct HostInfo {
    host_name: String,
    ip: Option<String>,
    criticality: i32,
    is_server: bool,
    typical_services: Vec<String>,
}

/// Lateral movement target prediction
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LateralMovementTarget {
    pub action: String,
    pub target_host: String,
    pub target_ip: Option<String>,
    pub probability: f64,
    pub timeframe_minutes: i32,
    pub risk_score: f64,
    pub reasoning: String,
    pub recommended_actions: Vec<String>,
    pub criticality: i32,
    pub is_server: bool,
    pub typical_services: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_markov_chain_prediction() {
        let mut chain = MarkovChain::new();

        // Add transitions: A -> B (3 times), A -> C (1 time), B -> C (2 times)
        chain.add_transition("A", "B", 3);
        chain.add_transition("A", "C", 1);
        chain.add_transition("B", "C", 2);
        chain.normalize();

        // Predict from A
        let predictions = chain.predict_next_hosts("A", 2);
        assert_eq!(predictions.len(), 2);
        assert_eq!(predictions[0].0, "B");
        assert!((predictions[0].1 - 0.75).abs() < 0.01); // 3/4 = 0.75

        // Path probability
        let path = vec!["A".to_string(), "B".to_string(), "C".to_string()];
        let prob = chain.calculate_path_probability(&path);
        assert!(prob > 0.0);
    }
}
