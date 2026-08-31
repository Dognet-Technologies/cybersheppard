// ============================================================================
// Bayesian Network - Probabilistic Causal Inference for Attack Chains
// ============================================================================

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use tracing::{debug, info};
use uuid::Uuid;

use crate::utils::{BigDecimalExt, ToBigDecimal};

/// Bayesian Network node representing an event type or condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BayesianNode {
    /// Node identifier (event type, condition, etc.)
    pub node_id: String,
    /// Node label for display
    pub label: String,
    /// Parent nodes (causes)
    pub parents: Vec<String>,
    /// Child nodes (effects)
    pub children: Vec<String>,
    /// Prior probability P(node)
    pub prior_probability: f64,
    /// Conditional probability table: P(node | parents)
    /// Key: parent state combination, Value: probability
    pub cpt: HashMap<String, f64>,
    /// Current belief (posterior probability)
    pub belief: f64,
    /// Evidence observed for this node
    pub evidence: Option<bool>,
}

impl BayesianNode {
    pub fn new(node_id: String, label: String, prior_probability: f64) -> Self {
        Self {
            node_id,
            label,
            parents: Vec::new(),
            children: Vec::new(),
            prior_probability,
            cpt: HashMap::new(),
            belief: prior_probability,
            evidence: None,
        }
    }

    /// Add parent node
    pub fn add_parent(&mut self, parent_id: String) {
        if !self.parents.contains(&parent_id) {
            self.parents.push(parent_id);
        }
    }

    /// Add child node
    pub fn add_child(&mut self, child_id: String) {
        if !self.children.contains(&child_id) {
            self.children.push(child_id);
        }
    }

    /// Set conditional probability P(node=true | parent_states)
    pub fn set_conditional_probability(&mut self, parent_states: &str, probability: f64) {
        self.cpt.insert(parent_states.to_string(), probability);
    }

    /// Get conditional probability given parent states
    pub fn get_conditional_probability(&self, parent_states: &str) -> f64 {
        self.cpt.get(parent_states).copied().unwrap_or(self.prior_probability)
    }
}

/// Bayesian Network for causal inference
pub struct BayesianNetwork {
    /// Network nodes indexed by node_id
    nodes: HashMap<String, BayesianNode>,
    /// Topological order for inference (parents before children)
    topological_order: Vec<String>,
}

impl BayesianNetwork {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            topological_order: Vec::new(),
        }
    }

    /// Build attack chain Bayesian Network
    pub fn build_attack_chain_network() -> Self {
        let mut network = Self::new();

        // Define attack chain nodes with prior probabilities

        // Initial Access
        let initial_access = BayesianNode::new(
            "initial_access".to_string(),
            "Initial Access Achieved".to_string(),
            0.05, // 5% prior probability
        );
        network.add_node(initial_access.clone());

        // Reconnaissance
        let reconnaissance = BayesianNode::new(
            "reconnaissance".to_string(),
            "Reconnaissance Activity".to_string(),
            0.10,
        );
        network.add_node(reconnaissance.clone());

        // Credential Access
        let mut credential_access = BayesianNode::new(
            "credential_access".to_string(),
            "Credential Access Attempt".to_string(),
            0.08,
        );
        credential_access.add_parent("initial_access".to_string());
        // P(credential_access | initial_access=true) = 0.7
        credential_access.set_conditional_probability("T", 0.7);
        // P(credential_access | initial_access=false) = 0.02
        credential_access.set_conditional_probability("F", 0.02);
        network.add_node(credential_access.clone());

        // Lateral Movement
        let mut lateral_movement = BayesianNode::new(
            "lateral_movement".to_string(),
            "Lateral Movement Detected".to_string(),
            0.03,
        );
        lateral_movement.add_parent("credential_access".to_string());
        lateral_movement.add_parent("reconnaissance".to_string());
        // P(lateral_movement | credential_access=T, reconnaissance=T) = 0.9
        lateral_movement.set_conditional_probability("TT", 0.9);
        // P(lateral_movement | credential_access=T, reconnaissance=F) = 0.5
        lateral_movement.set_conditional_probability("TF", 0.5);
        // P(lateral_movement | credential_access=F, reconnaissance=T) = 0.3
        lateral_movement.set_conditional_probability("FT", 0.3);
        // P(lateral_movement | credential_access=F, reconnaissance=F) = 0.01
        lateral_movement.set_conditional_probability("FF", 0.01);
        network.add_node(lateral_movement.clone());

        // Privilege Escalation
        let mut privilege_escalation = BayesianNode::new(
            "privilege_escalation".to_string(),
            "Privilege Escalation".to_string(),
            0.04,
        );
        privilege_escalation.add_parent("credential_access".to_string());
        privilege_escalation.set_conditional_probability("T", 0.6);
        privilege_escalation.set_conditional_probability("F", 0.01);
        network.add_node(privilege_escalation.clone());

        // Data Exfiltration
        let mut data_exfiltration = BayesianNode::new(
            "data_exfiltration".to_string(),
            "Data Exfiltration".to_string(),
            0.02,
        );
        data_exfiltration.add_parent("lateral_movement".to_string());
        data_exfiltration.add_parent("privilege_escalation".to_string());
        // P(exfiltration | lateral_movement=T, privilege_escalation=T) = 0.8
        data_exfiltration.set_conditional_probability("TT", 0.8);
        data_exfiltration.set_conditional_probability("TF", 0.4);
        data_exfiltration.set_conditional_probability("FT", 0.3);
        data_exfiltration.set_conditional_probability("FF", 0.005);
        network.add_node(data_exfiltration.clone());

        // Persistence
        let mut persistence = BayesianNode::new(
            "persistence".to_string(),
            "Persistence Established".to_string(),
            0.03,
        );
        persistence.add_parent("privilege_escalation".to_string());
        persistence.set_conditional_probability("T", 0.7);
        persistence.set_conditional_probability("F", 0.01);
        network.add_node(persistence.clone());

        // Command & Control
        let mut command_control = BayesianNode::new(
            "command_control".to_string(),
            "C2 Communication".to_string(),
            0.04,
        );
        command_control.add_parent("initial_access".to_string());
        command_control.set_conditional_probability("T", 0.8);
        command_control.set_conditional_probability("F", 0.01);
        network.add_node(command_control.clone());

        // Update parent-child relationships
        network.update_parent_child_relationships();

        // Compute topological order
        network.compute_topological_order();

        network
    }

    /// Add node to network
    pub fn add_node(&mut self, node: BayesianNode) {
        self.nodes.insert(node.node_id.clone(), node);
    }

    /// Update parent-child relationships
    fn update_parent_child_relationships(&mut self) {
        let mut parent_child_map: HashMap<String, Vec<String>> = HashMap::new();

        for (node_id, node) in &self.nodes {
            for parent_id in &node.parents {
                parent_child_map
                    .entry(parent_id.clone())
                    .or_insert_with(Vec::new)
                    .push(node_id.clone());
            }
        }

        for (parent_id, children) in parent_child_map {
            if let Some(parent_node) = self.nodes.get_mut(&parent_id) {
                parent_node.children = children;
            }
        }
    }

    /// Compute topological order using Kahn's algorithm
    fn compute_topological_order(&mut self) {
        let mut in_degree: HashMap<String, usize> = HashMap::new();
        let mut queue = Vec::new();

        // Calculate in-degrees
        for node_id in self.nodes.keys() {
            in_degree.insert(node_id.clone(), 0);
        }

        for node in self.nodes.values() {
            for child_id in &node.children {
                *in_degree.get_mut(child_id).unwrap() += 1;
            }
        }

        // Find nodes with no incoming edges
        for (node_id, &degree) in &in_degree {
            if degree == 0 {
                queue.push(node_id.clone());
            }
        }

        let mut order = Vec::new();

        while let Some(node_id) = queue.pop() {
            order.push(node_id.clone());

            if let Some(node) = self.nodes.get(&node_id) {
                for child_id in &node.children {
                    let degree = in_degree.get_mut(child_id).unwrap();
                    *degree -= 1;
                    if *degree == 0 {
                        queue.push(child_id.clone());
                    }
                }
            }
        }

        self.topological_order = order;
    }

    /// Set evidence for a node
    pub fn set_evidence(&mut self, node_id: &str, observed: bool) {
        if let Some(node) = self.nodes.get_mut(node_id) {
            node.evidence = Some(observed);
            debug!("Evidence set: {} = {}", node_id, observed);
        }
    }

    /// Clear all evidence
    pub fn clear_evidence(&mut self) {
        for node in self.nodes.values_mut() {
            node.evidence = None;
            node.belief = node.prior_probability;
        }
    }

    /// Perform belief propagation (simplified variable elimination)
    pub fn propagate_beliefs(&mut self) {
        info!("Propagating beliefs through Bayesian Network");

        // Forward pass: compute beliefs in topological order
        for node_id in self.topological_order.clone() {
            if let Some(node) = self.nodes.get(&node_id).cloned() {
                // If evidence is set, belief is 1.0 or 0.0
                if let Some(evidence) = node.evidence {
                    if let Some(node_mut) = self.nodes.get_mut(&node_id) {
                        node_mut.belief = if evidence { 1.0 } else { 0.0 };
                    }
                    continue;
                }

                // Calculate belief based on parent beliefs
                let belief = self.calculate_node_belief(&node);
                if let Some(node_mut) = self.nodes.get_mut(&node_id) {
                    node_mut.belief = belief;
                }
            }
        }

        // Normalize beliefs
        self.normalize_beliefs();
    }

    /// Calculate belief for a node given parent beliefs
    fn calculate_node_belief(&self, node: &BayesianNode) -> f64 {
        if node.parents.is_empty() {
            return node.prior_probability;
        }

        // Sum over all parent state combinations
        let mut total_probability = 0.0;
        let num_parents = node.parents.len();
        let num_combinations = 2_usize.pow(num_parents as u32);

        for i in 0..num_combinations {
            // Generate parent state combination
            let mut parent_states = String::new();
            let mut combination_prob = 1.0;

            for (j, parent_id) in node.parents.iter().enumerate() {
                let parent_state = (i >> j) & 1 == 1;
                parent_states.push(if parent_state { 'T' } else { 'F' });

                if let Some(parent_node) = self.nodes.get(parent_id) {
                    let parent_belief = parent_node.belief;
                    combination_prob *= if parent_state {
                        parent_belief
                    } else {
                        1.0 - parent_belief
                    };
                }
            }

            // P(node | parent_states) * P(parent_states)
            let conditional_prob = node.get_conditional_probability(&parent_states);
            total_probability += conditional_prob * combination_prob;
        }

        total_probability.clamp(0.0, 1.0)
    }

    /// Normalize beliefs (ensure they stay in [0, 1])
    fn normalize_beliefs(&mut self) {
        for node in self.nodes.values_mut() {
            node.belief = node.belief.clamp(0.0, 1.0);
        }
    }

    /// Query: What is the probability of a node given evidence?
    pub fn query(&mut self, node_id: &str) -> Option<f64> {
        self.propagate_beliefs();
        self.nodes.get(node_id).map(|node| node.belief)
    }

    /// Get most likely explanation (MAP - Maximum A Posteriori)
    pub fn get_most_likely_explanation(&mut self) -> HashMap<String, bool> {
        self.propagate_beliefs();

        self.nodes
            .iter()
            .map(|(node_id, node)| {
                (node_id.clone(), node.belief > 0.5)
            })
            .collect()
    }

    /// Get attack chain probability
    pub fn get_attack_chain_probability(&mut self, chain: &[&str]) -> f64 {
        let mut probability = 1.0;

        for node_id in chain {
            if let Some(belief) = self.query(node_id) {
                probability *= belief;
            }
        }

        probability
    }

    /// Get node information
    pub fn get_node(&self, node_id: &str) -> Option<&BayesianNode> {
        self.nodes.get(node_id)
    }

    /// Get all nodes sorted by belief
    pub fn get_nodes_by_belief(&mut self) -> Vec<(String, f64)> {
        self.propagate_beliefs();

        let mut nodes: Vec<(String, f64)> = self
            .nodes
            .iter()
            .map(|(id, node)| (id.clone(), node.belief))
            .collect();

        nodes.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        nodes
    }
}

/// Bayesian Network Service for attack inference
pub struct BayesianNetworkService {
    db: PgPool,
    network: BayesianNetwork,
}

impl BayesianNetworkService {
    pub fn new(db: PgPool) -> Self {
        let network = BayesianNetwork::build_attack_chain_network();

        Self { db, network }
    }

    /// Analyze correlation using Bayesian inference
    pub async fn analyze_correlation(
        &mut self,
        correlation_id: Uuid,
    ) -> Result<BayesianInferenceResult> {
        info!("Analyzing correlation {} with Bayesian Network", correlation_id);

        // Clear previous evidence
        self.network.clear_evidence();

        // Get correlation events
        let events = self.get_correlation_events(correlation_id).await?;

        // Set evidence based on observed events
        for event in &events {
            self.set_evidence_from_event(event);
        }

        // Propagate beliefs
        self.network.propagate_beliefs();

        // Get most likely attack stages
        let likely_stages = self.network.get_nodes_by_belief();

        // Calculate attack chain probabilities
        let full_attack_chain = [
            "initial_access",
            "credential_access",
            "lateral_movement",
            "privilege_escalation",
            "data_exfiltration",
        ];
        let attack_chain_probability = self.network.get_attack_chain_probability(&full_attack_chain);

        // Get most likely next stages
        let next_likely_stages = self.predict_next_stages(&events);

        // Generate causal explanation
        let causal_explanation = self.generate_causal_explanation(&likely_stages);

        Ok(BayesianInferenceResult {
            correlation_id,
            likely_attack_stages: likely_stages.into_iter().take(5).collect(),
            attack_chain_probability,
            next_likely_stages,
            causal_explanation,
            confidence: attack_chain_probability,
        })
    }

    /// Set evidence from event
    fn set_evidence_from_event(&mut self, event: &EventEvidence) {
        // Map event types to Bayesian Network nodes
        let node_mapping = self.get_event_to_node_mapping();

        if let Some(node_id) = node_mapping.get(&event.event_type.to_lowercase()) {
            self.network.set_evidence(node_id, true);
        }
    }

    /// Map event types to network nodes
    fn get_event_to_node_mapping(&self) -> HashMap<String, String> {
        let mut mapping = HashMap::new();

        // Event type patterns to node mapping
        mapping.insert("authentication".to_string(), "initial_access".to_string());
        mapping.insert("login".to_string(), "initial_access".to_string());
        mapping.insert("scan".to_string(), "reconnaissance".to_string());
        mapping.insert("enumeration".to_string(), "reconnaissance".to_string());
        mapping.insert("brute_force".to_string(), "credential_access".to_string());
        mapping.insert("password_spray".to_string(), "credential_access".to_string());
        mapping.insert("lateral_movement".to_string(), "lateral_movement".to_string());
        mapping.insert("remote_execution".to_string(), "lateral_movement".to_string());
        mapping.insert("privilege_escalation".to_string(), "privilege_escalation".to_string());
        mapping.insert("sudo".to_string(), "privilege_escalation".to_string());
        mapping.insert("exfiltration".to_string(), "data_exfiltration".to_string());
        mapping.insert("large_transfer".to_string(), "data_exfiltration".to_string());
        mapping.insert("persistence".to_string(), "persistence".to_string());
        mapping.insert("scheduled_task".to_string(), "persistence".to_string());
        mapping.insert("c2".to_string(), "command_control".to_string());
        mapping.insert("beacon".to_string(), "command_control".to_string());

        mapping
    }

    /// Predict next likely attack stages
    fn predict_next_stages(&self, _events: &[EventEvidence]) -> Vec<String> {
        // Get nodes with belief > 0.3 that have no evidence set
        let mut predictions = Vec::new();

        for (node_id, node) in &self.network.nodes {
            if node.evidence.is_none() && node.belief > 0.3 {
                predictions.push(node.label.clone());
            }
        }

        predictions.sort();
        predictions.into_iter().take(3).collect()
    }

    /// Generate human-readable causal explanation
    fn generate_causal_explanation(&self, likely_stages: &[(String, f64)]) -> String {
        let mut explanation = String::from("Causal analysis:\n");

        for (node_id, belief) in likely_stages.iter().take(5) {
            if let Some(node) = self.network.nodes.get(node_id) {
                let confidence = (belief * 100.0) as i32;

                if node.evidence == Some(true) {
                    explanation.push_str(&format!(
                        "- {} (OBSERVED)\n",
                        node.label
                    ));
                } else if *belief > 0.5 {
                    explanation.push_str(&format!(
                        "- {} is LIKELY ({}% confidence)\n",
                        node.label, confidence
                    ));
                } else if *belief > 0.2 {
                    explanation.push_str(&format!(
                        "- {} is POSSIBLE ({}% confidence)\n",
                        node.label, confidence
                    ));
                }

                // Add causal parents if any
                if !node.parents.is_empty() && *belief > 0.3 {
                    explanation.push_str("  └─ Caused by: ");
                    let parent_names: Vec<String> = node.parents.iter()
                        .filter_map(|p_id| self.network.nodes.get(p_id))
                        .map(|p| p.label.clone())
                        .collect();
                    explanation.push_str(&parent_names.join(", "));
                    explanation.push('\n');
                }
            }
        }

        explanation
    }

    /// Get correlation events from database
    async fn get_correlation_events(&self, correlation_id: Uuid) -> Result<Vec<EventEvidence>> {
        let rows = sqlx::query!(
            r#"
            SELECT
                e.event_type,
                e.event_category,
                e.severity,
                e.anomaly_score
            FROM security_events e
            INNER JOIN event_correlations c ON e.correlation_id = c.id
            WHERE c.id = $1
            ORDER BY e.timestamp
            "#,
            correlation_id
        )
        .fetch_all(&self.db)
        .await?;

        let events = rows
            .into_iter()
            .map(|row| EventEvidence {
                event_type: row.event_type,
                event_category: row.event_category,
                severity: row.severity,
                anomaly_score: row.anomaly_score.to_f64(),
            })
            .collect();

        Ok(events)
    }

    /// Save inference result to database
    pub async fn save_inference_result(&self, result: &BayesianInferenceResult) -> Result<()> {
        let stages_json = serde_json::to_value(&result.likely_attack_stages)?;
        let next_stages_json = serde_json::to_value(&result.next_likely_stages)?;

        sqlx::query!(
            r#"
            UPDATE event_correlations
            SET
                bayesian_attack_stages = $2,
                bayesian_next_stages = $3,
                bayesian_confidence = $4,
                bayesian_explanation = $5
            WHERE id = $1
            "#,
            result.correlation_id,
            stages_json,
            next_stages_json,
            result.confidence.to_bigdecimal(),
            result.causal_explanation
        )
        .execute(&self.db)
        .await?;

        info!("Saved Bayesian inference result for correlation {}", result.correlation_id);
        Ok(())
    }
}

/// Event evidence for Bayesian inference
#[derive(Debug, Clone)]
struct EventEvidence {
    event_type: String,
    event_category: String,
    severity: String,
    anomaly_score: f64,
}

/// Bayesian inference result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BayesianInferenceResult {
    pub correlation_id: Uuid,
    /// Most likely attack stages with probabilities
    pub likely_attack_stages: Vec<(String, f64)>,
    /// Probability of full attack chain
    pub attack_chain_probability: f64,
    /// Predicted next stages
    pub next_likely_stages: Vec<String>,
    /// Human-readable causal explanation
    pub causal_explanation: String,
    /// Overall confidence
    pub confidence: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bayesian_network_inference() {
        let mut network = BayesianNetwork::build_attack_chain_network();

        // Set evidence: initial access detected
        network.set_evidence("initial_access", true);

        // Query: what's the probability of credential access?
        let credential_access_prob = network.query("credential_access").unwrap();
        println!("P(credential_access | initial_access) = {:.2}", credential_access_prob);
        assert!(credential_access_prob > 0.5); // Should be high given initial access

        // Set more evidence: reconnaissance detected
        network.set_evidence("reconnaissance", true);

        // Query: what's the probability of lateral movement?
        let lateral_movement_prob = network.query("lateral_movement").unwrap();
        println!("P(lateral_movement | initial_access, reconnaissance) = {:.2}", lateral_movement_prob);
        assert!(lateral_movement_prob > 0.3);
    }

    #[test]
    fn test_attack_chain_probability() {
        let mut network = BayesianNetwork::build_attack_chain_network();

        network.set_evidence("initial_access", true);
        network.set_evidence("credential_access", true);

        let chain = ["initial_access", "credential_access", "lateral_movement"];
        let chain_prob = network.get_attack_chain_probability(&chain);

        println!("Attack chain probability: {:.2}", chain_prob);
        assert!(chain_prob > 0.0 && chain_prob <= 1.0);
    }
}
