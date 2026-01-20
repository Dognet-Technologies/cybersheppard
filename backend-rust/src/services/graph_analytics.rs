// ============================================================================
// Graph Analytics Service - Network Topology Analysis
// ============================================================================

use anyhow::Result;
use sqlx::PgPool;
use std::collections::{HashMap, HashSet, VecDeque};
use tracing::{debug, info};

/// Graph node representing a host
#[derive(Debug, Clone)]
pub struct GraphNode {
    pub host_name: String,
    pub criticality: i32,
    pub connections: usize,
    pub betweenness_centrality: f64,
    pub is_critical_path: bool,
}

/// Graph edge representing a connection between hosts
#[derive(Debug, Clone)]
pub struct GraphEdge {
    pub from_host: String,
    pub to_host: String,
    pub weight: f64, // Based on connection frequency
    pub is_suspicious: bool,
}

/// Network topology graph for analysis
pub struct NetworkGraph {
    /// Adjacency list: host -> list of connected hosts
    adjacency_list: HashMap<String, Vec<String>>,
    /// Edge weights: (from, to) -> weight
    edge_weights: HashMap<(String, String), f64>,
    /// Node metadata
    nodes: HashMap<String, GraphNode>,
}

impl NetworkGraph {
    pub fn new() -> Self {
        Self {
            adjacency_list: HashMap::new(),
            edge_weights: HashMap::new(),
            nodes: HashMap::new(),
        }
    }

    /// Build graph from database
    pub async fn build_from_db(db: &PgPool, days: i32) -> Result<Self> {
        info!("Building network topology graph from {} days of data", days);

        let rows = sqlx::query!(
            r#"
            SELECT
                source_host,
                destination_host,
                COUNT(*) as connection_count,
                MAX(timestamp) as last_seen,
                BOOL_OR(anomaly_score > 50) as has_anomalies
            FROM security_events
            WHERE timestamp > NOW() - INTERVAL '1 day' * $1
              AND event_category = 'network'
              AND source_host IS NOT NULL
              AND destination_host IS NOT NULL
              AND source_host != destination_host
            GROUP BY source_host, destination_host
            HAVING COUNT(*) >= 3
            "#,
            days
        )
        .fetch_all(db)
        .await?;

        let mut graph = Self::new();

        // Build adjacency list and edge weights
        for row in rows {
            let from = row.source_host;
            let to = row.destination_host.unwrap_or_else(|| "unknown".to_string());
            let weight = (row.connection_count.unwrap_or(0) as f64).ln_1p();
            let is_suspicious = row.has_anomalies.unwrap_or(false);

            graph.add_edge(&from, &to, weight, is_suspicious);
        }

        // Load host criticality
        graph.load_host_metadata(db).await?;

        // Calculate centrality metrics
        graph.calculate_betweenness_centrality();

        // Identify critical paths
        graph.identify_critical_paths();

        info!(
            "Built network graph: {} nodes, {} edges",
            graph.nodes.len(),
            graph.edge_weights.len()
        );

        Ok(graph)
    }

    /// Add an edge to the graph
    fn add_edge(&mut self, from: &str, to: &str, weight: f64, is_suspicious: bool) {
        // Add to adjacency list
        self.adjacency_list
            .entry(from.to_string())
            .or_insert_with(Vec::new)
            .push(to.to_string());

        // Add edge weight
        self.edge_weights
            .insert((from.to_string(), to.to_string()), weight);

        // Initialize nodes if not exist
        if !self.nodes.contains_key(from) {
            self.nodes.insert(
                from.to_string(),
                GraphNode {
                    host_name: from.to_string(),
                    criticality: 5,
                    connections: 0,
                    betweenness_centrality: 0.0,
                    is_critical_path: false,
                },
            );
        }

        if !self.nodes.contains_key(to) {
            self.nodes.insert(
                to.to_string(),
                GraphNode {
                    host_name: to.to_string(),
                    criticality: 5,
                    connections: 0,
                    betweenness_centrality: 0.0,
                    is_critical_path: false,
                },
            );
        }

        // Increment connection count
        if let Some(node) = self.nodes.get_mut(from) {
            node.connections += 1;
        }
    }

    /// Load host metadata from database
    async fn load_host_metadata(&mut self, db: &PgPool) -> Result<()> {
        let rows = sqlx::query!(
            r#"
            SELECT host_name, asset_criticality
            FROM host_behavior_baselines
            "#
        )
        .fetch_all(db)
        .await?;

        for row in rows {
            if let Some(node) = self.nodes.get_mut(&row.host_name) {
                node.criticality = row.asset_criticality;
            }
        }

        Ok(())
    }

    /// Calculate betweenness centrality for all nodes
    /// Betweenness centrality measures how often a node appears on shortest paths
    fn calculate_betweenness_centrality(&mut self) {
        let nodes: Vec<String> = self.nodes.keys().cloned().collect();
        let mut betweenness: HashMap<String, f64> = HashMap::new();

        // Initialize
        for node in &nodes {
            betweenness.insert(node.clone(), 0.0);
        }

        // For each pair of nodes, find shortest paths
        for source in &nodes {
            for target in &nodes {
                if source == target {
                    continue;
                }

                // BFS to find all shortest paths
                let paths = self.find_all_shortest_paths(source, target);

                // Count how many paths go through each node
                for path in paths {
                    for node in &path[1..path.len() - 1] {
                        // Exclude source and target
                        *betweenness.entry(node.clone()).or_insert(0.0) += 1.0;
                    }
                }
            }
        }

        // Normalize betweenness centrality
        let max_betweenness = betweenness.values().cloned().fold(0.0, f64::max);
        if max_betweenness > 0.0 {
            for (node_name, value) in betweenness {
                if let Some(node) = self.nodes.get_mut(&node_name) {
                    node.betweenness_centrality = value / max_betweenness;
                }
            }
        }
    }

    /// Find all shortest paths between two nodes (BFS)
    fn find_all_shortest_paths(&self, source: &str, target: &str) -> Vec<Vec<String>> {
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        let mut paths = Vec::new();
        let mut shortest_length = usize::MAX;

        // (current_node, path_so_far)
        queue.push_back((source.to_string(), vec![source.to_string()]));

        while let Some((current, path)) = queue.pop_front() {
            // Skip if path is longer than shortest found
            if path.len() > shortest_length {
                continue;
            }

            // Found target
            if current == target {
                if path.len() < shortest_length {
                    shortest_length = path.len();
                    paths.clear();
                }
                if path.len() == shortest_length {
                    paths.push(path.clone());
                }
                continue;
            }

            // Explore neighbors
            if let Some(neighbors) = self.adjacency_list.get(&current) {
                for neighbor in neighbors {
                    if !path.contains(neighbor) {
                        // Avoid cycles
                        let mut new_path = path.clone();
                        new_path.push(neighbor.clone());
                        queue.push_back((neighbor.clone(), new_path));
                    }
                }
            }
        }

        paths
    }

    /// Identify critical paths (nodes with high betweenness centrality)
    fn identify_critical_paths(&mut self) {
        let threshold = 0.5; // Nodes with centrality > 0.5 are critical

        for node in self.nodes.values_mut() {
            if node.betweenness_centrality > threshold {
                node.is_critical_path = true;
            }
        }
    }

    /// Get nodes sorted by betweenness centrality
    pub fn get_critical_nodes(&self, limit: usize) -> Vec<&GraphNode> {
        let mut nodes: Vec<&GraphNode> = self.nodes.values().collect();
        nodes.sort_by(|a, b| {
            b.betweenness_centrality
                .partial_cmp(&a.betweenness_centrality)
                .unwrap()
        });
        nodes.into_iter().take(limit).collect()
    }

    /// Calculate clustering coefficient for a node
    /// Measures how well connected a node's neighbors are
    pub fn calculate_clustering_coefficient(&self, node: &str) -> f64 {
        if let Some(neighbors) = self.adjacency_list.get(node) {
            if neighbors.len() < 2 {
                return 0.0;
            }

            let mut edges_between_neighbors = 0;
            for i in 0..neighbors.len() {
                for j in i + 1..neighbors.len() {
                    if self
                        .adjacency_list
                        .get(&neighbors[i])
                        .map(|n| n.contains(&neighbors[j]))
                        .unwrap_or(false)
                    {
                        edges_between_neighbors += 1;
                    }
                }
            }

            let max_possible_edges = neighbors.len() * (neighbors.len() - 1) / 2;
            edges_between_neighbors as f64 / max_possible_edges as f64
        } else {
            0.0
        }
    }

    /// Find communities using simple modularity-based approach
    pub fn detect_communities(&self) -> HashMap<String, usize> {
        // Simplified community detection using connected components
        let mut communities = HashMap::new();
        let mut visited = HashSet::new();
        let mut community_id = 0;

        for node in self.nodes.keys() {
            if visited.contains(node) {
                continue;
            }

            // BFS to find connected component
            let mut queue = VecDeque::new();
            queue.push_back(node.clone());

            while let Some(current) = queue.pop_front() {
                if visited.insert(current.clone()) {
                    communities.insert(current.clone(), community_id);

                    if let Some(neighbors) = self.adjacency_list.get(&current) {
                        for neighbor in neighbors {
                            if !visited.contains(neighbor) {
                                queue.push_back(neighbor.clone());
                            }
                        }
                    }
                }
            }

            community_id += 1;
        }

        communities
    }

    /// Get network statistics
    pub fn get_statistics(&self) -> NetworkStatistics {
        let total_nodes = self.nodes.len();
        let total_edges = self.edge_weights.len();

        let avg_degree = if total_nodes > 0 {
            (total_edges * 2) as f64 / total_nodes as f64
        } else {
            0.0
        };

        let critical_nodes = self
            .nodes
            .values()
            .filter(|n| n.is_critical_path)
            .count();

        let avg_centrality = if total_nodes > 0 {
            self.nodes
                .values()
                .map(|n| n.betweenness_centrality)
                .sum::<f64>()
                / total_nodes as f64
        } else {
            0.0
        };

        NetworkStatistics {
            total_nodes,
            total_edges,
            avg_degree,
            critical_nodes,
            avg_centrality,
        }
    }
}

/// Network statistics
#[derive(Debug, Clone, serde::Serialize)]
pub struct NetworkStatistics {
    pub total_nodes: usize,
    pub total_edges: usize,
    pub avg_degree: f64,
    pub critical_nodes: usize,
    pub avg_centrality: f64,
}

/// Graph Analytics Service
pub struct GraphAnalyticsService {
    db: PgPool,
}

impl GraphAnalyticsService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Analyze network topology
    pub async fn analyze_network_topology(&self, days: i32) -> Result<NetworkTopologyAnalysis> {
        info!("Analyzing network topology for {} days", days);

        // Build graph
        let graph = NetworkGraph::build_from_db(&self.db, days).await?;

        // Get critical nodes
        let critical_nodes = graph.get_critical_nodes(10);

        // Detect communities
        let communities = graph.detect_communities();

        // Get statistics
        let statistics = graph.get_statistics();

        // Find potential attack paths to critical assets
        let attack_paths = self.find_attack_paths_to_critical_assets(&graph).await?;

        // Update database with centrality scores
        self.update_network_topology_scores(&graph).await?;

        Ok(NetworkTopologyAnalysis {
            statistics,
            critical_nodes: critical_nodes
                .into_iter()
                .map(|n| n.clone())
                .collect(),
            community_count: communities.values().max().copied().unwrap_or(0) + 1,
            attack_paths,
        })
    }

    /// Find potential attack paths to critical assets
    async fn find_attack_paths_to_critical_assets(
        &self,
        graph: &NetworkGraph,
    ) -> Result<Vec<AttackPath>> {
        let mut attack_paths = Vec::new();

        // Get critical assets
        let critical_hosts: Vec<String> = graph
            .nodes
            .values()
            .filter(|n| n.criticality >= 8)
            .map(|n| n.host_name.clone())
            .collect();

        // Get potential entry points (nodes with high connections from outside)
        let entry_points: Vec<String> = graph
            .nodes
            .values()
            .filter(|n| n.connections > 5)
            .map(|n| n.host_name.clone())
            .collect();

        // Find paths from entry points to critical assets
        for entry in &entry_points {
            for critical in &critical_hosts {
                if entry == critical {
                    continue;
                }

                let paths = graph.find_all_shortest_paths(entry, critical);
                if !paths.is_empty() {
                    let shortest_path = &paths[0];
                    let path_length = shortest_path.len();

                    // Calculate path risk
                    let risk_score = self.calculate_path_risk(graph, shortest_path);

                    attack_paths.push(AttackPath {
                        from_host: entry.clone(),
                        to_host: critical.clone(),
                        path: shortest_path.clone(),
                        path_length,
                        risk_score,
                    });
                }
            }
        }

        // Sort by risk score
        attack_paths.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap());
        attack_paths.truncate(20); // Top 20 paths

        Ok(attack_paths)
    }

    /// Calculate risk score for a path
    fn calculate_path_risk(&self, graph: &NetworkGraph, path: &[String]) -> f64 {
        let mut risk_score = 0.0;

        // Shorter paths are riskier
        risk_score += 100.0 / path.len() as f64;

        // Paths through high-centrality nodes are riskier
        for node_name in path {
            if let Some(node) = graph.nodes.get(node_name) {
                risk_score += node.betweenness_centrality * 20.0;
            }
        }

        // Destination criticality
        if let Some(dest_node) = graph.nodes.get(&path[path.len() - 1]) {
            risk_score += dest_node.criticality as f64 * 5.0;
        }

        risk_score.min(100.0)
    }

    /// Update network topology scores in database
    async fn update_network_topology_scores(&self, graph: &NetworkGraph) -> Result<()> {
        for (host_name, node) in &graph.nodes {
            sqlx::query!(
                r#"
                INSERT INTO network_topology (
                    source_host,
                    destination_host,
                    connection_count,
                    betweenness_centrality,
                    first_seen,
                    last_seen
                )
                SELECT
                    $1,
                    $1,
                    $2,
                    $3,
                    NOW(),
                    NOW()
                WHERE NOT EXISTS (
                    SELECT 1 FROM network_topology WHERE source_host = $1 AND destination_host = $1
                )
                "#,
                host_name,
                node.connections as i32,
                node.betweenness_centrality
            )
            .execute(&self.db)
            .await
            .ok(); // Ignore errors for self-loops
        }

        Ok(())
    }
}

/// Network topology analysis result
#[derive(Debug, Clone, serde::Serialize)]
pub struct NetworkTopologyAnalysis {
    pub statistics: NetworkStatistics,
    pub critical_nodes: Vec<GraphNode>,
    pub community_count: usize,
    pub attack_paths: Vec<AttackPath>,
}

/// Potential attack path
#[derive(Debug, Clone, serde::Serialize)]
pub struct AttackPath {
    pub from_host: String,
    pub to_host: String,
    pub path: Vec<String>,
    pub path_length: usize,
    pub risk_score: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_graph() {
        let mut graph = NetworkGraph::new();

        graph.add_edge("A", "B", 1.0, false);
        graph.add_edge("B", "C", 1.0, false);
        graph.add_edge("A", "C", 1.0, false);

        assert_eq!(graph.nodes.len(), 3);
        assert_eq!(graph.edge_weights.len(), 3);

        // Shortest path
        let paths = graph.find_all_shortest_paths("A", "C");
        assert!(paths.len() > 0);
    }
}
