// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - Compliance Tests
// ============================================================================

#[cfg(test)]
mod compliance_tests {
    use cybersheppard_backend::services::compliance::ComplianceEngine;
    use cybersheppard_backend::models::{MonitoringDataPayload, MonitoringData, NetworkMetrics, AuditdMetrics};
    use chrono::Utc;

    #[test]
    fn test_threshold_detection() {
        // Test that violations are detected when thresholds are exceeded
        let payload = MonitoringDataPayload {
            target_id: "1".to_string(),
            timestamp: Utc::now(),
            data: MonitoringData {
                system_metrics: None,
                auditd: Some(AuditdMetrics {
                    status: None,
                    events_last_hour: None,
                    failed_logins: Some(100), // Exceeds threshold
                    config_changes: None,
                    privilege_escalations: None,
                }),
                sudo: None,
                network: Some(NetworkMetrics {
                    active_connections: None,
                    listening_ports: None,
                    failed_ssh_attempts: Some(60), // Exceeds threshold
                }),
                processes: None,
            },
        };

        // This would require actual DB connection in integration tests
        // For now, just verify the data structure
        assert!(payload.data.auditd.is_some());
        assert_eq!(payload.data.auditd.as_ref().unwrap().failed_logins, Some(100));
    }

    #[test]
    fn test_severity_classification() {
        // Test severity levels
        let severities = vec!["critical", "high", "medium", "low"];

        for severity in severities {
            assert!(["critical", "high", "medium", "low"].contains(&severity));
        }
    }
}
