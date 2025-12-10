// ============================================================================
// CYBERSHEPPARD (MicroSIEM) - API Tests
// ============================================================================

#[cfg(test)]
mod api_tests {
    use serde_json::json;

    #[test]
    fn test_monitoring_payload_serialization() {
        let payload = json!({
            "target_id": "1",
            "timestamp": "2025-12-10T00:00:00Z",
            "data": {
                "system_metrics": {
                    "cpu_usage": 75.5,
                    "memory_usage": 60.0,
                    "disk_usage": 85.0
                },
                "auditd": {
                    "failed_logins": 5
                }
            }
        });

        assert_eq!(payload["target_id"], "1");
        assert_eq!(payload["data"]["system_metrics"]["cpu_usage"], 75.5);
    }

    #[test]
    fn test_violation_response_format() {
        let response = json!({
            "status": "success",
            "compliance": {
                "violations_detected": 2,
                "status": "non_compliant"
            }
        });

        assert_eq!(response["status"], "success");
        assert_eq!(response["compliance"]["violations_detected"], 2);
    }
}
