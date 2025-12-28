#!/bin/bash
# ============================================================================
# CYBERSHEPPARD - Main Collector Script
# ============================================================================
# Orchestrates all monitoring collectors and sends data to backend
#
# Usage:
#   ./cybersheppard-collector.sh [OPTIONS]
#
# Options:
#   --api-url URL       Backend API URL (default: from config)
#   --api-key KEY       API authentication key
#   --interval SECONDS  Collection interval (default: 30)
#   --oneshot          Run once and exit
#   --verbose          Verbose output
#
# ============================================================================

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COLLECTORS_DIR="$SCRIPT_DIR/collectors"
CONFIG_FILE="/etc/cybersheppard/config.conf"

# Default values
API_URL="${CYBERSHEPPARD_API_URL:-http://localhost:8080}"
API_KEY="${CYBERSHEPPARD_API_KEY:-}"
TARGET_ID="${CYBERSHEPPARD_TARGET_ID:-}"
INTERVAL=30
ONESHOT=false
VERBOSE=false

# ============================================================================
# Load Configuration
# ============================================================================
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        # shellcheck source=/dev/null
        source "$CONFIG_FILE"
    fi
}

# ============================================================================
# Parse Arguments
# ============================================================================
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --api-url)
                API_URL="$2"
                shift 2
                ;;
            --api-key)
                API_KEY="$2"
                shift 2
                ;;
            --target-id)
                TARGET_ID="$2"
                shift 2
                ;;
            --interval)
                INTERVAL="$2"
                shift 2
                ;;
            --oneshot)
                ONESHOT=true
                shift
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            *)
                echo "Unknown option: $1" >&2
                exit 1
                ;;
        esac
    done
}

# ============================================================================
# Logging
# ============================================================================
log() {
    if [ "$VERBOSE" = true ]; then
        echo "[$(date -u +"%Y-%m-%d %H:%M:%S UTC")] $*"
    fi
}

log_error() {
    echo "[$(date -u +"%Y-%m-%d %H:%M:%S UTC")] ERROR: $*" >&2
}

# ============================================================================
# Run All Collectors
# ============================================================================
run_collectors() {
    local output_file=$(mktemp)
    local has_data=false

    log "Running collectors..."

    echo "{" > "$output_file"
    echo "  \"target_id\": \"$TARGET_ID\"," >> "$output_file"
    echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"," >> "$output_file"
    echo "  \"data\": {" >> "$output_file"

    # System Metrics
    if [ -x "$COLLECTORS_DIR/system_metrics.sh" ]; then
        log "  - Collecting system metrics..."
        echo "    \"system_metrics\": $("$COLLECTORS_DIR/system_metrics.sh" 2>/dev/null || echo '{}')," >> "$output_file"
        has_data=true
    fi

    # Auditd Logs
    if [ -x "$COLLECTORS_DIR/auditd_collector.sh" ]; then
        log "  - Collecting auditd logs..."
        echo "    \"auditd\": $("$COLLECTORS_DIR/auditd_collector.sh" 2>/dev/null || echo '{}')," >> "$output_file"
        has_data=true
    fi

    # Sudo Logs
    if [ -x "$COLLECTORS_DIR/sudo_collector.sh" ]; then
        log "  - Collecting sudo logs..."
        echo "    \"sudo\": $("$COLLECTORS_DIR/sudo_collector.sh" 2>/dev/null || echo '{}')," >> "$output_file"
        has_data=true
    fi

    # Network Monitoring
    if [ -x "$COLLECTORS_DIR/network_monitor.sh" ]; then
        log "  - Collecting network data..."
        echo "    \"network\": $("$COLLECTORS_DIR/network_monitor.sh" 2>/dev/null || echo '{}')," >> "$output_file"
        has_data=true
    fi

    # Process Monitoring
    if [ -x "$COLLECTORS_DIR/process_monitor.sh" ]; then
        log "  - Collecting process data..."
        echo "    \"processes\": $("$COLLECTORS_DIR/process_monitor.sh" 2>/dev/null || echo '{}')" >> "$output_file"
        has_data=true
    fi

    echo "  }" >> "$output_file"
    echo "}" >> "$output_file"

    if [ "$has_data" = true ]; then
        cat "$output_file"
    else
        echo "{\"error\": \"No collectors available\"}"
    fi

    rm -f "$output_file"
}

# ============================================================================
# Send Data to Backend
# ============================================================================
send_to_backend() {
    local data="$1"

    if [ -z "$API_KEY" ]; then
        log_error "API key not configured. Data will not be sent."
        return 1
    fi

    if [ -z "$TARGET_ID" ]; then
        log_error "Target ID not configured. Data will not be sent."
        return 1
    fi

    log "Sending data to backend: $API_URL/api/monitoring/data"

    local response
    response=$(curl -s -w "\n%{http_code}" \
        -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $API_KEY" \
        -d "$data" \
        "$API_URL/api/monitoring/data" 2>&1)

    local http_code=$(echo "$response" | tail -1)
    local body=$(echo "$response" | head -n -1)

    if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
        log "Data sent successfully (HTTP $http_code)"
        return 0
    else
        log_error "Failed to send data (HTTP $http_code): $body"
        return 1
    fi
}

# ============================================================================
# Main Collection Loop
# ============================================================================
main_loop() {
    log "CyberSheppard collector started"
    log "  API URL: $API_URL"
    log "  Target ID: $TARGET_ID"
    log "  Interval: ${INTERVAL}s"
    log "  Oneshot: $ONESHOT"

    while true; do
        # Run collectors
        local data
        data=$(run_collectors)

        # Send to backend if configured
        if [ -n "$API_KEY" ] && [ -n "$TARGET_ID" ]; then
            if ! send_to_backend "$data"; then
                # On failure, log data locally for later retry
                local backup_file="/var/log/cybersheppard/failed_$(date +%s).json"
                mkdir -p "$(dirname "$backup_file")"
                echo "$data" > "$backup_file"
                log "Data saved to $backup_file for later retry"
            fi
        else
            # Just output to stdout if no backend configured
            echo "$data"
        fi

        # Exit if oneshot mode
        if [ "$ONESHOT" = true ]; then
            log "Oneshot mode: exiting"
            break
        fi

        # Wait for next interval
        log "Sleeping for ${INTERVAL}s..."
        sleep "$INTERVAL"
    done
}

# ============================================================================
# Entry Point
# ============================================================================
load_config
parse_args "$@"
main_loop
