#!/bin/bash
# ============================================================================
# CYBERSHEPPARD - Services Status Collector
# ============================================================================
# Monitors system services status, enabled/disabled state
# Detects unexpected service states, failed services, rogue processes

set -euo pipefail

# Configuration
COLLECTOR_NAME="services"
DATA_DIR="${DATA_DIR:-/opt/cybersheppard/data}"
OUTPUT_FILE="${DATA_DIR}/services_$(date +%Y%m%d_%H%M%S).json"

# Initialize
mkdir -p "$(dirname "$OUTPUT_FILE")"

# JSON structure
cat > "$OUTPUT_FILE" <<'EOF'
{
    "systemd_services": [],
    "listening_ports": [],
    "docker_containers": []
}
EOF

# Temporary file
TMP_JSON=$(mktemp)

# ============================================================================
# Systemd Services Collection
# ============================================================================

echo "Collecting systemd services..." >&2

# Check if systemd is available
if command -v systemctl &> /dev/null; then
    jq '.systemd_services = [' "$OUTPUT_FILE" > "$TMP_JSON"
    FIRST=true

    systemctl list-units --type=service --all --no-pager --no-legend 2>/dev/null | \
    while read -r service load active sub description; do
        # Get service state
        ENABLED="unknown"
        if systemctl is-enabled "$service" &>/dev/null; then
            ENABLED=$(systemctl is-enabled "$service" 2>/dev/null || echo "unknown")
        fi

        # Get PID if running
        PID="null"
        if [ "$active" = "active" ]; then
            PID=$(systemctl show "$service" --property=MainPID --value 2>/dev/null || echo "null")
        fi

        # Get start time
        START_TIME="unknown"
        if [ "$active" = "active" ]; then
            START_TIME=$(systemctl show "$service" --property=ActiveEnterTimestamp --value 2>/dev/null || echo "unknown")
        fi

        if [ "$FIRST" = false ]; then
            echo "," >> "$TMP_JSON"
        fi
        FIRST=false

        cat <<EOF >> "$TMP_JSON"
{
    "name": "$service",
    "load": "$load",
    "active": "$active",
    "sub": "$sub",
    "description": "$description",
    "enabled": "$ENABLED",
    "pid": $PID,
    "start_time": "$START_TIME"
}
EOF
    done

    echo "]" >> "$TMP_JSON"
    jq -s '.[0] * .[1]' "$OUTPUT_FILE" "$TMP_JSON" > "${OUTPUT_FILE}.new"
    mv "${OUTPUT_FILE}.new" "$OUTPUT_FILE"
fi

# ============================================================================
# Listening Ports Collection
# ============================================================================

echo "Collecting listening ports..." >&2

jq '.listening_ports = [' "$OUTPUT_FILE" > "$TMP_JSON"
FIRST=true

# Use ss (preferred) or netstat as fallback
if command -v ss &> /dev/null; then
    ss -tuln 2>/dev/null | tail -n +2 | while read -r netid state recv_q send_q local_addr foreign_addr; do
        # Parse local address
        if [[ "$local_addr" =~ ^(.*):([0-9]+)$ ]]; then
            IP="${BASH_REMATCH[1]}"
            PORT="${BASH_REMATCH[2]}"
        else
            continue
        fi

        # Get process using the port
        PROCESS="unknown"
        if command -v lsof &> /dev/null; then
            PROCESS=$(lsof -i :"$PORT" -sTCP:LISTEN -t 2>/dev/null | head -1 | xargs -r ps -p -o comm= 2>/dev/null || echo "unknown")
        fi

        if [ "$FIRST" = false ]; then
            echo "," >> "$TMP_JSON"
        fi
        FIRST=false

        cat <<EOF >> "$TMP_JSON"
{
    "protocol": "$netid",
    "state": "$state",
    "local_address": "$IP",
    "local_port": $PORT,
    "process": "$PROCESS"
}
EOF
    done
elif command -v netstat &> /dev/null; then
    netstat -tuln 2>/dev/null | grep LISTEN | while read -r proto recv_q send_q local foreign state; do
        # Parse local address
        if [[ "$local" =~ ^(.*):([0-9]+)$ ]]; then
            IP="${BASH_REMATCH[1]}"
            PORT="${BASH_REMATCH[2]}"
        else
            continue
        fi

        if [ "$FIRST" = false ]; then
            echo "," >> "$TMP_JSON"
        fi
        FIRST=false

        cat <<EOF >> "$TMP_JSON"
{
    "protocol": "$proto",
    "state": "LISTEN",
    "local_address": "$IP",
    "local_port": $PORT,
    "process": "unknown"
}
EOF
    done
fi

echo "]" >> "$TMP_JSON"
jq -s '.[0] * .[1]' "$OUTPUT_FILE" "$TMP_JSON" > "${OUTPUT_FILE}.new"
mv "${OUTPUT_FILE}.new" "$OUTPUT_FILE"

# ============================================================================
# Docker Containers Collection (if Docker available)
# ============================================================================

echo "Collecting Docker containers..." >&2

if command -v docker &> /dev/null && docker ps &>/dev/null; then
    jq '.docker_containers = [' "$OUTPUT_FILE" > "$TMP_JSON"
    FIRST=true

    docker ps -a --format '{{json .}}' 2>/dev/null | while read -r container_json; do
        if [ "$FIRST" = false ]; then
            echo "," >> "$TMP_JSON"
        fi
        FIRST=false

        echo "$container_json" >> "$TMP_JSON"
    done

    echo "]" >> "$TMP_JSON"
    jq -s '.[0] * .[1]' "$OUTPUT_FILE" "$TMP_JSON" > "${OUTPUT_FILE}.new"
    mv "${OUTPUT_FILE}.new" "$OUTPUT_FILE"
else
    # No Docker, keep empty array
    :
fi

# Cleanup
rm -f "$TMP_JSON"

# Statistics
TOTAL_SERVICES=$(jq '.systemd_services | length' "$OUTPUT_FILE" 2>/dev/null || echo "0")
ACTIVE_SERVICES=$(jq '[.systemd_services[] | select(.active == "active")] | length' "$OUTPUT_FILE" 2>/dev/null || echo "0")
FAILED_SERVICES=$(jq '[.systemd_services[] | select(.active == "failed")] | length' "$OUTPUT_FILE" 2>/dev/null || echo "0")
LISTENING_PORTS=$(jq '.listening_ports | length' "$OUTPUT_FILE" 2>/dev/null || echo "0")
DOCKER_CONTAINERS=$(jq '.docker_containers | length' "$OUTPUT_FILE" 2>/dev/null || echo "0")

# Metadata
cat > "${OUTPUT_FILE}.meta" <<EOF
{
    "collector": "$COLLECTOR_NAME",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "hostname": "$(hostname)",
    "total_services": $TOTAL_SERVICES,
    "active_services": $ACTIVE_SERVICES,
    "failed_services": $FAILED_SERVICES,
    "listening_ports": $LISTENING_PORTS,
    "docker_containers": $DOCKER_CONTAINERS
}
EOF

echo "Services collector: $TOTAL_SERVICES services ($ACTIVE_SERVICES active, $FAILED_SERVICES failed), $LISTENING_PORTS listening ports" >&2
echo "$OUTPUT_FILE"
