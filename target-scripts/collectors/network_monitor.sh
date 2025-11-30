#!/bin/bash
# ============================================================================
# CYBERSHEPPARD - Network Monitor
# ============================================================================
# Monitors network connections using netstat, ss, lsof, and pidof

set -euo pipefail

# Configuration
HOSTNAME=$(hostname)
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# ============================================================================
# Collect Listening Ports
# ============================================================================
collect_listening_ports() {
    echo "{"
    echo "  \"measurement\": \"listening_ports\","
    echo "  \"tags\": {"
    echo "    \"host\": \"$HOSTNAME\""
    echo "  },"
    echo "  \"timestamp\": \"$TIMESTAMP\","
    echo "  \"ports\": ["

    # Use ss if available, otherwise netstat
    local ports=""
    if command -v ss &> /dev/null; then
        ports=$(ss -tlnp 2>/dev/null | grep LISTEN)
    elif command -v netstat &> /dev/null; then
        ports=$(netstat -tlnp 2>/dev/null | grep LISTEN)
    fi

    if [ -n "$ports" ]; then
        local first=true
        echo "$ports" | while IFS= read -r line; do
            if [ "$first" = false ]; then
                echo ","
            fi
            first=false

            local proto=$(echo "$line" | awk '{print $1}')
            local local_addr=$(echo "$line" | awk '{print $4}')
            local port=$(echo "$local_addr" | rev | cut -d: -f1 | rev)
            local pid=$(echo "$line" | grep -oP 'pid=\K[0-9]+' || echo "$line" | awk '{print $7}' | grep -oP '[0-9]+' | head -1 || echo "0")
            local process=$(echo "$line" | grep -oP 'users:\(\(".*?"\)' | sed 's/users:(("//' | sed 's/".*//' || echo "unknown")

            echo "      {"
            echo "        \"protocol\": \"$proto\","
            echo "        \"port\": \"$port\","
            echo "        \"address\": \"$local_addr\","
            echo "        \"pid\": \"$pid\","
            echo "        \"process\": \"$process\""
            echo -n "      }"
        done
    fi

    echo ""
    echo "  ]"
    echo "}"
}

# ============================================================================
# Collect Active Connections
# ============================================================================
collect_active_connections() {
    echo "{"
    echo "  \"measurement\": \"active_connections\","
    echo "  \"tags\": {"
    echo "    \"host\": \"$HOSTNAME\""
    echo "  },"
    echo "  \"timestamp\": \"$TIMESTAMP\","
    echo "  \"connections\": ["

    # Get established connections
    local conns=""
    if command -v ss &> /dev/null; then
        conns=$(ss -tnp state established 2>/dev/null | tail -n +2)
    elif command -v netstat &> /dev/null; then
        conns=$(netstat -tnp 2>/dev/null | grep ESTABLISHED)
    fi

    if [ -n "$conns" ]; then
        local first=true
        echo "$conns" | head -20 | while IFS= read -r line; do
            if [ "$first" = false ]; then
                echo ","
            fi
            first=false

            local local_addr=$(echo "$line" | awk '{print $4}')
            local remote_addr=$(echo "$line" | awk '{print $5}')
            local pid=$(echo "$line" | grep -oP 'pid=\K[0-9]+' || echo "$line" | awk '{print $7}' | grep -oP '[0-9]+' | head -1 || echo "0")

            echo "      {"
            echo "        \"local\": \"$local_addr\","
            echo "        \"remote\": \"$remote_addr\","
            echo "        \"pid\": \"$pid\""
            echo -n "      }"
        done
    fi

    echo ""
    echo "  ]"
    echo "}"
}

# ============================================================================
# Collect Open Files by Network Processes
# ============================================================================
collect_network_files() {
    echo "{"
    echo "  \"measurement\": \"network_files\","
    echo "  \"tags\": {"
    echo "    \"host\": \"$HOSTNAME\""
    echo "  },"
    echo "  \"timestamp\": \"$TIMESTAMP\","
    echo "  \"files\": ["

    # Use lsof to find network-related open files
    if command -v lsof &> /dev/null; then
        local first=true
        lsof -i -n -P 2>/dev/null | tail -n +2 | head -20 | while IFS= read -r line; do
            if [ "$first" = false ]; then
                echo ","
            fi
            first=false

            local command=$(echo "$line" | awk '{print $1}')
            local pid=$(echo "$line" | awk '{print $2}')
            local user=$(echo "$line" | awk '{print $3}')
            local type=$(echo "$line" | awk '{print $5}')
            local name=$(echo "$line" | awk '{print $9}')

            echo "      {"
            echo "        \"command\": \"$command\","
            echo "        \"pid\": \"$pid\","
            echo "        \"user\": \"$user\","
            echo "        \"type\": \"$type\","
            echo "        \"name\": \"$name\""
            echo -n "      }"
        done
    fi

    echo ""
    echo "  ]"
    echo "}"
}

# ============================================================================
# Collect Network Statistics
# ============================================================================
collect_network_stats() {
    echo "{"
    echo "  \"measurement\": \"network_stats\","
    echo "  \"tags\": {"
    echo "    \"host\": \"$HOSTNAME\""
    echo "  },"
    echo "  \"timestamp\": \"$TIMESTAMP\","
    echo "  \"fields\": {"

    # Connection counts by state
    local established=0
    local listen=0
    local time_wait=0
    local close_wait=0

    if command -v ss &> /dev/null; then
        established=$(ss -tn state established 2>/dev/null | tail -n +2 | wc -l)
        listen=$(ss -tln 2>/dev/null | grep LISTEN | wc -l)
        time_wait=$(ss -tn state time-wait 2>/dev/null | tail -n +2 | wc -l)
        close_wait=$(ss -tn state close-wait 2>/dev/null | tail -n +2 | wc -l)
    elif command -v netstat &> /dev/null; then
        established=$(netstat -tn 2>/dev/null | grep -c ESTABLISHED || echo 0)
        listen=$(netstat -tln 2>/dev/null | grep -c LISTEN || echo 0)
        time_wait=$(netstat -tn 2>/dev/null | grep -c TIME_WAIT || echo 0)
        close_wait=$(netstat -tn 2>/dev/null | grep -c CLOSE_WAIT || echo 0)
    fi

    # Count unique remote IPs
    local unique_ips=0
    if command -v ss &> /dev/null; then
        unique_ips=$(ss -tn state established 2>/dev/null | tail -n +2 | awk '{print $5}' | cut -d: -f1 | sort -u | wc -l)
    elif command -v netstat &> /dev/null; then
        unique_ips=$(netstat -tn 2>/dev/null | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort -u | wc -l)
    fi

    echo "    \"established\": $established,"
    echo "    \"listen\": $listen,"
    echo "    \"time_wait\": $time_wait,"
    echo "    \"close_wait\": $close_wait,"
    echo "    \"unique_remote_ips\": $unique_ips"

    echo "  }"
    echo "}"
}

# ============================================================================
# Main
# ============================================================================
main() {
    echo "{"
    echo "  \"type\": \"network_monitoring\","
    echo "  \"hostname\": \"$HOSTNAME\","
    echo "  \"timestamp\": \"$TIMESTAMP\","
    echo "  \"data\": {"

    echo "    \"stats\": $(collect_network_stats | tr -d '\n' | sed 's/  //g'),"
    echo "    \"listening_ports\": $(collect_listening_ports | tr -d '\n' | sed 's/  //g'),"
    echo "    \"active_connections\": $(collect_active_connections | tr -d '\n' | sed 's/  //g'),"
    echo "    \"network_files\": $(collect_network_files | tr -d '\n' | sed 's/  //g')"

    echo "  }"
    echo "}"
}

main "$@"
