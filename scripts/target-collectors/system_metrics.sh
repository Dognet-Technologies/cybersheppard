#!/bin/bash
# ============================================================================
# CYBERSHEPPARD - System Metrics Collector
# ============================================================================
# Collects system metrics using native Linux commands
# No external dependencies required

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOSTNAME=$(hostname)
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# ============================================================================
# CPU Metrics
# ============================================================================
collect_cpu_metrics() {
    echo "{"
    echo "  \"measurement\": \"cpu\","
    echo "  \"tags\": {"
    echo "    \"host\": \"$HOSTNAME\""
    echo "  },"
    echo "  \"timestamp\": \"$TIMESTAMP\","
    echo "  \"fields\": {"

    # CPU usage from top (1 second sample)
    local cpu_line=$(top -bn2 -d 1 | grep "^%Cpu" | tail -1)
    local cpu_user=$(echo "$cpu_line" | awk '{print $2}' | sed 's/us,//')
    local cpu_system=$(echo "$cpu_line" | awk '{print $4}' | sed 's/sy,//')
    local cpu_idle=$(echo "$cpu_line" | awk '{print $8}' | sed 's/id,//')
    local cpu_iowait=$(echo "$cpu_line" | awk '{print $10}' | sed 's/wa,//')

    echo "    \"user\": $cpu_user,"
    echo "    \"system\": $cpu_system,"
    echo "    \"idle\": $cpu_idle,"
    echo "    \"iowait\": $cpu_iowait,"

    # Load average
    local load=$(uptime | awk -F'load average:' '{print $2}' | sed 's/,//g')
    local load1=$(echo $load | awk '{print $1}')
    local load5=$(echo $load | awk '{print $2}')
    local load15=$(echo $load | awk '{print $3}')

    echo "    \"load1\": $load1,"
    echo "    \"load5\": $load5,"
    echo "    \"load15\": $load15,"

    # CPU count
    local cpu_count=$(nproc)
    echo "    \"cpu_count\": $cpu_count"

    echo "  }"
    echo "}"
}

# ============================================================================
# Memory Metrics
# ============================================================================
collect_memory_metrics() {
    echo "{"
    echo "  \"measurement\": \"memory\","
    echo "  \"tags\": {"
    echo "    \"host\": \"$HOSTNAME\""
    echo "  },"
    echo "  \"timestamp\": \"$TIMESTAMP\","
    echo "  \"fields\": {"

    # Memory info from /proc/meminfo
    local mem_total=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local mem_free=$(grep MemFree /proc/meminfo | awk '{print $2}')
    local mem_available=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
    local mem_buffers=$(grep Buffers /proc/meminfo | awk '{print $2}')
    local mem_cached=$(grep "^Cached:" /proc/meminfo | awk '{print $2}')
    local swap_total=$(grep SwapTotal /proc/meminfo | awk '{print $2}')
    local swap_free=$(grep SwapFree /proc/meminfo | awk '{print $2}')

    local mem_used=$((mem_total - mem_free - mem_buffers - mem_cached))
    local mem_used_percent=$(awk "BEGIN {printf \"%.2f\", ($mem_used/$mem_total)*100}")
    local swap_used=$((swap_total - swap_free))

    echo "    \"total\": $mem_total,"
    echo "    \"free\": $mem_free,"
    echo "    \"available\": $mem_available,"
    echo "    \"used\": $mem_used,"
    echo "    \"used_percent\": $mem_used_percent,"
    echo "    \"buffers\": $mem_buffers,"
    echo "    \"cached\": $mem_cached,"
    echo "    \"swap_total\": $swap_total,"
    echo "    \"swap_used\": $swap_used,"
    echo "    \"swap_free\": $swap_free"

    echo "  }"
    echo "}"
}

# ============================================================================
# Disk Metrics
# ============================================================================
collect_disk_metrics() {
    echo "{"
    echo "  \"measurement\": \"disk\","
    echo "  \"tags\": {"
    echo "    \"host\": \"$HOSTNAME\""
    echo "  },"
    echo "  \"timestamp\": \"$TIMESTAMP\","
    echo "  \"fields\": {"
    echo "    \"filesystems\": ["

    local first=true
    df -B1 | tail -n +2 | while IFS= read -r line; do
        local filesystem=$(echo "$line" | awk '{print $1}')
        local size=$(echo "$line" | awk '{print $2}')
        local used=$(echo "$line" | awk '{print $3}')
        local available=$(echo "$line" | awk '{print $4}')
        local use_percent=$(echo "$line" | awk '{print $5}' | sed 's/%//')
        local mountpoint=$(echo "$line" | awk '{print $6}')

        # Skip special filesystems
        if [[ "$filesystem" == tmpfs ]] || [[ "$filesystem" == devtmpfs ]] || [[ "$filesystem" == udev ]]; then
            continue
        fi

        if [ "$first" = false ]; then
            echo ","
        fi
        first=false

        echo "      {"
        echo "        \"filesystem\": \"$filesystem\","
        echo "        \"mountpoint\": \"$mountpoint\","
        echo "        \"size\": $size,"
        echo "        \"used\": $used,"
        echo "        \"available\": $available,"
        echo "        \"use_percent\": $use_percent"
        echo -n "      }"
    done

    echo ""
    echo "    ]"
    echo "  }"
    echo "}"
}

# ============================================================================
# Network Metrics
# ============================================================================
collect_network_metrics() {
    echo "{"
    echo "  \"measurement\": \"network\","
    echo "  \"tags\": {"
    echo "    \"host\": \"$HOSTNAME\""
    echo "  },"
    echo "  \"timestamp\": \"$TIMESTAMP\","
    echo "  \"fields\": {"
    echo "    \"interfaces\": ["

    local first=true
    for iface in $(ls /sys/class/net/); do
        # Skip loopback
        if [ "$iface" = "lo" ]; then
            continue
        fi

        if [ "$first" = false ]; then
            echo ","
        fi
        first=false

        local rx_bytes=$(cat /sys/class/net/$iface/statistics/rx_bytes 2>/dev/null || echo 0)
        local tx_bytes=$(cat /sys/class/net/$iface/statistics/tx_bytes 2>/dev/null || echo 0)
        local rx_packets=$(cat /sys/class/net/$iface/statistics/rx_packets 2>/dev/null || echo 0)
        local tx_packets=$(cat /sys/class/net/$iface/statistics/tx_packets 2>/dev/null || echo 0)
        local rx_errors=$(cat /sys/class/net/$iface/statistics/rx_errors 2>/dev/null || echo 0)
        local tx_errors=$(cat /sys/class/net/$iface/statistics/tx_errors 2>/dev/null || echo 0)

        echo "      {"
        echo "        \"name\": \"$iface\","
        echo "        \"rx_bytes\": $rx_bytes,"
        echo "        \"tx_bytes\": $tx_bytes,"
        echo "        \"rx_packets\": $rx_packets,"
        echo "        \"tx_packets\": $tx_packets,"
        echo "        \"rx_errors\": $rx_errors,"
        echo "        \"tx_errors\": $tx_errors"
        echo -n "      }"
    done

    echo ""
    echo "    ]"
    echo "  }"
    echo "}"
}

# ============================================================================
# Main
# ============================================================================
main() {
    echo "{"
    echo "  \"type\": \"system_metrics\","
    echo "  \"hostname\": \"$HOSTNAME\","
    echo "  \"timestamp\": \"$TIMESTAMP\","
    echo "  \"metrics\": {"

    echo "    \"cpu\": $(collect_cpu_metrics | tr -d '\n' | sed 's/  //g'),"
    echo "    \"memory\": $(collect_memory_metrics | tr -d '\n' | sed 's/  //g'),"
    echo "    \"disk\": $(collect_disk_metrics | tr -d '\n' | sed 's/  //g'),"
    echo "    \"network\": $(collect_network_metrics | tr -d '\n' | sed 's/  //g')"

    echo "  }"
    echo "}"
}

main "$@"
