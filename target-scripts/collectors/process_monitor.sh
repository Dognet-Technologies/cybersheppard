#!/bin/bash
# ============================================================================
# CYBERSHEPPARD - Process Monitor
# ============================================================================
# Monitors running processes using ps, pidof, and /proc

set -euo pipefail

# Configuration
HOSTNAME=$(hostname)
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
TOP_PROCESSES="${1:-10}"  # Number of top processes to track

# ============================================================================
# Collect Top Processes by CPU
# ============================================================================
collect_top_cpu() {
    echo "{"
    echo "  \"measurement\": \"top_cpu_processes\","
    echo "  \"tags\": {"
    echo "    \"host\": \"$HOSTNAME\""
    echo "  },"
    echo "  \"timestamp\": \"$TIMESTAMP\","
    echo "  \"processes\": ["

    local first=true
    ps aux --sort=-%cpu | head -n $((TOP_PROCESSES + 1)) | tail -n +2 | while IFS= read -r line; do
        if [ "$first" = false ]; then
            echo ","
        fi
        first=false

        local user=$(echo "$line" | awk '{print $1}')
        local pid=$(echo "$line" | awk '{print $2}')
        local cpu=$(echo "$line" | awk '{print $3}')
        local mem=$(echo "$line" | awk '{print $4}')
        local vsz=$(echo "$line" | awk '{print $5}')
        local rss=$(echo "$line" | awk '{print $6}')
        local command=$(echo "$line" | awk '{for(i=11;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/ $//')

        echo "      {"
        echo "        \"user\": \"$user\","
        echo "        \"pid\": $pid,"
        echo "        \"cpu_percent\": $cpu,"
        echo "        \"mem_percent\": $mem,"
        echo "        \"vsz\": $vsz,"
        echo "        \"rss\": $rss,"
        echo "        \"command\": \"$command\""
        echo -n "      }"
    done

    echo ""
    echo "  ]"
    echo "}"
}

# ============================================================================
# Collect Top Processes by Memory
# ============================================================================
collect_top_memory() {
    echo "{"
    echo "  \"measurement\": \"top_memory_processes\","
    echo "  \"tags\": {"
    echo "    \"host\": \"$HOSTNAME\""
    echo "  },"
    echo "  \"timestamp\": \"$TIMESTAMP\","
    echo "  \"processes\": ["

    local first=true
    ps aux --sort=-%mem | head -n $((TOP_PROCESSES + 1)) | tail -n +2 | while IFS= read -r line; do
        if [ "$first" = false ]; then
            echo ","
        fi
        first=false

        local user=$(echo "$line" | awk '{print $1}')
        local pid=$(echo "$line" | awk '{print $2}')
        local cpu=$(echo "$line" | awk '{print $3}')
        local mem=$(echo "$line" | awk '{print $4}')
        local vsz=$(echo "$line" | awk '{print $5}')
        local rss=$(echo "$line" | awk '{print $6}')
        local command=$(echo "$line" | awk '{for(i=11;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/ $//')

        echo "      {"
        echo "        \"user\": \"$user\","
        echo "        \"pid\": $pid,"
        echo "        \"cpu_percent\": $cpu,"
        echo "        \"mem_percent\": $mem,"
        echo "        \"vsz\": $vsz,"
        echo "        \"rss\": $rss,"
        echo "        \"command\": \"$command\""
        echo -n "      }"
    done

    echo ""
    echo "  ]"
    echo "}"
}

# ============================================================================
# Collect Process Statistics
# ============================================================================
collect_process_stats() {
    echo "{"
    echo "  \"measurement\": \"process_stats\","
    echo "  \"tags\": {"
    echo "    \"host\": \"$HOSTNAME\""
    echo "  },"
    echo "  \"timestamp\": \"$TIMESTAMP\","
    echo "  \"fields\": {"

    # Total processes
    local total=$(ps aux | wc -l)
    total=$((total - 1))  # Remove header

    # Running processes
    local running=$(ps aux | grep -c " R " || echo 0)

    # Sleeping processes
    local sleeping=$(ps aux | grep -c " S " || echo 0)

    # Zombie processes
    local zombies=$(ps aux | grep -c " Z " || echo 0)

    # Stopped processes
    local stopped=$(ps aux | grep -c " T " || echo 0)

    # Count processes by user
    local root_procs=$(ps aux | grep -c "^root " || echo 0)

    echo "    \"total\": $total,"
    echo "    \"running\": $running,"
    echo "    \"sleeping\": $sleeping,"
    echo "    \"zombies\": $zombies,"
    echo "    \"stopped\": $stopped,"
    echo "    \"root_processes\": $root_procs"

    echo "  }"
    echo "}"
}

# ============================================================================
# Check Critical Services
# ============================================================================
check_critical_services() {
    echo "{"
    echo "  \"measurement\": \"critical_services\","
    echo "  \"tags\": {"
    echo "    \"host\": \"$HOSTNAME\""
    echo "  },"
    echo "  \"timestamp\": \"$TIMESTAMP\","
    echo "  \"services\": ["

    # List of critical services to monitor
    local services=("sshd" "cron" "rsyslog" "systemd-journald" "auditd")

    local first=true
    for service in "${services[@]}"; do
        if [ "$first" = false ]; then
            echo ","
        fi
        first=false

        # Check if process is running using pidof
        local pid=$(pidof "$service" 2>/dev/null | awk '{print $1}' || echo "0")
        local status="stopped"
        local cpu=0
        local mem=0

        if [ "$pid" != "0" ]; then
            status="running"
            # Get CPU and memory usage
            if [ -f "/proc/$pid/stat" ]; then
                cpu=$(ps -p "$pid" -o %cpu --no-headers 2>/dev/null || echo 0)
                mem=$(ps -p "$pid" -o %mem --no-headers 2>/dev/null || echo 0)
            fi
        fi

        echo "      {"
        echo "        \"name\": \"$service\","
        echo "        \"status\": \"$status\","
        echo "        \"pid\": $pid,"
        echo "        \"cpu_percent\": $cpu,"
        echo "        \"mem_percent\": $mem"
        echo -n "      }"
    done

    echo ""
    echo "  ]"
    echo "}"
}

# ============================================================================
# Main
# ============================================================================
main() {
    echo "{"
    echo "  \"type\": \"process_monitoring\","
    echo "  \"hostname\": \"$HOSTNAME\","
    echo "  \"timestamp\": \"$TIMESTAMP\","
    echo "  \"data\": {"

    echo "    \"stats\": $(collect_process_stats | tr -d '\n' | sed 's/  //g'),"
    echo "    \"top_cpu\": $(collect_top_cpu | tr -d '\n' | sed 's/  //g'),"
    echo "    \"top_memory\": $(collect_top_memory | tr -d '\n' | sed 's/  //g'),"
    echo "    \"critical_services\": $(check_critical_services | tr -d '\n' | sed 's/  //g')"

    echo "  }"
    echo "}"
}

main "$@"
