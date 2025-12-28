#!/bin/bash
# ============================================================================
# CYBERSHEPPARD - Users Activity Collector
# ============================================================================
# Monitors user accounts, login activity, failed login attempts
# Tracks user creation/deletion, privilege changes, suspicious activity

set -euo pipefail

# Configuration
COLLECTOR_NAME="users"
DATA_DIR="${DATA_DIR:-/opt/cybersheppard/data}"
OUTPUT_FILE="${DATA_DIR}/users_$(date +%Y%m%d_%H%M%S).json"

# Initialize
mkdir -p "$(dirname "$OUTPUT_FILE")"

# JSON structure
cat > "$OUTPUT_FILE" <<'EOF'
{
    "users": [],
    "active_sessions": [],
    "recent_logins": [],
    "failed_logins": [],
    "sudo_activity": []
}
EOF

# Temporary file for building JSON
TMP_JSON=$(mktemp)

# ============================================================================
# User Accounts Collection
# ============================================================================

echo "Collecting user accounts..." >&2

jq '.users = [' "$OUTPUT_FILE" > "$TMP_JSON"
FIRST=true

while IFS=: read -r username password uid gid gecos home shell; do
    # Skip system users below UID 1000 (except root)
    if [ "$uid" -lt 1000 ] && [ "$username" != "root" ]; then
        continue
    fi

    # Get last login
    LAST_LOGIN=$(lastlog -u "$username" 2>/dev/null | tail -1 | awk '{for(i=4;i<=NF;i++) printf "%s ", $i; print ""}' | xargs)
    if [ "$LAST_LOGIN" = "**Never logged in**" ] || [ -z "$LAST_LOGIN" ]; then
        LAST_LOGIN="never"
    fi

    # Check if user has sudo privileges
    SUDO_PRIV="false"
    if id -nG "$username" 2>/dev/null | grep -qw "sudo\|wheel"; then
        SUDO_PRIV="true"
    fi

    # Check if account is locked
    LOCKED="false"
    if passwd -S "$username" 2>/dev/null | grep -q " L "; then
        LOCKED="true"
    fi

    # Get password expiry info
    PASSWORD_EXPIRY=$(chage -l "$username" 2>/dev/null | grep "Password expires" | cut -d: -f2 | xargs || echo "never")

    # Check home directory
    HOME_EXISTS="false"
    if [ -d "$home" ]; then
        HOME_EXISTS="true"
    fi

    if [ "$FIRST" = false ]; then
        echo "," >> "$TMP_JSON"
    fi
    FIRST=false

    cat <<USEREOF >> "$TMP_JSON"
{
    "username": "$username",
    "uid": $uid,
    "gid": $gid,
    "gecos": "$gecos",
    "home": "$home",
    "shell": "$shell",
    "home_exists": $HOME_EXISTS,
    "has_sudo": $SUDO_PRIV,
    "locked": $LOCKED,
    "last_login": "$LAST_LOGIN",
    "password_expiry": "$PASSWORD_EXPIRY"
}
USEREOF
done < /etc/passwd

echo "]" >> "$TMP_JSON"
jq -s '.[0] * .[1]' "$OUTPUT_FILE" "$TMP_JSON" > "${OUTPUT_FILE}.new"
mv "${OUTPUT_FILE}.new" "$OUTPUT_FILE"

# ============================================================================
# Active Sessions Collection
# ============================================================================

echo "Collecting active sessions..." >&2

jq '.active_sessions = [' "$OUTPUT_FILE" > "$TMP_JSON"
FIRST=true

who -u 2>/dev/null | while read -r username tty login_time idle pid comment; do
    if [ "$FIRST" = false ]; then
        echo "," >> "$TMP_JSON"
    fi
    FIRST=false

    cat <<EOF >> "$TMP_JSON"
{
    "username": "$username",
    "tty": "$tty",
    "login_time": "$login_time",
    "idle": "$idle",
    "pid": "$pid",
    "from": "$comment"
}
EOF
done

echo "]" >> "$TMP_JSON"
jq -s '.[0] * .[1]' "$OUTPUT_FILE" "$TMP_JSON" > "${OUTPUT_FILE}.new"
mv "${OUTPUT_FILE}.new" "$OUTPUT_FILE"

# ============================================================================
# Recent Logins Collection
# ============================================================================

echo "Collecting recent logins..." >&2

jq '.recent_logins = [' "$OUTPUT_FILE" > "$TMP_JSON"
FIRST=true

# Last 50 successful logins
last -n 50 -F 2>/dev/null | grep -v "^$" | grep -v "^wtmp" | while read -r line; do
    USERNAME=$(echo "$line" | awk '{print $1}')
    TTY=$(echo "$line" | awk '{print $2}')
    FROM=$(echo "$line" | awk '{print $3}')
    LOGIN_TIME=$(echo "$line" | awk '{print $4" "$5" "$6" "$7" "$8}')

    if [ -n "$USERNAME" ] && [ "$USERNAME" != "reboot" ]; then
        if [ "$FIRST" = false ]; then
            echo "," >> "$TMP_JSON"
        fi
        FIRST=false

        cat <<EOF >> "$TMP_JSON"
{
    "username": "$USERNAME",
    "tty": "$TTY",
    "from": "$FROM",
    "login_time": "$LOGIN_TIME"
}
EOF
    fi
done

echo "]" >> "$TMP_JSON"
jq -s '.[0] * .[1]' "$OUTPUT_FILE" "$TMP_JSON" > "${OUTPUT_FILE}.new"
mv "${OUTPUT_FILE}.new" "$OUTPUT_FILE"

# ============================================================================
# Failed Logins Collection
# ============================================================================

echo "Collecting failed logins..." >&2

jq '.failed_logins = [' "$OUTPUT_FILE" > "$TMP_JSON"
FIRST=true

# Check auth logs for failed login attempts (last 100)
if [ -f /var/log/auth.log ]; then
    grep "Failed password" /var/log/auth.log 2>/dev/null | tail -100 | while read -r line; do
        TIMESTAMP=$(echo "$line" | awk '{print $1" "$2" "$3}')
        USERNAME=$(echo "$line" | grep -oP 'for \K[^ ]+' || echo "unknown")
        FROM=$(echo "$line" | grep -oP 'from \K[^ ]+' || echo "unknown")

        if [ "$FIRST" = false ]; then
            echo "," >> "$TMP_JSON"
        fi
        FIRST=false

        cat <<EOF >> "$TMP_JSON"
{
    "timestamp": "$TIMESTAMP",
    "username": "$USERNAME",
    "from": "$FROM",
    "reason": "failed_password"
}
EOF
    done
elif [ -f /var/log/secure ]; then
    grep "Failed password" /var/log/secure 2>/dev/null | tail -100 | while read -r line; do
        TIMESTAMP=$(echo "$line" | awk '{print $1" "$2" "$3}')
        USERNAME=$(echo "$line" | grep -oP 'for \K[^ ]+' || echo "unknown")
        FROM=$(echo "$line" | grep -oP 'from \K[^ ]+' || echo "unknown")

        if [ "$FIRST" = false ]; then
            echo "," >> "$TMP_JSON"
        fi
        FIRST=false

        cat <<EOF >> "$TMP_JSON"
{
    "timestamp": "$TIMESTAMP",
    "username": "$USERNAME",
    "from": "$FROM",
    "reason": "failed_password"
}
EOF
    done
fi

echo "]" >> "$TMP_JSON"
jq -s '.[0] * .[1]' "$OUTPUT_FILE" "$TMP_JSON" > "${OUTPUT_FILE}.new"
mv "${OUTPUT_FILE}.new" "$OUTPUT_FILE"

# ============================================================================
# Sudo Activity Collection
# ============================================================================

echo "Collecting sudo activity..." >&2

jq '.sudo_activity = [' "$OUTPUT_FILE" > "$TMP_JSON"
FIRST=true

# Recent sudo commands (last 50)
if [ -f /var/log/auth.log ]; then
    grep "sudo:" /var/log/auth.log 2>/dev/null | grep "COMMAND=" | tail -50 | while read -r line; do
        TIMESTAMP=$(echo "$line" | awk '{print $1" "$2" "$3}')
        USERNAME=$(echo "$line" | grep -oP 'USER=\K[^ ]+' || echo "unknown")
        COMMAND=$(echo "$line" | grep -oP 'COMMAND=\K.*' || echo "unknown")

        if [ "$FIRST" = false ]; then
            echo "," >> "$TMP_JSON"
        fi
        FIRST=false

        cat <<EOF >> "$TMP_JSON"
{
    "timestamp": "$TIMESTAMP",
    "user": "$USERNAME",
    "command": "$COMMAND"
}
EOF
    done
elif [ -f /var/log/secure ]; then
    grep "sudo:" /var/log/secure 2>/dev/null | grep "COMMAND=" | tail -50 | while read -r line; do
        TIMESTAMP=$(echo "$line" | awk '{print $1" "$2" "$3}')
        USERNAME=$(echo "$line" | grep -oP 'USER=\K[^ ]+' || echo "unknown")
        COMMAND=$(echo "$line" | grep -oP 'COMMAND=\K.*' || echo "unknown")

        if [ "$FIRST" = false ]; then
            echo "," >> "$TMP_JSON"
        fi
        FIRST=false

        cat <<EOF >> "$TMP_JSON"
{
    "timestamp": "$TIMESTAMP",
    "user": "$USERNAME",
    "command": "$COMMAND"
}
EOF
    done
fi

echo "]" >> "$TMP_JSON"
jq -s '.[0] * .[1]' "$OUTPUT_FILE" "$TMP_JSON" > "${OUTPUT_FILE}.new"
mv "${OUTPUT_FILE}.new" "$OUTPUT_FILE"

# Cleanup
rm -f "$TMP_JSON"

# Statistics
TOTAL_USERS=$(jq '.users | length' "$OUTPUT_FILE")
ACTIVE_SESSIONS=$(jq '.active_sessions | length' "$OUTPUT_FILE")
FAILED_LOGINS=$(jq '.failed_logins | length' "$OUTPUT_FILE")
SUDO_COMMANDS=$(jq '.sudo_activity | length' "$OUTPUT_FILE")

# Metadata
cat > "${OUTPUT_FILE}.meta" <<EOF
{
    "collector": "$COLLECTOR_NAME",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "hostname": "$(hostname)",
    "total_users": $TOTAL_USERS,
    "active_sessions": $ACTIVE_SESSIONS,
    "failed_logins_count": $FAILED_LOGINS,
    "sudo_commands_count": $SUDO_COMMANDS
}
EOF

echo "Users collector: $TOTAL_USERS users, $ACTIVE_SESSIONS active, $FAILED_LOGINS failed logins" >&2
echo "$OUTPUT_FILE"
