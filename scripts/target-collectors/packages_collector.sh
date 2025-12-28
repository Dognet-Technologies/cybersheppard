#!/bin/bash
# ============================================================================
# CYBERSHEPPARD - Package Vulnerabilities Collector
# ============================================================================
# Collects installed packages and checks for known vulnerabilities
# Tracks package versions, updates, and security advisories

set -euo pipefail

# Configuration
COLLECTOR_NAME="packages"
DATA_DIR="${DATA_DIR:-/opt/cybersheppard/data}"
OUTPUT_FILE="${DATA_DIR}/packages_$(date +%Y%m%d_%H%M%S).json"

# Initialize
mkdir -p "$(dirname "$OUTPUT_FILE")"

# JSON array initialization
echo "[" > "$OUTPUT_FILE"
FIRST=true

# ============================================================================
# Helper Functions
# ============================================================================

# Detect package manager
detect_package_manager() {
    if command -v dpkg &> /dev/null; then
        echo "dpkg"
    elif command -v rpm &> /dev/null; then
        echo "rpm"
    elif command -v pacman &> /dev/null; then
        echo "pacman"
    else
        echo "unknown"
    fi
}

# Get packages list (Debian/Ubuntu)
get_dpkg_packages() {
    dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\n' 2>/dev/null | \
    while IFS=$'\t' read -r package version arch status; do
        # Only installed packages
        if [[ "$status" == *"install ok installed"* ]]; then
            if [ "$FIRST" = false ]; then
                echo "," >> "$OUTPUT_FILE"
            fi
            FIRST=false

            # Check if security update available
            local security_update="false"
            if apt-cache policy "$package" 2>/dev/null | grep -q "security"; then
                security_update="true"
            fi

            # Get package source
            local source=$(dpkg-query -W -f='${Source}' "$package" 2>/dev/null || echo "$package")

            cat <<EOF >> "$OUTPUT_FILE"
{
    "name": "$package",
    "version": "$version",
    "architecture": "$arch",
    "source": "$source",
    "manager": "dpkg",
    "security_update_available": $security_update
}
EOF
        fi
    done
}

# Get packages list (RedHat/CentOS)
get_rpm_packages() {
    rpm -qa --queryformat '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n' 2>/dev/null | \
    while IFS=$'\t' read -r package version arch source; do
        if [ "$FIRST" = false ]; then
            echo "," >> "$OUTPUT_FILE"
        fi
        FIRST=false

        # Check if security update available
        local security_update="false"
        if yum list updates --security "$package" 2>/dev/null | grep -q "$package"; then
            security_update="true"
        fi

        cat <<EOF >> "$OUTPUT_FILE"
{
    "name": "$package",
    "version": "$version",
    "architecture": "$arch",
    "source": "$source",
    "manager": "rpm",
    "security_update_available": $security_update
}
EOF
    done
}

# ============================================================================
# Main Collection
# ============================================================================

PKG_MANAGER=$(detect_package_manager)

case "$PKG_MANAGER" in
    dpkg)
        get_dpkg_packages
        ;;
    rpm)
        get_rpm_packages
        ;;
    *)
        echo "Warning: Unknown package manager" >&2
        ;;
esac

# Get security updates count
SECURITY_UPDATES=0
if [ "$PKG_MANAGER" = "dpkg" ]; then
    SECURITY_UPDATES=$(apt list --upgradable 2>/dev/null | grep -c "security" || echo "0")
elif [ "$PKG_MANAGER" = "rpm" ]; then
    SECURITY_UPDATES=$(yum list updates --security 2>/dev/null | grep -c "^[a-zA-Z]" || echo "0")
fi

# Close JSON array
echo "]" >> "$OUTPUT_FILE"

# Count packages
TOTAL_PACKAGES=$(grep -c '"name"' "$OUTPUT_FILE" || echo "0")

# Metadata
cat > "${OUTPUT_FILE}.meta" <<EOF
{
    "collector": "$COLLECTOR_NAME",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "hostname": "$(hostname)",
    "package_manager": "$PKG_MANAGER",
    "total_packages": $TOTAL_PACKAGES,
    "security_updates_available": $SECURITY_UPDATES
}
EOF

echo "Packages collector: $TOTAL_PACKAGES packages, $SECURITY_UPDATES security updates available" >&2
echo "$OUTPUT_FILE"
