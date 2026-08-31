#!/usr/bin/env bash
# ============================================================================
# CyberSheppard — Installazione di Laurel (plugin auditd) sul TARGET
# ============================================================================
# STARTER, DA FINALIZZARE: la sorgente del binario Laurel (release/build) va
# confermata (vedi README.md). Il resto (utente, config, plugin, regole,
# restart) è pronto. Eseguire come root sul target monitorato.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAUREL_BIN="/usr/local/sbin/laurel"

log() { printf '[laurel-install] %s\n' "$*"; }

# 1. Prerequisito: auditd installato.
if ! command -v auditctl >/dev/null 2>&1; then
    log "auditd non presente: installalo prima (vedi template logging-monitoring)."
    exit 1
fi

# 2. Utente di servizio + directory (log JSON + stato).
if ! id laurel >/dev/null 2>&1; then
    useradd --system --home-dir /var/log/laurel --shell /usr/sbin/nologin laurel
fi
install -d -o laurel -g laurel -m 0750 /var/log/laurel /var/lib/laurel

# 3. Binario Laurel.  ── DA FINALIZZARE ──
# Opzione A (release precompilata):
#   LAUREL_VERSION=0.6.3 ; ARCH=$(uname -m)
#   curl -fsSL "https://github.com/threathunters-io/laurel/releases/download/v${LAUREL_VERSION}/laurel-v${LAUREL_VERSION}-${ARCH}-glibc.tar.gz" \
#     | tar -xz -C /usr/local/sbin laurel
# Opzione B (build da sorgente con cargo): cargo build --release && cp target/release/laurel "$LAUREL_BIN"
if [[ ! -x "$LAUREL_BIN" ]]; then
    log "ATTENZIONE: binario Laurel assente in $LAUREL_BIN."
    log "Finalizza scaricando la release o compilando (vedi commenti sopra), poi rilancia."
    # Non usciamo con errore: config/regole vengono comunque installate.
fi

# 4. Config di Laurel.
install -d -m 0755 /etc/laurel
install -o root -g laurel -m 0640 "$SCRIPT_DIR/config.toml" /etc/laurel/config.toml

# 5. Registrazione come plugin auditd.
PLUGIN_DIR="/etc/audit/plugins.d"
[[ -d "$PLUGIN_DIR" ]] || PLUGIN_DIR="/etc/audisp/plugins.d" # distro più vecchie
install -o root -g root -m 0640 "$SCRIPT_DIR/plugin-laurel.conf" "$PLUGIN_DIR/laurel.conf"

# 6. Regole audit CyberSheppard.
install -o root -g root -m 0640 "$SCRIPT_DIR/../audit/cybersheppard.rules" \
    /etc/audit/rules.d/cybersheppard.rules
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
else
    auditctl -R /etc/audit/rules.d/cybersheppard.rules || true
fi

# 7. Riavvio auditd (ricarica plugin + regole).
systemctl restart auditd 2>/dev/null || service auditd restart || true

log "Fatto. Se il binario è presente, verifica gli eventi JSON con:"
log "  tail -f /var/log/laurel/audit.log"
log "Poi configura l'agent con laurel_log_path = \"/var/log/laurel/audit.log\"."
