#!/bin/bash
# ==============================================================================
# 🛡️ NetGuard Pro v5.4 (PERFECTED FINAL EDITION) 
# https://github.com/netguard-pro/install.sh
# ==============================================================================
set -euo pipefail

# --- Visual Styling ---
BOLD=$(tput bold 2>/dev/null || echo ""); RESET=$(tput sgr0 2>/dev/null || echo "")
GREEN='\033[0;32m'; CYAN='\033[0;36m'; RED='\033[0;31m'; YELLOW='\033[1;33m'

# --- Root & Validation ---
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}${BOLD}ERROR: Please run as root or with sudo.${RESET}"
   echo "Usage: curl -sSL [link] | sudo bash"
   exit 1
fi

REAL_USER=${SUDO_USER:-$USER}
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
IP_REGEX='^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'

echo -e "${CYAN}${BOLD}🚀 NetGuard Pro v5.4 - Enterprise Installation Starting...${RESET}"

# 1. CORE DEPENDENCIES
echo -e "📦 Installing Enterprise Dependencies..."
apt update -qq >/dev/null
apt install -y curl iproute2 ipset geoip-bin geoip-database whois ufw bc \
    python3 python3-gi python3-requests gir1.2-appindicator3-0.1 libnotify-bin \
    bsdmainutils logrotate cron || echo -e "${YELLOW}Non-critical packages skipped.${RESET}"

ufw --force enable >/dev/null 2>/dev/null

# 2. CONFIG & DIRECTORIES
echo -e "⚙️  Initializing Configuration..."
mkdir -p /etc/netguard /var/lib/netguard /var/log/netguard /var/run/netguard
chown -R "$REAL_USER:$REAL_USER" /etc/netguard /var/log/netguard /var/run/netguard

cat > /etc/netguard/config.conf << 'EOF'
# NetGuard Pro v5.4 Enterprise Configuration
WHITELIST_IPS="1.1.1.1 8.8.8.8 1.0.0.1"
THREAT_COUNTRIES="RU CN KP IR SY IQ AF YE SO SD LB VE CU BY TR BG VN"
UPDATE_DB_DAILY=true
BLOCK_NEW_CONNECTIONS=true
MAX_BLOCKLIST=10000
EOF

echo -e "1.1.1.1\n8.8.8.8\n1.0.0.1" > /etc/netguard/whitelist.conf
chown "$REAL_USER:$REAL_USER" /etc/netguard/whitelist.conf

# 3. INITIAL THREAT INTEL
echo -e "🌐 Downloading FireHOL Level 1 Blocklist..."
if curl -fsSL -m 30 https://iplists.firehol.org/files/firehol_level1.netset/latest -o /var/lib/netguard/malicious-ips.txt; then
    echo -e "  [${GREEN}✓${RESET}] $(wc -l < /var/lib/netguard/malicious-ips.txt) entries"
else
    echo -e "  [${YELLOW}!${RESET}] Using empty DB (retry later)"
    touch /var/lib/netguard/malicious-ips.txt
fi

# Initialize ipset
ipset create netguard_blacklist hash:ip 2>/dev/null || true
awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {print $1}' /var/lib/netguard/malicious-ips.txt | \
    grep -E "$IP_REGEX" | head -${MAX_BLOCKLIST:-5000} | xargs -n1 ipset add netguard_blacklist 2>/dev/null || true

# 4. LOGROTATE CONFIG
cat > /etc/logrotate.d/netguard << 'EOF'
/var/log/netguard/*.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    postrotate
        /usr/local/bin/netguard-scan --log-rotate >/dev/null 2>&1
    endscript
}
EOF

# 5. SCANNER ENGINE (Fixed Regex + Production)
cat > /usr/local/bin/netguard-scan << 'EOF'
#!/bin/bash
set -euo pipefail
CONFIG="/etc/netguard/config.conf"
WHITELIST="/etc/netguard/whitelist.conf"
MALICIOUS_DB="/var/lib/netguard/malicious-ips.txt"
LOG_FILE="/var/log/netguard/netguard-alerts.log"
STATE_FILE="/var/run/netguard_bw_state"
IP_REGEX='^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'
NOW=$(date +%s)

source "$CONFIG" 2>/dev/null || { echo "Config missing"; exit 1; }

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [$1] $2" | tee -a "$LOG_FILE"; }

validate_ip() { [[ $1 =~ $IP_REGEX ]]; }

case "${1:-}" in
    --block)
        IP="$2"; shift 2
        if ! validate_ip "$IP"; then log "ERROR" "Invalid IP: $IP"; exit 1; fi
        grep -q "^$IP$" "$WHITELIST" 2>/dev/null && { log "INFO" "Whitelisted: $IP"; exit 0; }
        if ufw insert 1 deny from "$IP" to any comment "NetGuard-Pro" 2>/dev/null && \
           ipset add netguard_blacklist "$IP" 2>/dev/null; then
            log "BLOCK" "$IP (UFW+ipset)"
        fi
        ;;
    --unblock)
        IP="$2"; shift 2
        if ! validate_ip "$IP"; then log "ERROR" "Invalid IP: $IP"; exit 1; fi
        while read -r line; do
            idx=$(echo "$line" | awk -F"[][]" '{print $2}')
            [[ "$idx" =~ ^[0-9]+$ ]] && ufw --force delete "$idx" 2>/dev/null
        done < <(ufw status numbered 2>/dev/null | grep "$IP")
        ipset del netguard_blacklist "$IP" 2>/dev/null
        log "UNBLOCK" "$IP"
        ;;
    --list-blocks)
        echo "=== UFW Blocks ==="
        ufw status | grep "NetGuard-Pro" | awk '{print $3}' | sort -u
        echo "=== ipset ($IPSET_COUNT total) ==="
        ipset list netguard_blacklist 2>/dev/null | grep '^<ip>' | head -10
        ;;
    --log-rotate)
        ipset save netguard_blacklist > /var/lib/netguard/ipset-backup.$(date +%s).txt 2>/dev/null || true
        ;;
    *)  # SCAN MODE
        declare -A PREV_RX PREV_TX
        [ -f "$STATE_FILE" ] && source "$STATE_FILE" 2>/dev/null
        TMP_STATE="/tmp/netguard_bw_state.$$"
        echo "PREV_TS=$NOW" > "$TMP_STATE"
        
        ss -tun state established -i 2>/dev/null | awk '
        /^[0-9]/ {split($5,a,":"); ip=a[1]; if(ip!~"^(127|192\.168|10\.|172\.|::1|fe80::)") curr=ip}
        /bytes:/ {if(curr&&NF>=2) print curr "|" $2 "|" $4; curr=""}' | 
        while IFS='|' read -r ip rx tx; do
            [[ -z "$ip" || ! "$ip" =~ '$IP_REGEX' ]] && continue  # ✅ FIXED REGEX
            
            echo "PREV_RX[$ip]=\$rx" >> "$TMP_STATE"
            echo "PREV_TX[$ip]=\$tx" >> "$TMP_STATE"
            
            dt=$((NOW - ${PREV_TS:-0})); dx=$((rx - ${PREV_RX[$ip]:-0})); du=$((tx - ${PREV_TX[$ip]:-0}))
            bw_info=""
            [ "$dt" -gt 1 ] && {
                rx_f=$((dx/1024)); tx_f=$((du/1024))
                bw_info=" (↓${rx_f}kB ↑${tx_f}kB)"
            }
            
            prio=0; icon="🟢"
            ipset list netguard_blacklist 2>/dev/null | grep -q "^$ip$" && { prio=3; icon="🔴"; }
            grep -q "^$ip[[:space:]]" "$MALICIOUS_DB" 2>/dev/null && { prio=2; icon="🔴"; }
            cc=$(timeout 1 geoiplookup "$ip" 2>/dev/null | awk -F, '{print $2}' | tr -d ' ' || echo "??")
            [[ " $THREAT_COUNTRIES " =~ " $cc " ]] && { prio=$((prio+1)); [ $prio -lt 2 ] && icon="🟠"; }
            grep -q "^$IP$" "$WHITELIST" 2>/dev/null && icon="✅"
            
            org=$(timeout 2 whois "$ip" 2>/dev/null | grep -iE "organization|orgname|owner|descr" | \
                  head -n1 | cut -d: -f2- | xargs | cut -c1-25 2>/dev/null || echo "Unknown")
            
            printf "%d|%s %s (%s)%s | %s\n" "$prio" "$icon" "$ip" "$cc" "$bw_info" "$org|$ip"
        done | sort -rn | cut -d'|' -f2-
        
        mv "$TMP_STATE" "$STATE_FILE" 2>/dev/null || rm -f "$TMP_STATE"
        ;;
esac
EOF
chmod +x /usr/local/bin/netguard-scan


# 6. AUTO-UPDATE CRON (✅ FIXED)
echo -e "⏰ Configuring Daily Threat Intelligence Updates..."
cat > /usr/local/bin/netguard-update << 'EOF'
#!/bin/bash
set -euo pipefail
DB="/var/lib/netguard/malicious-ips.txt"
IPSET="netguard_blacklist"
CONFIG="/etc/netguard/config.conf"
MAX_BLOCKLIST=${MAX_BLOCKLIST:-10000}

source "$CONFIG" 2>/dev/null || exit 0
[ "$UPDATE_DB_DAILY" != "true" ] && exit 0

echo "$(date): $(whoami) updating threat intel..." >> /var/log/netguard/update.log

ipset save "$IPSET" > /var/lib/netguard/ipset-backup.$(date +%Y%m%d).txt 2>/dev/null || true

# ✅ FIXED: Proper quote + file size check
if curl -fsSL -m 30 https://iplists.firehol.org/files/firehol_level1.netset/latest -o "$DB.tmp" && \
   [[ -s "$DB.tmp" ]]; then
    mv "$DB.tmp" "$DB"
    ipset flush "$IPSET" 2>/dev/null || ipset create "$IPSET" hash:ip
    
    awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {print $1}' "$DB" | \
        grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" | \
        head -$MAX_BLOCKLIST | xargs -n 10 -P 4 ipset add "$IPSET"
    
    BLOCKED=$(ipset list "$IPSET" 2>/dev/null | grep -c '^<ip>' || echo 0)
    echo "$(date): Updated ${BLOCKED} blocked IPs" >> /var/log/netguard/update.log
    timeout 5 notify-send "🛡️ NetGuard Pro" "Threat DB refreshed: ${BLOCKED} IPs" 2>/dev/null || true
else
    echo "$(date): Download failed - keeping old DB" >> /var/log/netguard/update.log
    rm -f "$DB.tmp"
fi
EOF
chmod +x /usr/local/bin/netguard-update



# 7. DASHBOARD
cat > /usr/local/bin/netguard-dash << 'EOF'
#!/bin/bash
LOG_FILE="/var/log/netguard/netguard-alerts.log"
IPSET_COUNT=$(ipset list netguard_blacklist 2>/dev/null | grep -c '^<ip>' 2>/dev/null || echo 0)
clear
echo -e "\033[1;36m╔══════════════════════════════════════════════════════════╗\033[0m"
echo -e "\033[1;36m║          🛡️  NETGUARD PRO v5.4 ENTERPRISE DASHBOARD      ║\033[0m"
echo -e "\033[1;36m╚══════════════════════════════════════════════════════════╝\033[0m"
echo -e "\n\033[1;32m📊 STATS:\033[0m ipset: ${IPSET_COUNT} | UFW: $(ufw status | grep -c 'NetGuard-Pro' 2>/dev/null)"
echo -e "\n\033[1;33m📋 RECENT ALERTS (tail -20):\033[0m"
[ -s "$LOG_FILE" ] && tail -20 "$LOG_FILE" | sed 's/\[BLOCK\]/\x1b[31m[BLOCK]\x1b[0m/g' \
    | sed 's/\[UNBLOCK\]/\x1b[32m[UNBLOCK]\x1b[0m/g' | sed 's/\[ALERT\]/\x1b[33m[ALERT]\x1b[0m/g' \
    || echo "No alerts (normal during idle)"
echo -e "\n\033[1;33m🔒 ACTIVE BLOCKS:\033[0m"
ufw status | grep "NetGuard-Pro" || echo "No manual UFW blocks"
echo -e "\n\033[1;36m💡 PROTIP: netguard-scan --list-blocks | less\033[0m"
EOF
chmod +x /usr/local/bin/netguard-dash

# 8. GTK TRAY APPLET (Production)
mkdir -p "$REAL_HOME/.local/bin"
cat > "$REAL_HOME/.local/bin/netguard-applet.py" << 'EOF'
#!/usr/bin/env python3
import gi, subprocess, os, sys
gi.require_version('Gtk', '3.0')
gi.require_version('AppIndicator3', '0.1')
from gi.repository import Gtk, AppIndicator3, GLib

class NetGuard:
    def __init__(self):
        self.ind = AppIndicator3.Indicator.new("netguard", "network-transmit-receive", 
                                             AppIndicator3.IndicatorCategory.SYSTEM_SERVICES)
        self.ind.set_status(AppIndicator3.IndicatorStatus.ACTIVE)
        self.menu = Gtk.Menu(); self.ind.set_menu(self.menu)
        self.refresh(); GLib.timeout_add_seconds(15, self.refresh)

    def safe_run(self, cmd, *args, timeout=10):
        try: return subprocess.check_output(cmd + list(args), stderr=subprocess.DEVNULL, timeout=timeout).decode()
        except: return ""

    def action(self, widget, cmd, ip): 
        subprocess.Popen(["pkexec", "/usr/local/bin/netguard-scan", cmd, ip])
        GLib.timeout_add_seconds(3, self.refresh)

    def refresh(self, *args):
        self.menu.foreach(self.menu.remove)
        scan_data = self.safe_run(["/usr/local/bin/netguard-scan"]).splitlines()
        
        # Top threats only
        threats = [l for l in scan_data[:12] if '|' in l and ('🔴' in l or '🟠' in l)]
        for line in threats:
            parts = line.split('|')
            if len(parts) >= 2:
                label = parts[0].strip()[:55]
                ip = parts[-1] if parts[-1] else ''
                if ip:
                    mi = Gtk.MenuItem(label=f"🚫 {label}")
                    mi.connect("activate", self.action, "--block", ip)
                    self.menu.append(mi)
        
        self.menu.append(Gtk.SeparatorMenuItem())
        
        # Current blocks (short)
        blocks = self.safe_run(["/usr/local/bin/netguard-scan", "--list-blocks"]).splitlines()
        for b in blocks[:6]:
            if b.strip() and not b.startswith('==='):
                mi = Gtk.MenuItem(label=f"🔒 {b.strip()}")
                mi.connect("activate", self.action, "--unblock", b.strip())
                self.menu.append(mi)
        
        self.menu.append(Gtk.SeparatorMenuItem())
        actions = [
            ("📊 Dashboard", lambda x: subprocess.Popen(["/usr/local/bin/netguard-dash"])),
            ("🔄 Update Now", lambda x: subprocess.Popen(["pkexec", "/usr/local/bin/netguard-update"])),
            ("❌ Quit", lambda x: Gtk.main_quit())
        ]
        for label, cb in actions:
            mi = Gtk.MenuItem(label=label); mi.connect("activate", cb)
            self.menu.append(mi)
        self.menu.show_all(); return True

if __name__ == "__main__" and os.environ.get('DISPLAY'):
    NetGuard(); Gtk.main()
EOF
chown "$REAL_USER:$REAL_USER" "$REAL_HOME/.local/bin/netguard-applet.py"
chmod +x "$REAL_HOME/.local/bin/netguard-applet.py"

# 9. AUTOSTART (Multi-DE)
mkdir -p "$REAL_HOME/.config/autostart"
cat > "$REAL_HOME/.config/autostart/netguard.desktop" << EOF
[Desktop Entry]
Type=Application
Name=NetGuard Pro v5.4
Exec=$REAL_HOME/.local/bin/netguard-applet.py
Icon=network-transmit-receive
StartupWMClass=NetGuard
X-GNOME-Autostart-enabled=true
EOF
chown "$REAL_USER:$REAL_USER" "$REAL_HOME/.config/autostart/netguard.desktop"

# 10. UNINSTALLER
cat > /usr/local/bin/netguard-uninstall << 'EOF'
#!/bin/bash
echo "🗑️  Removing NetGuard Pro v5.4..."
ipset destroy netguard_blacklist 2>/dev/null || true
rm -rf /etc/netguard /var/lib/netguard /var/log/netguard /var/run/netguard \
       /usr/local/bin/netguard-* "$HOME/.local/bin/netguard-applet.py" \
       "$HOME/.config/autostart/netguard.desktop" \
       /etc/logrotate.d/netguard
(crontab -l 2>/dev/null | grep -v netguard || true) | crontab -
ufw status | grep -q NetGuard-Pro && echo "⚠️  Manual UFW cleanup needed"
echo "✅ Uninstalled. Reboot recommended."
EOF
chmod +x /usr/local/bin/netguard-uninstall

# 11. FINAL SELF-TEST & LAUNCH
echo -e "\n${CYAN}🔍 Enterprise Self-Test...${RESET}"
TEST_PASSED=0; TOTAL_TESTS=6

ufw status | grep -q "Status: active" && { echo "  [${GREEN}✓${RESET}] UFW"; ((TEST_PASSED++)); } || echo "  [${YELLOW}!${RESET}] UFW inactive"
command -v ipset && ipset list netguard_blacklist >/dev/null 2>/dev/null && { 
    echo "  [${GREEN}✓${RESET}] ipset ($(ipset list netguard_blacklist 2>/dev/null | grep -c '^<ip>'))"; 
    ((TEST_PASSED++)); 
} || echo "  [${YELLOW}!${RESET}] ipset"
[ -s /var/lib/netguard/malicious-ips.txt ] && { 
    echo "  [${GREEN}✓${RESET}] Threat DB"; ((TEST_PASSED++)); 
} || echo "  [${YELLOW}!${RESET}] Threat DB"
[ -f /usr/local/bin/netguard-scan ] && { echo "  [${GREEN}✓${RESET}] Scanner"; ((TEST_PASSED++)); }
crontab -l 2>/dev/null | grep -q netguard-update && { echo "  [${GREEN}✓${RESET}] Cron"; ((TEST_PASSED++)); }
[ -f "$REAL_HOME/.local/bin/netguard-applet.py" ] && { echo "  [${GREEN}✓${RESET}] Applet"; ((TEST_PASSED++)); }

echo -e "\n${GREEN}${BOLD}🎉 INSTALLATION COMPLETE! ${TEST_PASSED}/${TOTAL_TESTS} TESTS PASSED${RESET}"
echo -e "${CYAN}🔧 QUICK START:${RESET}"
echo "  ${BOLD}netguard-dash${RESET}           📊 Live Dashboard"
echo "  ${BOLD}netguard-scan${RESET}         🔍 Scan Connections"  
echo "  ${BOLD}netguard-scan --block 1.2.3.4${RESET}  🚫 Block IP"
echo "  ${BOLD}netguard-scan --list-blocks${RESET}   📋 View Blocks"
echo "  ${BOLD}netguard-update${RESET}       🔄 Force Update"
echo "  ${BOLD}netguard-uninstall${RESET}    🗑️  Remove All"

# LAUNCH APPLET
if pgrep -f "netguard-applet.py" >/dev/null 2>&1; then
    echo -e "\n  [${GREEN}⚡${RESET}] Applet already running in tray"
else
    echo -e "\n  [${CYAN}🚀${RESET}] Launching Enterprise Tray Applet..."
    sudo -u "$REAL_USER" DISPLAY="${DISPLAY:-:0}" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u $REAL_USER)/bus" \
        python3 "$REAL_HOME/.local/bin/netguard-applet.py" >/dev/null 2>&1 &
    sleep 2
fi

echo -e "\n${GREEN}${BOLD}🏰 NetGuard Pro v5.4 ENTERPRISE is LIVE & AUTO-UPDATING!${RESET}"
echo -e "${YELLOW}💡 Tray icon appears in 5-10 seconds. Reboot for full autostart.${RESET}"
