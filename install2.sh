#!/bin/bash
# ==============================================================================
# 🛡️ NetGuard Pro v5.4 (Final GitHub Edition)
# One-liner compatible installation script for Debian-based Linux Desktops.
# Features: UFW Integration, Live Bandwidth, Self-Test, Instant Launch.
# ==============================================================================
set -e

# --- Visual Styling ---
BOLD=$(tput bold); RESET=$(tput sgr0); GREEN='\033[0;32m'; CYAN='\033[0;36m'; RED='\033[0;31m'

# --- Root Check ---
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}${BOLD}ERROR: Please run as root or with sudo.${RESET}"
   echo "Usage: curl -sSL [link] | sudo bash"
   exit 1
fi

REAL_USER=${SUDO_USER:-$USER}
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)

echo -e "${CYAN}${BOLD}🛡️ Starting NetGuard Pro v5.4 Universal Installation...${RESET}"

# 1. Dependency Audit
echo -e "📦 Installing System Dependencies..."
apt update -qq
apt install -y curl iproute2 geoip-bin geoip-database whois ufw bc \
    python3 python3-gi python3-requests gir1.2-appindicator3-0.1 libnotify-bin gedit bsdmainutils

# Ensure UFW is active
ufw --force enable

# 2. Setup Config & Threat Intel
mkdir -p /etc/netguard /var/lib/netguard
[ ! -f /etc/netguard/whitelist.conf ] && echo -e "1.1.1.1\n8.8.8.8" > /etc/netguard/whitelist.conf
chown "$REAL_USER":"$REAL_USER" /etc/netguard/whitelist.conf

echo -e "🌐 Fetching Malicious IP Database (FireHOL)..."
curl -fsSL https://iplists.firehol.org/files/ipsum/latest.txt -o /var/lib/netguard/malicious-ips.txt

# 3. Log Setup & Rotation
touch /var/log/netguard-alerts.log
chown "$REAL_USER":"$REAL_USER" /var/log/netguard-alerts.log
cat > /etc/logrotate.d/netguard <<EOF
/var/log/netguard-alerts.log {
    weekly
    rotate 4
    compress
    missingok
    notifempty
}
EOF

# 4. Install Visual Dashboard Command
cat > /usr/local/bin/netguard-dash <<'EOF'
#!/bin/bash
LOG_FILE="/var/log/netguard-alerts.log"
echo -e "\033[1;36m╔══════════════════════════════════════════════════════════╗\033[0m"
echo -e "\033[1;36m║          🛡️  NETGUARD PRO: UFW + BANDWIDTH DASH             ║\033[0m"
echo -e "\033[1;36m╚══════════════════════════════════════════════════════════╝\033[0m"
echo -e "\033[1;33m[!] RECENT ALERTS & BLOCKS (Last 15)\033[0m"
[ -s "$LOG_FILE" ] && tail -n 15 "$LOG_FILE" | sed 's/\[BLOCK\]/\x1b[31m[BLOCK]\x1b[0m/g' | sed 's/\[UNBLOCK\]/\x1b[32m[UNBLOCK]\x1b[0m/g' | sed 's/\[ALERT\]/\x1b[33m[ALERT]\x1b[0m/g'
echo -e "\n\033[1;33m[!] ACTIVE UFW BLOCKS\033[0m"
ufw status numbered | grep "NetGuard-Pro" || echo "No active NetGuard blocks."
EOF
chmod +x /usr/local/bin/netguard-dash

# 5. Install Scanner Engine
cat > /usr/local/bin/netguard-scan <<'EOF'
#!/bin/bash
WHITELIST="/etc/netguard/whitelist.conf"
MALICIOUS_DB="/var/lib/netguard/malicious-ips.txt"
LOG_FILE="/var/log/netguard-alerts.log"
THREAT_COUNTRIES="RU CN KP IR SY IQ AF YE SO SD LB VE CU BY TR BG VN"
STATE_FILE="/tmp/netguard_bw_state"
NOW=$(date +%s)

if [ "$1" == "--block" ]; then
    ufw insert 1 deny from "$2" to any comment "NetGuard-Pro"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [BLOCK] $2" >> "$LOG_FILE"
    exit 0
elif [ "$1" == "--unblock" ]; then
    while ufw status numbered | grep -q "$2"; do
        idx=$(ufw status numbered | grep "$2" | head -1 | awk -F"[][]" '{print $2}')
        ufw --force delete "$idx"
    done
    echo "$(date '+%Y-%m-%d %H:%M:%S') [UNBLOCK] $2" >> "$LOG_FILE"
    exit 0
elif [ "$1" == "--list-blocks" ]; then
    ufw status | grep "NetGuard-Pro" | awk '{print $3}' | sort -u
    exit 0
fi

declare -A PREV_RX PREV_TX
[ -f "$STATE_FILE" ] && source "$STATE_FILE"
TMP_STATE="/tmp/netguard_bw_state.new"
echo "PREV_TS=$NOW" > "$TMP_STATE"

ss -tun state established -i | awk '/^[0-9]/ {split($5,a,":"); ip=a[1]; if(ip !~ /^(127|192\.168|10|172)/) curr=ip} /bytes:/ {if(curr) print curr "|" $2 "|" $4; curr=""}' | while IFS='|' read -r ip rx tx; do
    [[ -z "$ip" ]] && continue
    echo "PREV_RX[$ip]=$rx" >> "$TMP_STATE"
    echo "PREV_TX[$ip]=$tx" >> "$TMP_STATE"
    cc=$(geoiplookup "$ip" | awk -F, '{print $2}' | tr -d ' ' | head -n1)
    org=$(timeout 2 whois "$ip" | grep -iE "owner|orgname|organization|descr" | head -n1 | cut -d: -f2 | xargs | cut -c1-20)
    bw_info=""
    if [[ -n "${PREV_RX[$ip]}" ]]; then
        dt=$((NOW - PREV_TS)); dx=$((rx - PREV_RX[$ip])); du=$((tx - PREV_TX[$ip]))
        if [ "$dt" -gt 0 ]; then
            rx_f=$((dx/1024))KB; tx_f=$((du/1024))KB
            bw_info=" (↓$rx_f ↑$tx_f)"
        fi
    fi
    prio=0; icon="🟢"
    if grep -q "^$ip[[:space:]]" "$MALICIOUS_DB"; then prio=2; icon="🔴"
    elif [[ " $THREAT_COUNTRIES " =~ " $cc " ]]; then prio=1; icon="🟠"; fi
    echo "$prio|$icon $ip ($cc) | $org$bw_info|$ip"
done | sort -r
mv "$TMP_STATE" "$STATE_FILE" 2>/dev/null
EOF
chmod +x /usr/local/bin/netguard-scan

# 6. Install Tray Applet
mkdir -p "$REAL_HOME/.local/bin"
cat > "$REAL_HOME/.local/bin/netguard-applet.py" <<'EOF'
#!/usr/bin/env python3
import gi, subprocess, os
gi.require_version('Gtk', '3.0')
gi.require_version('AppIndicator3', '0.1')
from gi.repository import Gtk, AppIndicator3, GLib

class NetGuard:
    def __init__(self):
        self.ind = AppIndicator3.Indicator.new("netguard", "network-transmit-receive", AppIndicator3.IndicatorCategory.SYSTEM_SERVICES)
        self.ind.set_status(AppIndicator3.IndicatorStatus.ACTIVE)
        self.menu = Gtk.Menu()
        self.ind.set_menu(self.menu)
        self.refresh()
        GLib.timeout_add_seconds(10, self.refresh)

    def action(self, w, cmd, ip):
        subprocess.Popen(["pkexec", "/usr/local/bin/netguard-scan", cmd, ip])
        GLib.timeout_add_seconds(2, self.refresh)

    def refresh(self, *args):
        for c in self.menu.get_children(): self.menu.remove(c)
        try:
            out = subprocess.check_output(["/usr/local/bin/netguard-scan"]).decode().splitlines()
            for l in [x for x in out if '|' in x]:
                p, disp, info, ip = l.split('|')
                mi = Gtk.MenuItem(label=f"{disp} - {info}")
                mi.connect("activate", self.action, "--block", ip)
                self.menu.append(mi)
        except: pass
        self.menu.append(Gtk.SeparatorMenuItem())
        blocks = subprocess.getoutput("/usr/local/bin/netguard-scan --list-blocks").splitlines()
        for b_ip in [b for b in blocks if b]:
            mi = Gtk.MenuItem(label=f"Locked: {b_ip}")
            mi.connect("activate", self.action, "--unblock", b_ip)
            self.menu.append(mi)
        self.menu.append(Gtk.SeparatorMenuItem())
        q = Gtk.MenuItem(label="Quit"); q.connect("activate", Gtk.main_quit); self.menu.append(q)
        self.menu.show_all(); return True

if __name__ == "__main__": NetGuard(); Gtk.main()
EOF
chown "$REAL_USER":"$REAL_USER" "$REAL_HOME/.local/bin/netguard-applet.py"
chmod +x "$REAL_HOME/.local/bin/netguard-applet.py"

# 7. Autostart
mkdir -p "$REAL_HOME/.config/autostart"
cat > "$REAL_HOME/.config/autostart/netguard.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=NetGuard Pro
Exec=python3 $REAL_HOME/.local/bin/netguard-applet.py
Icon=network-transmit-receive
EOF
chown "$REAL_USER":"$REAL_USER" "$REAL_HOME/.config/autostart/netguard.desktop"

# 8. Self-Test & Instant Launch
echo -e "\n${CYAN}🔍 Running System Self-Test...${RESET}"
if ufw status | grep -q "active"; then
    echo -e "  [${GREEN}OK${RESET}] UFW Engine is Active"
else
    echo -e "  [${RED}!!${RESET}] UFW is inactive. Force enabling..."
    ufw --force enable
fi

if pgrep -f "netguard-applet.py" > /dev/null; then
    echo -e "  [${GREEN}OK${RESET}] Applet is already running."
else
    echo -e "  [${CYAN}>>${RESET}] Launching Tray Applet..."
    sudo -u "$REAL_USER" DISPLAY="$DISPLAY" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u "$REAL_USER")/bus" \
    python3 "$REAL_HOME/.local/bin/netguard-applet.py" > /dev/null 2>&1 &
fi

echo -e "\n${GREEN}${BOLD}✅ SUCCESS: NetGuard Pro v5.4 is fully deployed!${RESET}"
echo -e "🚀 Run '${BOLD}netguard-dash${RESET}' to see the console."
