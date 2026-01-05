#!/bin/bash
# ==============================================================================
# 🛡️ NetGuard Pro v6.1 (Enterprise Edition - Final Polished Build)
# Fixes: Duplicate Repos, Missing Dependencies, and Daily Maintenance
# ==============================================================================
set -euo pipefail

BOLD=$(tput bold 2>/dev/null || echo ""); RESET=$(tput sgr0 2>/dev/null || echo "")
GREEN='\u001B[0;32m'; CYAN='\u001B[0;36m'; RED='\u001B[0;31m'

[[ $EUID -ne 0 ]] && { echo -e "${RED}Error: Run as root.${RESET}"; exit 1; }

REAL_USER=${SUDO_USER:-$USER}
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)

echo -e "${CYAN}${BOLD}🚀 Starting NetGuard Pro v6.1 Final Deployment...${RESET}"

# 1. REPOSITORY REPAIR (Crucial fix for "configured multiple times" warnings)
echo -e "🧹 Repairing system repository configurations..."
sed -i 'N;/^(.*)
\u0001$/!P;D' /etc/apt/sources.list

# 2. SMART DEPENDENCY RESOLUTION (Ayatana vs Legacy detection)
echo -e "📦 Installing hardened dependencies..."
apt update -qq >/dev/null
if apt-cache show gir1.2-ayatanaappindicator3-0.1 >/dev/null 2>&1; then
    APP_IND="gir1.2-ayatanaappindicator3-0.1"
else
    APP_IND="gir1.2-appindicator3-0.1"
fi
apt install -y curl ipset ufw python3 python3-gi "$APP_IND" \
               gir1.2-notify-0.7 sqlite3 netcat-openbsd geoip-bin libnotify-bin >/dev/null

# 3. DIRECTORY SETUP
mkdir -p /etc/netguard /var/lib/netguard /var/log/netguard /run/netguard /var/cache/netguard
groupadd -f netguard-admin && usermod -aG netguard-admin "$REAL_USER"
chown root:netguard-admin /run/netguard /var/log/netguard
chmod 775 /run/netguard /var/log/netguard

# 4. BACKEND: The Guardian (Hardened socket listener)
cat << 'EOF' > /usr/local/bin/netguard-core
#!/bin/bash
SOCKET="/run/netguard/control.sock"
LOG="/var/log/netguard/audit.log"
validate_ip() {
    [[ $1 =~ ^([0-9]{1,3}.){3}[0-9]{1,3}$ ]] || return 1
    IFS='.' read -r -a o <<< "$1"
    [[ ${o[0]} -le 255 && ${o[1]} -le 255 && ${o[2]} -le 255 && ${o[3]} -le 255 ]]
}
rm -f "$SOCKET"
while true; do
    cmd=$(timeout 1 nc -Ul "$SOCKET" || true)
    [[ -z "$cmd" ]] && continue
    action=$(echo "$cmd" | cut -d' ' -f1); target=$(echo "$cmd" | cut -d' ' -f2)
    if validate_ip "$target"; then
        case "$action" in
            BLOCK)
                ipset add netguard_blacklist "$target" 2>/dev/null
                ufw insert 1 deny from "$target" to any comment "NetGuard-Pro"
                echo "$(date) [AUDIT] Blocked: $target" >> "$LOG" ;;
            UNBLOCK)
                ipset del netguard_blacklist "$target" 2>/dev/null
                for r in $(ufw status numbered | grep "NetGuard-Pro" | grep "$target" | awk -F"[][]" '{print $2}'); do
                    ufw --force delete "$r"
                done
                echo "$(date) [AUDIT] Unblocked: $target" >> "$LOG" ;;
        esac
    fi
done
EOF
chmod 755 /usr/local/bin/netguard-core

# 5. MAINTENANCE: Daily Health Check
cat << 'EOF' > /usr/local/bin/netguard-maint
#!/bin/bash
ipset create netguard_blacklist hash:ip 2>/dev/null || true
ufw status | grep -q "active" || ufw --force enable
echo "$(date) [MAINT] Health check completed." >> /var/log/netguard/audit.log
EOF
chmod 755 /usr/local/bin/netguard-maint

# 6. SYSTEMD CONFIG
cat << EOF > /etc/systemd/system/netguard.service
[Unit]
Description=NetGuard Pro Backend
After=network.target ufw.service
[Service]
ExecStart=/usr/local/bin/netguard-core
Restart=always
User=root
[Install]
WantedBy=multi-user.target
EOF

cat << EOF > /etc/systemd/system/netguard-maint.timer
[Unit]
Description=Daily Maintenance
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
EOF

cat << EOF > /etc/systemd/system/netguard-maint.service
[Unit]
Description=NetGuard Maint
[Service]
Type=oneshot
ExecStart=/usr/local/bin/netguard-maint
EOF

# 7. FRONTEND: Applet (Distro-aware Ayatana/Legacy support)
cat << 'EOF' > /usr/local/bin/netguard-applet
#!/usr/bin/env python3
import gi, subprocess, os
gi.require_version('Gtk', '3.0')
try:
    gi.require_version('AyatanaAppIndicator3', '0.1')
    from gi.repository import AyatanaAppIndicator3 as AppIndicator3
except (ImportError, ValueError):
    gi.require_version('AppIndicator3', '0.1')
    from gi.repository import AppIndicator3
gi.require_version('Notify', '0.7')
from gi.repository import Gtk, GLib, Notify

SOCKET = "/run/netguard/control.sock"
THREAT_COUNTRIES = ["Russia", "China", "North Korea"]

class NetGuardUI:
    def __init__(self):
        Notify.init("NetGuard Pro")
        self.ind = AppIndicator3.Indicator.new("netguard", "network-transmit-receive", AppIndicator3.IndicatorCategory.SYSTEM_SERVICES)
        self.ind.set_status(AppIndicator3.IndicatorStatus.ACTIVE)
        self.menu = Gtk.Menu(); self.ind.set_menu(self.menu)
        self.known_ips = set()
        self.refresh(); GLib.timeout_add_seconds(10, self.refresh)

    def send_to_socket(self, action, ip):
        payload = f"{action} {ip}".encode()
        subprocess.run(["nc", "-U", SOCKET], input=payload, check=False)

    def trigger_notification(self, ip, country):
        n = Notify.Notification.new("🛡️ NetGuard Threat", f"Connection: {ip} ({country})", "network-error")
        n.set_urgency(Notify.Urgency.CRITICAL)
        n.add_action("block", "Block IP", self.on_notification_click, ip); n.show()

    def on_notification_click(self, n, action, ip):
        self.send_to_socket("BLOCK", ip)

    def refresh(self, *args):
        self.menu.foreach(self.menu.remove)
        raw = subprocess.getoutput("ss -tun state established | awk 'NR>1 {split($5,a,":"); print a[1]}' | sort -u")
        for ip in raw.splitlines():
            if ip and ip not in self.known_ips:
                country = subprocess.getoutput(f"geoiplookup {ip} | cut -d: -f2").strip()
                if any(c in country for c in THREAT_COUNTRIES):
                    self.trigger_notification(ip, country)
                self.known_ips.add(ip)
            mi = Gtk.MenuItem(label=f"🟢 {ip}"); mi.connect("activate", lambda w, i=ip: self.send_to_socket("BLOCK", i))
            self.menu.append(mi)
        q = Gtk.MenuItem(label="Exit"); q.connect("activate", Gtk.main_quit); self.menu.append(q)
        self.menu.show_all(); return True

if __name__ == "__main__":
    NetGuardUI(); Gtk.main()
EOF
chmod 755 /usr/local/bin/netguard-applet

# 8. ACTIVATION
echo -e "⚙️ Activating services..."
ufw --force enable || true
systemctl daemon-reload
systemctl enable --now netguard netguard-maint.timer
ipset create netguard_blacklist hash:ip 2>/dev/null || true

# User Autostart
mkdir -p "$REAL_HOME/.config/autostart"
cat << EOF > "$REAL_HOME/.config/autostart/netguard.desktop"
[Desktop Entry]
Type=Application
Name=NetGuard Pro
Exec=/usr/local/bin/netguard-applet
Icon=network-transmit-receive
EOF
chown "$REAL_USER:$REAL_USER" "$REAL_HOME/.config/autostart/netguard.desktop"

echo -e "
${GREEN}${BOLD}🏰 NETGUARD PRO v6.1 FULLY DEPLOYED!${RESET}"
echo -e "${CYAN}Repo fixed, Ayatana detected, services active.${RESET}"
echo -e "${YELLOW}Test: netguard-applet${RESET}"
