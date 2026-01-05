#!/bin/bash
# ==============================================================================
# 🛡️ NetGuard Pro v6.1 (Enterprise Edition - FINAL VERIFIED)
# Fixes: SED error, Python string breaks, and UFW indexing
# ==============================================================================
set -euo pipefail

BOLD=$(tput bold 2>/dev/null || echo ""); RESET=$(tput sgr0 2>/dev/null || echo "")
GREEN='\033[0;32m'; CYAN='\033[0;36m'; RED='\033[0;31m'; YELLOW='\033[1;33m'

[[ $EUID -ne 0 ]] && { echo -e "${RED}Error: Run as root.${RESET}"; exit 1; }

REAL_USER=${SUDO_USER:-$USER}
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)

echo -e "${CYAN}${BOLD}🚀 Starting NetGuard Pro v6.1 Final Deployment...${RESET}"

# 1. SAFE REPOSITORY REPAIR (Using awk to avoid sed regex errors)
echo -e "🧹 Cleaning repository duplicates..."
awk '!seen[$0]++' /etc/apt/sources.list > /tmp/sources.list.tmp && mv /tmp/sources.list.tmp /etc/apt/sources.list

# 2. SMART DEPENDENCY RESOLUTION
echo -e "📦 Installing dependencies..."
apt update -qq >/dev/null 2>&1
if apt-cache show gir1.2-ayatanaappindicator3-0.1 >/dev/null 2>&1; then
    APP_IND="gir1.2-ayatanaappindicator3-0.1"
else
    APP_IND="gir1.2-appindicator3-0.1"
fi
apt install -y curl ipset ufw python3 python3-gi "$APP_IND" gir1.2-notify-0.7 \
    sqlite3 netcat-openbsd geoip-bin libnotify-bin >/dev/null 2>&1

# 3. DIRECTORY & PERMISSIONS
mkdir -p /etc/netguard /var/lib/netguard /var/log/netguard /run/netguard /var/cache/netguard
touch /var/log/netguard/audit.log
groupadd -f netguard-admin && usermod -aG netguard-admin "$REAL_USER" 2>/dev/null || true
chown root:netguard-admin /run/netguard /var/log/netguard /var/log/netguard/audit.log
chmod 775 /run/netguard /var/log/netguard
chmod 664 /var/log/netguard/audit.log

# 4. BACKEND DAEMON
cat << 'EOF' > /usr/local/bin/netguard-core
#!/bin/bash
SOCKET="/run/netguard/control.sock"
LOG="/var/log/netguard/audit.log"
validate_ip() {
    [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS='.' read -r -a o <<< "$1"
    [[ ${o[0]} -le 255 && ${o[1]} -le 255 && ${o[2]} -le 255 && ${o[3]} -le 255 ]]
}
rm -f "$SOCKET"
while true; do
    cmd=$(timeout 2 nc -Ul "$SOCKET" 2>/dev/null || true)
    [[ -z "$cmd" ]] && continue
    action=$(echo "$cmd" | awk '{print $1}')
    target=$(echo "$cmd" | awk '{print $2}')
    if validate_ip "$target"; then
        case "$action" in
            BLOCK)
                ipset add netguard_blacklist "$target" 2>/dev/null || true
                ufw insert 1 deny from "$target" to any comment "NetGuard-Pro" 2>/dev/null || true
                echo "$(date '+%Y-%m-%d %H:%M:%S') [BLOCK] $target" >> "$LOG"
                ;;
            UNBLOCK)
                ipset del netguard_blacklist "$target" 2>/dev/null || true
                for r in $(ufw status numbered | grep "NetGuard-Pro" | grep "$target" | awk -F"[][]" '{print $2}' | sort -rn); do
                    ufw --force delete "$r" 2>/dev/null || true
                done
                echo "$(date '+%Y-%m-%d %H:%M:%S') [UNBLOCK] $target" >> "$LOG"
                ;;
        esac
    fi
done
EOF
chmod 755 /usr/local/bin/netguard-core

# 5. MAINTENANCE SCRIPT
cat << 'EOF' > /usr/local/bin/netguard-maint
#!/bin/bash
ipset create netguard_blacklist hash:ip 2>/dev/null || true
ufw status | grep -q "Status: active" || ufw --force enable 2>/dev/null || true
EOF
chmod 755 /usr/local/bin/netguard-maint

# 6. SYSTEMD SERVICES
cat << EOF > /etc/systemd/system/netguard.service
[Unit]
Description=NetGuard Pro Backend
After=network.target ufw.service
[Service]
ExecStart=/usr/local/bin/netguard-core
Restart=always
[Install]
WantedBy=multi-user.target
EOF

cat << EOF > /etc/systemd/system/netguard-maint.timer
[Unit]
Description=NetGuard Daily Maint
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
EOF

# 7. INTERACTIVE APPLET (Tray Icon)
cat << 'EOF' > /usr/local/bin/netguard-applet
#!/usr/bin/env python3
import gi, subprocess, os, sys
gi.require_version('Gtk', '3.0')
try:
    gi.require_version('AyatanaAppIndicator3', '0.1')
    from gi.repository import AyatanaAppIndicator3 as AppIndicator3
except:
    gi.require_version('AppIndicator3', '0.1')
    from gi.repository import AppIndicator3

gi.require_version('Notify', '0.7')
from gi.repository import Gtk, GLib, Notify

SOCKET = "/run/netguard/control.sock"

class NetGuardUI:
    def __init__(self):
        Notify.init("NetGuard Pro")
        self.ind = AppIndicator3.Indicator.new("netguard", "network-security", AppIndicator3.IndicatorCategory.SYSTEM_SERVICES)
        self.ind.set_status(AppIndicator3.IndicatorStatus.ACTIVE)
        self.menu = Gtk.Menu()
        self.ind.set_menu(self.menu)
        self.refresh()
        GLib.timeout_add_seconds(10, self.refresh)

    def send_to_socket(self, action, ip):
        try:
            payload = f"{action} {ip}\n".encode()
            subprocess.run(["nc", "-U", SOCKET], input=payload, check=False)
        except: pass

    def refresh(self, *args):
        for child in self.menu.get_children(): self.menu.remove(child)
        raw = subprocess.getoutput("ss -tunap state established | awk 'NR>1 {split($5,a,\":\"); print a[1]}' | grep -E '^[0-9]' | sort -u | head -15")
        for ip in raw.splitlines():
            if ip.strip():
                mi = Gtk.MenuItem(label=f"🛑 Block {ip.strip()}")
                mi.connect("activate", lambda w, i=ip.strip(): self.send_to_socket("BLOCK", i))
                self.menu.append(mi)
        q = Gtk.MenuItem(label="Exit")
        q.connect("activate", Gtk.main_quit)
        self.menu.append(q)
        self.menu.show_all()
        return True

if __name__ == "__main__":
    NetGuardUI()
    Gtk.main()
EOF
chmod 755 /usr/local/bin/netguard-applet

# 8. ACTIVATION
systemctl daemon-reload
systemctl enable --now netguard netguard-maint.timer
ipset create netguard_blacklist hash:ip 2>/dev/null || true

echo -e "${GREEN}${BOLD}🏰 NETGUARD PRO v6.1 DEPLOYED!${RESET}"
