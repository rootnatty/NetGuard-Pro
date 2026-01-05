#!/bin/bash
# ==============================================================================
# 🛡️ NetGuard Pro v6.3 (FINAL VERIFIED LTS BUILD)
# ==============================================================================
set -euo pipefail

BOLD=$(tput bold 2>/dev/null || echo ""); RESET=$(tput sgr0 2>/dev/null || echo "")
GREEN='\033[0;32m'; CYAN='\033[0;36m'; RED='\033[0;31m'; YELLOW='\033[1;33m'

[[ $EUID -ne 0 ]] && { echo -e "${RED}Error: Run as root.${RESET}"; exit 1; }

REAL_USER=${SUDO_USER:-$USER}
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)

echo -e "${CYAN}${BOLD}🚀 Deploying NetGuard Pro v6.3 LTS Production...${RESET}"

# 1. DEPENDENCIES (✅ ERROR CHECKING + VERBOSE)
echo -e "📦 Installing Core Dependencies..."
apt update -qq || { echo "❌ apt update failed"; exit 1; }

if apt-cache show gir1.2-ayatanaappindicator3-0.1 >/dev/null 2>&1; then
  APP_IND="gir1.2-ayatanaappindicator3-0.1"
else
  APP_IND="gir1.2-appindicator3-0.1"
fi

apt install -y curl ipset ufw python3 python3-gi python3-whois "$APP_IND" \
  gir1.2-notify-0.7 netcat-openbsd geoip-bin libnotify-bin mailutils logrotate || {
    echo -e "${RED}❌ CRITICAL: Package installation failed${RESET}"
    echo "Run: sudo apt install ipset"
    exit 1
}

# ✅ VERIFY ipset works
command -v ipset >/dev/null || { echo "❌ ipset still missing"; exit 1; }
echo -e "${GREEN}✅ Dependencies OK${RESET}"


# 2. PERMISSIONS & DIRECTORIES
mkdir -p /etc/netguard /var/log/netguard /run/netguard
groupadd -f netguard-admin && usermod -aG netguard-admin "$REAL_USER" || true
touch /var/log/netguard/audit.log
chown root:netguard-admin /run/netguard /var/log/netguard /var/log/netguard/audit.log
chmod 775 /run/netguard /var/log/netguard
chmod 664 /var/log/netguard/audit.log

# 3. BACKEND DAEMON
cat << 'EOF' > /usr/local/bin/netguard-core
#!/bin/bash
PIPE="/run/netguard/control.fifo"
LOG="/var/log/netguard/audit.log"
rm -f "$PIPE" && mkfifo "$PIPE"
chmod 666 "$PIPE"
chown root:netguard-admin "$PIPE"
ipset create netguard_blacklist hash:ip 2>/dev/null || true

# Mandatory Fix: Correct Signal handling for log rotation
reopen_logs() { exec 1>>"$LOG" 2>&1; }
trap reopen_logs HUP
reopen_logs

exec 3<> "$PIPE"

validate_ip() {
  [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS='.' read -r -a o <<< "$1"
  for i in {0..3}; do [[ ${o[$i]} -le 255 ]] || return 1; done
}

echo "NetGuard Core Active..."
while read -u 3 -r cmd; do
  action=$(echo "$cmd" | awk '{print toupper($1)}')
  target=$(echo "$cmd" | awk '{print $2}')
  if [[ "$action" == "BLOCK" ]] && validate_ip "$target"; then
    ipset add netguard_blacklist "$target" 2>/dev/null || true
    ufw insert 1 deny from "$target" to any comment "NetGuard-Pro" >/dev/null 2>&1 || \
    ufw deny from "$target" to any comment "NetGuard-Pro" >/dev/null 2>&1
    echo "$(date '+%F %T') [BLOCK] $target"
  elif [[ "$action" == "CLEAR" ]]; then
    ipset flush netguard_blacklist 2>/dev/null || true
    ufw status numbered | grep "NetGuard-Pro" | awk -F"[][]" '{print $2}' | sort -rn | \
    while read -r line; do ufw --force delete "$line" >/dev/null 2>&1; done
    echo "$(date '+%F %T') [CLEAR] Flushed all rules"
  fi
done
EOF
chmod 755 /usr/local/bin/netguard-core

# 4. PYTHON APPLET
cat << 'EOF' > /usr/local/bin/netguard-applet
#!/usr/bin/env python3
import os, subprocess, gi
os.environ['GDK_BACKEND'] = 'x11'
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GLib, Notify
try:
    gi.require_version('AyatanaAppIndicator3', '0.1')
    from gi.repository import AyatanaAppIndicator3 as AppIndicator3
except (ValueError, ImportError):
    gi.require_version('AppIndicator3', '0.1')
    from gi.repository import AppIndicator3

PIPE = "/run/netguard/control.fifo"
FLAGS = {'RU':'🇷🇺','CN':'🇨🇳','IR':'🇮🇷','KP':'🇰🇵','US':'🇺🇸','GB':'🇬🇧','DE':'🇩🇪','FR':'🇫🇷'}

class NetGuardUI:
    def __init__(self):
        Notify.init("NetGuard Pro")
        self.ind = AppIndicator3.Indicator.new("netguard", "network-transmit-receive", AppIndicator3.IndicatorCategory.SYSTEM_SERVICES)
        self.ind.set_status(AppIndicator3.IndicatorStatus.ACTIVE)
        self.menu = Gtk.Menu()
        self.ind.set_menu(self.menu)
        self.refresh()
        GLib.timeout_add_seconds(12, self.refresh)

    def send_cmd(self, cmd):
        try:
            fd = os.open(PIPE, os.O_WRONLY | os.O_NONBLOCK)
            os.write(fd, (cmd + "\n").encode())
            os.close(fd)
        except OSError:
            pass # Backend busy or unavailable

    def refresh(self, *args):
        for child in self.menu.get_children(): self.menu.remove(child)
        try:
            # -H strips headers for cleaner parsing
            raw = subprocess.getoutput("ss -ntuH state established | awk '{split($5,a,\":\");print a[1]}' | grep -vE '^(127\\.0\\.0\\.1|::1)' | sort -u | head -12")
            for ip in raw.splitlines():
                if ip.strip():
                    cc = subprocess.getoutput(f"geoiplookup {ip} | awk -F', ' '{{print $2}}' | awk '{{print $1}}'").strip()
                    flag = FLAGS.get(cc, '🌐')
                    item = Gtk.MenuItem(label=f"{flag} {ip} ({cc})")
                    sub = Gtk.Menu()
                    blk = Gtk.MenuItem(label="🛑 BLOCK IP")
                    blk.connect("activate", lambda w, i=ip: self.send_cmd(f"BLOCK {i}"))
                    sub.append(blk); item.set_submenu(sub); self.menu.append(item)
        except: pass
        self.menu.append(Gtk.SeparatorMenuItem())
        clr = Gtk.MenuItem(label="🗑️ Flush All Blocks")
        clr.connect("activate", lambda w: self.send_cmd("CLEAR"))
        self.menu.append(clr); q = Gtk.MenuItem(label="❌ Exit")
        q.connect("activate", Gtk.main_quit); self.menu.append(q); self.menu.show_all()
        return True

if __name__ == "__main__":
    NetGuardUI(); Gtk.main()
EOF
chmod 755 /usr/local/bin/netguard-applet

# 5. DAILY REPORT
cat << 'EOF' > /usr/local/bin/netguard-report
#!/usr/bin/env bash
LOG="/var/log/netguard/audit.log"
REPORT="/var/log/netguard/report-$(date +%F).html"
MAIL_TO="admin@example.com"
declare -A FLAGS=([RU]="🇷🇺" [CN]="🇨🇳" [IR]="🇮🇷" [KP]="🇰🇵" [US]="🇺🇸" [GB]="🇬🇧" [DE]="🇩🇪" [FR]="🇫🇷")
HTML_HEAD='<html><body style="font-family:sans-serif;padding:20px;">'

{
echo "$HTML_HEAD"
echo "<h1>NetGuard Report — $(date '+%F %T')</h1>"
echo "<h2>⚔️ Blocked IPs</h2><table border='1'><tr><th>Flag</th><th>IP</th></tr>"
for ip in $(ipset list netguard_blacklist 2>/dev/null | grep -E '^[0-9]'); do
  cc=$(geoiplookup "$ip" 2>/dev/null | awk -F', ' '{print $2}' | awk '{print $1}')
  echo "<tr><td>${FLAGS[$cc]:-🌐}</td><td>$ip</td></tr>"
done
echo "</table><h2>🏆 Top Offenders</h2><ul>"
awk '/\[BLOCK\]/{print $NF}' "$LOG" | sort | uniq -c | sort -rn | head -10 | while read c i; do echo "<li>$i — $c hits</li>"; done
echo "</ul></body></html>"
} > "$REPORT"

find /var/log/netguard -name 'report-*.html' -mtime +7 -delete 2>/dev/null
# Mandatory Fix: use 'mail' instead of 'mailx' for mailutils compatibility
if command -v mail >/dev/null; then
  cat "$REPORT" | mail -a "Content-Type: text/html" -s "📊 NetGuard Report — $(hostname)" "$MAIL_TO"
fi
EOF
chmod 755 /usr/local/bin/netguard-report

# 6. LOGROTATE CONFIGURATION
cat << 'EOF' > /etc/logrotate.d/netguard
/var/log/netguard/audit.log {
    weekly
    rotate 8
    size 5M
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root netguard-admin
    postrotate
        /usr/bin/systemctl kill -s HUP netguard.service >/dev/null 2>&1 || true
    endscript
}
EOF

# 7. SYSTEMD & ACTIVATION
cat << EOF > /etc/systemd/system/netguard.service
[Unit]
Description=NetGuard Core
After=network.target
[Service]
ExecStart=/usr/local/bin/netguard-core
Restart=always
[Install]
WantedBy=multi-user.target
EOF

cat << EOF > /etc/systemd/system/netguard-report.timer
[Unit]
Description=Daily Report Timer
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
EOF

mkdir -p "$REAL_HOME/.config/autostart"
cat << EOF > "$REAL_HOME/.config/autostart/netguard.desktop"
[Desktop Entry]
Type=Application
Name=NetGuard Pro
Exec=env GDK_BACKEND=x11 /usr/local/bin/netguard-applet
Icon=network-transmit-receive
EOF
chown -R "$REAL_USER:$REAL_USER" "$REAL_HOME/.config"

systemctl daemon-reload
systemctl enable --now netguard netguard-report.timer >/dev/null 2>&1
ipset create netguard_blacklist hash:ip 2>/dev/null || true

echo -e "\n${GREEN}${BOLD}✅ NETGUARD PRO v6.3 DEPLOYED SUCCESSFULLY!${RESET}"

