#!/bin/bash
# ==============================================================================
# 🛡️ NetGuard Pro v6.3 LTS - FINAL PRODUCTION PERFECT
# ==============================================================================
set -euo pipefail

BOLD=$(tput bold 2>/dev/null || echo ""); RESET=$(tput sgr0 2>/dev/null || echo "")
GREEN='\033[0;32m'; CYAN='\033[0;36m'; RED='\033[0;31m'; YELLOW='\033[1;33m'

[[ $EUID -ne 0 ]] && { echo -e "${RED}❌ Run as root${RESET}"; exit 1; }
REAL_USER=${SUDO_USER:-$USER}
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)

echo -e "${CYAN}${BOLD}🚀 Deploying NetGuard Pro v6.3 LTS Ultimate...${RESET}"

# 1. DEPENDENCIES
echo -e "📦 Dependencies..."
apt update -qq >/dev/null 2>&1
APP_IND=$(apt-cache show gir1.2-ayatanaappindicator3-0.1 >/dev/null 2>&1 && echo "gir1.2-ayatanaappindicator3-0.1" || echo "gir1.2-appindicator3-0.1")
apt install -y curl ipset ufw python3 python3-gi python3-whois "$APP_IND" gir1.2-notify-0.7 netcat-openbsd geoip-bin libnotify-bin mailutils logrotate whois >/dev/null 2>&1
command -v ipset >/dev/null 2>&1 || { echo -e "${RED}❌ ipset missing${RESET}"; exit 1; }
echo -e "  ${GREEN}✅ OK${RESET}"

# 2. INFRASTRUCTURE & PERMISSIONS
echo -e "🏗️  Infrastructure..."
mkdir -p /etc/netguard /var/log/netguard /run/netguard
groupadd -f netguard-admin && usermod -aG netguard-admin "$REAL_USER" || true
touch /var/log/netguard/audit.log
chown root:netguard-admin /run/netguard /var/log/netguard /var/log/netguard/audit.log
chmod 775 /run/netguard /var/log/netguard && chmod 664 /var/log/netguard/audit.log
echo -e "  ${GREEN}✅ Permissions${RESET}"

# 3. CORE DAEMON
cat > /usr/local/bin/netguard-core << 'EOF'
#!/bin/bash
PIPE="/run/netguard/control.fifo"
LOG="/var/log/netguard/audit.log"
rm -f "$PIPE" && mkfifo "$PIPE" && chmod 666 "$PIPE" && chown root:netguard-admin "$PIPE"
ipset create netguard_blacklist hash:ip 2>/dev/null || true

log_msg() { echo "$(date '+%F %T') $1" | tee -a "$LOG"; }
reopen_logs() { exec 1>>"$LOG" 2>&1; }; trap reopen_logs HUP; reopen_logs

exec 3<> "$PIPE"
log_msg "NetGuard Core v6.3 Active"

while read -u 3 -r cmd; do
    action=$(echo "$cmd" | awk '{print toupper($1)}')
    target=$(echo "$cmd" | awk '{print $2}')
    
    if [[ "$action" == "BLOCK" && "$target" =~ ^[0-9.]+$ ]]; then
        ipset add netguard_blacklist "$target" 2>/dev/null || true
        ufw insert 1 deny from "$target" to any comment "NetGuard-Pro" >/dev/null 2>&1 || ufw deny from "$target" >/dev/null 2>&1
        log_msg "[BLOCK] $target"
    elif [[ "$action" == "UNBLOCK" && "$target" =~ ^[0-9.]+$ ]]; then
        ipset del netguard_blacklist "$target" 2>/dev/null || true
        ufw status numbered 2>/dev/null | grep "$target" | awk -F"[][]" '{print $2}' | sort -rn | while read line; do 
            [ -n "$line" ] && ufw --force delete "$line" >/dev/null 2>&1
        done
        log_msg "[UNBLOCK] $target"
    elif [[ "$action" == "CLEAR" ]]; then
        ipset flush netguard_blacklist 2>/dev/null || true
        ufw status numbered 2>/dev/null | grep "NetGuard-Pro" | awk -F"[][]" '{print $2}' | sort -rn | while read line; do 
            [ -n "$line" ] && ufw --force delete "$line" >/dev/null 2>&1
        done
        log_msg "[CLEAR] All rules flushed"
    fi
done
EOF
chmod 755 /usr/local/bin/netguard-core
echo -e "  ${GREEN}✅ Core Daemon${RESET}"

# 4. TRAY APPLET
cat > /usr/local/bin/netguard-applet << 'EOF'
#!/usr/bin/env python3
import os, subprocess, gi, threading
os.environ['GDK_BACKEND'] = 'x11'
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GLib, Notify
try: 
    gi.require_version('AyatanaAppIndicator3', '0.1')
    from gi.repository import AyatanaAppIndicator3 as AppIndicator3
except: 
    gi.require_version('AppIndicator3', '0.1')
    from gi.repository import AppIndicator3

PIPE = "/run/netguard/control.fifo"
LOG_FILE = "/var/log/netguard/audit.log"
FLAGS = {'RU':'🇷🇺','CN':'🇨🇳','IR':'🇮🇷','KP':'🇰🇵','SY':'🇸🇾','IQ':'🇮🇶','US':'🇺🇸','GB':'🇬🇧','DE':'🇩🇪','FR':'🇫🇷'}

class NetGuardUI:
    def __init__(self):
        Notify.init("NetGuard Pro v6.3")
        self.ind = AppIndicator3.Indicator.new("netguard", "network-transmit-receive", AppIndicator3.IndicatorCategory.SYSTEM_SERVICES)
        self.ind.set_status(AppIndicator3.IndicatorStatus.ACTIVE)
        self.menu = Gtk.Menu(); self.ind.set_menu(self.menu)
        self.refresh(); GLib.timeout_add_seconds(12, self.refresh)

    def send_cmd(self, cmd):
        try:
            with open(PIPE, 'w') as f: f.write(cmd + "\n"); f.flush()
            Notify.Notification.new("NetGuard", f"✓ {cmd}", "dialog-information").show()
        except: pass

    def open_logs(self, widget):
        subprocess.Popen(["x-terminal-emulator", "-e", "tail", "-f", LOG_FILE])

    def show_whois(self, ip):
        def run():
            data = subprocess.getoutput(f"timeout 3 whois {ip} | grep -iE 'org|descr|country' | head -5 | tr '\\n' ' | '").strip()
            GLib.idle_add(self.show_dialog, f"WHOIS: {ip}", data or "No data")
        threading.Thread(target=run, daemon=True).start()

    def show_dialog(self, title, text):
        dialog = Gtk.MessageDialog(None, 0, Gtk.MessageType.INFO, Gtk.ButtonsType.OK, title)
        dialog.format_secondary_text(text[:250]); dialog.run(); dialog.destroy()

    def refresh(self, *args):
        self.menu.foreach(self.menu.remove)
        
        live = Gtk.MenuItem("🔴 LIVE CONNECTIONS"); live.set_sensitive(False); self.menu.append(live)
        try:
            raw = subprocess.getoutput("ss -ntuH state established | awk '{split($5,a,\":\");print a[1]}' | grep -vE '^(127|192.168|10|172|::1)' | sort -u | head -10")
            for ip in raw.splitlines():
                if ip.strip():
                    cc = subprocess.getoutput(f"timeout 1 geoiplookup {ip} | awk -F', ' '{{print $2}}' | head -1").strip()
                    flag = FLAGS.get(cc, '🌐')
                    item = Gtk.MenuItem(f"{flag} {ip} ({cc})")
                    sub = Gtk.Menu()
                    blk = Gtk.MenuItem("🛑 BLOCK"); blk.connect("activate", lambda w, i=ip.strip(): self.send_cmd(f"BLOCK {i}"))
                    whois = Gtk.MenuItem("🔍 WHOIS"); whois.connect("activate", lambda w, i=ip.strip(): self.show_whois(i))
                    sub.append(blk); sub.append(whois); item.set_submenu(sub); self.menu.append(item)
        except: pass

        self.menu.append(Gtk.SeparatorMenuItem())
        
        blocked = Gtk.MenuItem("🚫 BLOCKED IPS"); blocked.set_sensitive(False); self.menu.append(blocked)
        try:
            blist = subprocess.getoutput("ipset list netguard_blacklist 2>/dev/null | grep '^[0-9]' | head -8")
            for b_ip in blist.splitlines():
                if b_ip.strip():
                    item = Gtk.MenuItem(f"🚫 {b_ip.strip()}")
                    sub = Gtk.Menu()
                    unblk = Gtk.MenuItem("✅ UNBLOCK"); unblk.connect("activate", lambda w, i=b_ip.strip(): self.send_cmd(f"UNBLOCK {i}"))
                    sub.append(unblk); item.set_submenu(sub); self.menu.append(item)
        except: pass

        self.menu.append(Gtk.SeparatorMenuItem())
        view_logs = Gtk.MenuItem("📋 View Audit Logs"); view_logs.connect("activate", self.open_logs); self.menu.append(view_logs)
        clear = Gtk.MenuItem("🗑️ CLEAR ALL"); clear.connect("activate", lambda w: self.send_cmd("CLEAR"))
        self.menu.append(clear)
        quit_item = Gtk.MenuItem("❌ Quit"); quit_item.connect("activate", Gtk.main_quit)
        self.menu.append(quit_item); self.menu.show_all(); return True

if __name__ == "__main__": NetGuardUI(); Gtk.main()
EOF
chmod 755 /usr/local/bin/netguard-applet
echo -e "  ${GREEN}✅ Tray Applet${RESET}"

# 5. HEALTH CHECK
cat > /usr/local/bin/netguard-health << 'EOF'
#!/bin/bash
CYAN='\033[0;36m'; GREEN='\033[0;32m'; RED='\033[0;31m'; RESET='\033[0m'; BOLD='\033[1m'
echo -e "${CYAN}${BOLD}🩺 NetGuard Pro v6.3 Health Check${RESET}"
[[ -p /run/netguard/control.fifo ]] && echo -e "  ✅ ${GREEN}FIFO Pipe${RESET}" || echo -e "  ❌ ${RED}FIFO Pipe${RESET}"
systemctl is-active --quiet netguard 2>/dev/null && echo -e "  ✅ ${GREEN}Core Daemon${RESET}" || echo -e "  ❌ ${RED}Core Daemon${RESET}"
ipset list netguard_blacklist >/dev/null 2>/dev/null && echo -e "  ✅ ${GREEN}IPSet Ready${RESET}" || echo -e "  ❌ ${RED}IPSet Missing${RESET}"
ufw status 2>/dev/null | grep -q active && echo -e "  ✅ ${GREEN}UFW Active${RESET}" || echo -e "  ❌ ${RED}UFW Inactive${RESET}"
echo -e "${CYAN}📊 Blocked: $(ipset list netguard_blacklist 2>/dev/null | grep -c '^[0-9]' || echo 0) IPs${RESET}"
EOF
chmod 755 /usr/local/bin/netguard-health
echo -e "  ${GREEN}✅ Health Check${RESET}"

# 6. LOGROTATE
cat > /etc/logrotate.d/netguard << 'EOF'
/var/log/netguard/audit.log {
    weekly
    rotate 12
    size 10M
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root netguard-admin
    postrotate
        systemctl kill -s HUP netguard >/dev/null 2>&1 || true
    endscript
}
EOF
echo -e "  ${GREEN}✅ Logrotate${RESET}"

# 7. SYSTEMD
cat > /etc/systemd/system/netguard.service << 'EOF'
[Unit]
Description=NetGuard Pro v6.3 Core Daemon
After=network.target

[Service]
ExecStart=/usr/local/bin/netguard-core
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF
echo -e "  ${GREEN}✅ Systemd${RESET}"

# 8. AUTOSTART
mkdir -p "$REAL_HOME/.config/autostart"
cat > "$REAL_HOME/.config/autostart/netguard.desktop" << EOF
[Desktop Entry]
Type=Application
Name=NetGuard Pro v6.3
Exec=env GDK_BACKEND=x11 /usr/local/bin/netguard-applet
Icon=network-transmit-receive
StartupWMClass=NetGuard
X-GNOME-Autostart-enabled=true
EOF
chown -R "$REAL_USER:$REAL_USER" "$REAL_HOME/.config"
echo -e "  ${GREEN}✅ Autostart${RESET}"

# 9. FINAL ACTIVATION
chmod 755 /usr/local/bin/netguard-*
systemctl daemon-reload
systemctl enable --now netguard >/dev/null 2>&1
ipset create netguard_blacklist hash:ip 2>/dev/null || true
ufw --force enable >/dev/null 2>&1

echo -e "\n${GREEN}${BOLD}🎉 NETGUARD PRO v6.3 LTS FULLY DEPLOYED!${RESET}"
echo -e "${YELLOW}🔍 ${CYAN}netguard-health${RESET}                 ${YELLOW}(Status Check)${RESET}"
echo -e "${YELLOW}🖱️  ${CYAN}netguard-applet &${RESET}               ${YELLOW}(Launch Tray)${RESET}"
echo -e "${YELLOW}🚫 ${CYAN}echo \"BLOCK 1.2.3.4\" > /run/netguard/control.fifo${RESET} ${YELLOW}(Test Block)${RESET}"
echo -e "${CYAN}${BOLD}🏰 Your network fortress is LIVE!${RESET}"
