#!/bin/bash
# NetGuard Pro v5.4 → v6.3 LTS UPGRADE CLEANER
# Complete wipe for seamless upgrade
[[ $EUID -ne 0 ]] && { echo "🛑 Run as root"; exit 1; }

echo -e "\n🧹 ${YELLOW}NetGuard Pro v5.4 Complete Cleanup...${RESET}"

# 1. STOP ALL SERVICES
pkill -f netguard-applet.py 2>/dev/null || true
pkill -f netguard-scan 2>/dev/null || true

# 2. SYSTEMD (v6.3 prep)
systemctl disable --now netguard netguard-report.timer netguard-report.service 2>/dev/null || true
systemctl daemon-reload

# 3. CRON (v5.4)
(crontab -l 2>/dev/null | grep -v netguard || true) | crontab - 2>/dev/null || true

# 4. IPSET CLEANUP
ipset destroy netguard_blacklist 2>/dev/null || true

# 5. COMPLETE FILE REMOVAL (v5.4)
rm -f /usr/local/bin/netguard-*
rm -f "$HOME/.local/bin/netguard-applet.py" 2>/dev/null || true
rm -f "$HOME/.config/autostart/netguard.desktop" 2>/dev/null || true

# 6. CONFIG & DATA (Safe wipe - keeps whitelist if desired)
rm -rf /etc/netguard /var/lib/netguard /var/log/netguard /var/run/netguard \
       /etc/logrotate.d/netguard 2>/dev/null || true

# 7. UFW CLEANUP
ufw status numbered 2>/dev/null | grep -i netguard | awk -F"[][]" '{print $2}' | sort -rn | \
while read idx; do [[ "$idx" =~ ^[0-9]+$ ]] && ufw --force delete "$idx"; done 2>/dev/null || true

echo -e "${GREEN}✅ v5.4 Completely Removed${RESET}"
echo -e "${CYAN}🚀 Ready for v6.3 LTS install${RESET}"
echo -e "${YELLOW}💡 Run: sudo bash v6.3-install.sh${RESET}"
