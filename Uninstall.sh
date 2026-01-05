#!/bin/bash
# ==============================================================================
# 🛡️ NetGuard Pro v6.3 LTS - ULTIMATE UNINSTALLER / SYSTEM PURGE
# ==============================================================================
set -euo pipefail

BOLD=$(tput bold 2>/dev/null || echo ""); RESET=$(tput sgr0 2>/dev/null || echo "")
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'

[[ $EUID -ne 0 ]] && { echo -e "${RED}❌ Run as root (sudo)${RESET}"; exit 1; }

echo -e "${CYAN}${BOLD}🗑️  Starting NetGuard Pro Total Removal...${RESET}"

# 1. STOP SERVICES
echo -e "🛑 Stopping services and processes..."
systemctl stop netguard >/dev/null 2>&1 || true
systemctl disable netguard >/dev/null 2>&1 || true
pkill -f netguard >/dev/null 2>&1 || true
sleep 2 
echo -e "  ${GREEN}✅ Services stopped${RESET}"

# 2. CLEAN FIREWALL (UFW & IPSet) 
echo -e "🔥 Cleaning firewall rules..."
ufw status numbered | grep "NetGuard-Pro" | awk -F"[][]" '{print $2}' | sort -rn | while read -r line; do
    [ -n "$line" ] && ufw --force delete "$line" >/dev/null 2>&1
done
ipset destroy netguard_blacklist >/dev/null 2>&1 || true
ufw reload >/dev/null 2>&1
echo -e "  ${GREEN}✅ Firewall cleaned${RESET}"

# 3. REMOVE BINARIES & SCRIPTS
echo -e "📂 Removing binaries..."
rm -f /usr/local/bin/netguard-*
echo -e "  ${GREEN}✅ Scripts removed${RESET}"

# 4. PURGE SYSTEM CONFIGS
echo -e "⚙️  Purging system configurations..."
rm -f /etc/systemd/system/netguard.service
rm -f /etc/logrotate.d/netguard
systemctl daemon-reload
systemctl reset-failed
echo -e "  ${GREEN}✅ System configs removed${RESET}"

# 5. DELETE DATA & LOGS
echo -e "📊 Deleting logs and pipes..."
rm -rf /etc/netguard /var/log/netguard /run/netguard
echo -e "  ${GREEN}✅ Data purged${RESET}"

# 6. USER ENVIRONMENT CLEANUP
echo -e "👤 Cleaning user environment..."
find /home -path "*/.config/autostart/netguard.desktop" -delete 2>/dev/null || true
echo -e "  ${GREEN}✅ Environment cleaned${RESET}"

# 7. FINAL VERIFICATION
echo -e "\n🔍 Final verification..."
systemctl is-active netguard >/dev/null 2>&1 && echo -e "${RED}⚠️  Service still active${RESET}" || echo -e "  ${GREEN}✅ Service gone${RESET}"
[ -f /usr/local/bin/netguard-core ] && echo -e "${RED}⚠️  Binary remains${RESET}" || echo -e "  ${GREEN}✅ Binaries gone${RESET}"
[ -p /run/netguard/control.fifo ] && echo -e "${RED}⚠️  Pipe remains${RESET}" || echo -e "  ${GREEN}✅ Pipe gone${RESET}"

echo -e "\n${YELLOW}${BOLD}✨ NetGuard Pro v6.3 LTS completely removed!${RESET}"
echo -e "${CYAN}💡 UFW is still active. Check: sudo ufw status verbose${RESET}"
