#!/bin/bash
# NetGuard Pro Cleanup Utility
[[ $EUID -ne 0 ]] && echo "Run as root" && exit 1

echo "🛑 Stopping NetGuard Services..."
systemctl disable --now netguard netguard-report.timer netguard-report.service 2>/dev/null || true

echo "🧹 Removing Files..."
rm -f /usr/local/bin/netguard-core
rm -f /usr/local/bin/netguard-applet
rm -f /usr/local/bin/netguard-report
rm -f /usr/local/bin/netguard-health
rm -f /etc/systemd/system/netguard.service
rm -f /etc/systemd/system/netguard-report.service
rm -f /etc/systemd/system/netguard-report.timer
rm -f /etc/logrotate.d/netguard

# Optional: Remove logs and configs (Uncomment if you want a total wipe)
# rm -rf /etc/netguard /var/log/netguard /run/netguard

echo "🔄 Reloading Systemd..."
systemctl daemon-reload
echo "✅ System cleaned. You can now run the new install.sh"
