# NetGuard-Pro
# 🛡️ NetGuard Pro: UFW + Bandwidth Real-time Security

**NetGuard Pro** is a powerful, visual, and lightweight network defense suite for Debian-based Linux desktops. It integrates with **UFW (Uncomplicated Firewall)** to provide real-time monitoring of active connections, identifies high-risk IPs, displays live bandwidth usage, and allows one-click blocking directly from your system tray.

This project transforms your desktop into a "Security War Room," providing immediate, actionable insights into your network traffic.

## ✨ Features

* **🌐 Live Connection Monitoring**: See all active outbound connections.
* **🚦 Threat Intelligence**: Automatically flags `MALICIOUS` (🔴) IPs using FireHOL and `HIGH RISK` (🟠) countries (e.g., RU, CN, KP) using GeoIP.
* **📈 Real-time Bandwidth**: Displays current Download (RX) and Upload (TX) speed for each connection in KB/MB.
* **🚫 One-Click UFW Blocking**: Instantly block suspicious IPs directly from the tray menu using `pkexec` for secure privilege escalation.
* **✅ One-Click UFW Unblocking**: Easily release blocked IPs from the tray menu.
* **🔥 One-Click Global Reset**: Clear all NetGuard-created UFW rules with a single click.
* **📄 Whitelisting**: Define trusted IPs that should never be flagged or blocked.
* **📊 Visual Dashboard**: A command-line "war room" (`netguard-dash`) showing recent alerts, blocks, and active UFW rules.
* **🔔 Desktop Notifications**: Critical alerts for malicious or high-risk connections.
* **🔄 Automatic Updates**: Malicious IP database is updated on each install.
* **🚀 Auto-Start**: The tray applet launches automatically at login.
* **🔐 Secure & Audited**: Built with security best practices, using UFW and `pkexec`.
* **🐧 Universal**: Designed to work on various Debian-based desktop environments (GNOME, KDE, Budgie, XFCE etc.).

## 🚀 Installation (One-Liner)

To install NetGuard Pro, simply copy and paste the following command into your terminal. This will download the `install.sh` script and run it with `sudo` privileges to set up all necessary components.

```bash
curl -sSL https://raw.githubusercontent.com/rootnatty/NetGuard-Pro/refs/heads/main/install.sh | sudo bash
curl -sSL https://raw.githubusercontent.com/rootnatty/NetGuard-Pro/refs/heads/main/install.sh | sudo bash && netguard-health

```

Upgrading to v6.3 LTS and above 
If you are moving from an older version of NetGuard, a "Clean Upgrade" is mandatory to ensure the new log rotation and signal handling are configured correctly.
1. Run the Uninstaller Ensure no legacy processes or orphaned pipes remain:
`sudo bash uninstall.sh`
Post-Installation Verification
After the installation completes, verify that the kernel-level blocking (ipset), the firewall (ufw), and the control pipe (FIFO) are synced and operational.
Run the Health Check:
`sudo netguard-health --repair`

Note: The --repair flag will automatically fix missing directories or misconfigured permissions discovered during the scan.
🧪 Testing the "Sack" (Block) Functionality
To ensure the system is working, you can perform a safe test:

* Open the UI: /usr/local/bin/netguard-applet &
 * Find a non-critical connection in the list.
 * Select 🛑 BLOCK IP.
 * Verify the block in the audit log:
   tail -f /var/log/netguard/audit.log

💡 Pro-Tip for your README
You might want to add a "Subsystems Map" so users understand what files they are touching. You can add this table to your "Filesystem" section:
| Path | Purpose |
|---|---|
| /usr/local/bin/netguard-core | The backend "Sack" engine (Bash) |
| /usr/local/bin/netguard-applet | The UI Monitor (Python) |
| /etc/netguard/safelist.conf | Your "Sunderland" (Trusted) IPs |
| /var/log/netguard/ | Daily HTML Reports & Audit Logs |



 POST-DEPLOY TESTS:
bash
netguard-health                    # 4/4 green checks
netguard-applet &                  # Tray appears instantly
echo "BLOCK 1.2.3.4" | nc -U /run/netguard/control.fifo  # Logs [BLOCK]
tail -f /var/log/netguard/audit.log # Confirm action logged


# ✅ CORRECT - Direct file write to FIFO
echo "BLOCK 1.2.3.4" > /run/netguard/control.fifo

# ✅ Verify block worked
ipset list netguard_blacklist | grep 1.2.3.4
ufw status | grep 1.2.3.4
tail /var/log/netguard/audit.log

