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
