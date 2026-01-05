```markdown
# 🛡️ NetGuard Pro v6.3 LTS
**Real-time Network Defense Suite for Debian/Ubuntu**

[![Status](https://img.shields.io/badge/status-production-green.svg)]() [![Version](https://img.shields.io/badge/version-6.3_LTS-blue.svg)]() [![License](https://img.shields.io/badge/license-MIT-yellow.svg)]()

**NetGuard Pro** transforms your desktop into a Security Operations Center with live connection monitoring, one-click IP blocking, and visual threat intelligence - all from your system tray.

## ✨ Features

- 🌐 **Live Connection Monitoring** - Active connections with country flags
- 🚫 **One-Click Blocking** - BLOCK/UNBLOCK/CLEAR via system tray menu  
- 🔍 **WHOIS Lookup** - Instant IP intelligence from tray menu
- 📊 **Real-time Dashboard** - Live connections + blocked IPs
- 🔔 **Desktop Notifications** - Visual feedback for all actions
- 🏛️ **Dual Protection** - ipset + UFW rules (survives reboots)
- 🚀 **Zero Config** - Autostart + systemd daemon included

## 🚀 One-Line Installation

```bash
curl -sSL https://raw.githubusercontent.com/rootnatty/NetGuard-Pro/main/install.sh | sudo bash
```

## ✅ Post-Install Verification

```bash
netguard-health    # ✅ All systems green
netguard-applet &  # 🖱️  Tray icon appears
```

## 📋 Quick Management

| Command | Purpose |
|---------|---------|
| `netguard-health` | System status check |
| `netguard-applet` | Launch system tray |
| `tail -f /var/log/netguard/audit.log` | Live audit trail |

**Power Commands:**
```bash
echo "BLOCK 1.2.3.4"  | sudo tee /run/netguard/control.fifo   # Block IP
echo "UNBLOCK 1.2.3.4" | sudo tee /run/netguard/control.fifo   # Unblock  
echo "CLEAR"           | sudo tee /run/netguard/control.fifo   # Reset all
```

## 🏗️ System Architecture

| Path | Component |
|------|-----------|
| `/usr/local/bin/netguard-core` | Daemon engine (bash) |
| `/usr/local/bin/netguard-applet` | System tray UI (python) |
| `/run/netguard/control.fifo` | Command pipe |
| `/var/log/netguard/audit.log` | Action log |
| `netguard_blacklist` | ipset blacklist |

## 🛡️ Tray Menu Features

Right-click system tray icon → 
- **🔴 LIVE CONNECTIONS** → BLOCK | WHOIS per IP
- **🚫 BLOCKED IPS** → UNBLOCK per IP  
- **📋 View Audit Logs** → Live tail -f
- **🗑️ CLEAR ALL** → Flush everything

## 🔄 Upgrading (v6.3+)

For clean upgrades from older versions:
```bash
sudo systemctl stop netguard
sudo rm -rf /run/netguard /var/log/netguard
# Then re-run installer
```

## 🎯 Test Installation

```bash
# 1. Safe test block
echo "BLOCK 1.2.3.4" | sudo tee /run/netguard/control.fifo

# 2. Verify
ipset list netguard_blacklist | grep 1.2.3.4
ufw status | grep NetGuard-Pro
tail /var/log/netguard/audit.log
```
