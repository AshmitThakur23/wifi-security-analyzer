<div align="center">

# 🛡️ WiFi Security Analyzer

### *Your Personal Network Security Guardian*

[![Made with Python](https://img.shields.io/badge/Made%20with-Python-1f425f.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.1.2-000000?logo=flask)](https://flask.palletsprojects.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Windows](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows)](https://www.microsoft.com/windows)
[![GitHub](https://img.shields.io/badge/GitHub-AshmitThakur23-181717?logo=github)](https://github.com/AshmitThakur23/wifi-security-analyzer)

<img src="https://raw.githubusercontent.com/abhisheknaiidu/abhisheknaiidu/master/code.gif" width="500" alt="Coding">

*Protect yourself from WiFi hackers, Evil Twin attacks, and unauthorized network access*

[Features](#-features) • [Quick Start](#-quick-start) • [How It Works](#-how-it-works) • [Documentation](#-documentation) • [Screenshots](#-screenshots)

</div>

---

## 📊 Project Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  🏠 HOME WIFI              🔍 ANALYZE              ✅ SECURE    │
│                                                                 │
│  ┌──────────┐            ┌──────────┐            ┌──────────┐  │
│  │ Router   │  ------→   │ Security │  ------→   │ Protected│  │
│  │ Devices  │            │ Scan     │            │ Network  │  │
│  └──────────┘            └──────────┘            └──────────┘  │
│                                                                 │
│  • Check WiFi Safety     • Evil Twin Detection  • Real-time    │
│  • Scan Devices          • Encryption Analysis  • Monitoring   │
│  • Identify Threats      • DNS Security Check   • Alerts       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## 🎯 What This Tool Does

This is a **REAL** WiFi security analyzer designed for **Windows** that works with your actual WiFi networks. It provides two powerful security features to protect your network from hackers and unauthorized access.

### ✅ Feature 1: WiFi Security Analysis
```
📡 YOUR AREA NETWORKS          →    🔍 SECURITY CHECK    →    📊 DETAILED REPORT
┌─────────────────┐                 ┌────────────────┐         ┌──────────────────┐
│ • Home WiFi     │                 │ ✓ Encryption   │         │ ✅ WPA2 - Safe   │
│ • Coffee Shop   │   ────────→     │ ✓ Evil Twin    │   →     │ ⚠️ WEP - Unsafe  │
│ • Office WiFi   │                 │ ✓ DNS Check    │         │ ❌ Open - Danger │
│ • Guest Network │                 └────────────────┘         └──────────────────┘
└─────────────────┘
```

**Capabilities:**
- 🔐 **Encryption Analysis** - Identifies WPA3, WPA2, WPA, WEP, or Open networks
- 👥 **Evil Twin Detection** - Detects fake WiFi hotspots trying to steal your data
- 🌐 **DNS Security Check** - Verifies DNS isn't hijacked to redirect you to malicious sites
- 📊 **Risk Scoring** - Provides 0-100 risk score with detailed explanations
- 💡 **Smart Recommendations** - Tells you exactly what to do

### ✅ Feature 2: Network Device Monitoring
```
🏠 YOUR HOME NETWORK                 🔍 DEVICE SCAN                 🚨 THREAT DETECTION
┌──────────────────┐                ┌───────────────┐              ┌─────────────────┐
│ Router           │                │ Scan ARP      │              │ Known Devices ✅│
│ ├─ Phone        │                │ Table for     │              │ Unknown Devices❓│
│ ├─ Laptop       │   ────────→    │ Connected     │   ────────→  │ Suspicious    ⚠️│
│ ├─ Smart TV     │                │ Devices       │              │ ALERT!        🔴│
│ └─ ??? Device   │                └───────────────┘              └─────────────────┘
└──────────────────┘
```

**Capabilities:**
- 📱 **Device Discovery** - Finds ALL devices connected to your WiFi
- 🏷️ **Vendor Identification** - Identifies device manufacturers (Apple, Samsung, etc.)
- 🔍 **Device Classification** - Categorizes as phone, computer, TV, IoT device
- ⚡ **Real-time Monitoring** - 24/7 continuous monitoring with ON/OFF toggle
- 🚨 **Instant Alerts** - Notifies you when unknown devices connect
- 📊 **Historical Tracking** - See who connected and when

---

## 🚀 Quick Start

### 🎬 One-Click Launch (Easiest Method)

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│  1️⃣  Double-click START_SERVER.bat                         │
│      └──→ ✅ Installs dependencies                         │
│      └──→ ✅ Starts Flask server                           │
│      └──→ ✅ Opens frontend automatically                  │
│                                                             │
│  2️⃣  Browser opens with the app running                    │
│      └──→ ✅ Ready to use immediately!                     │
│                                                             │
│  That's it! Everything works with ONE CLICK! 🎉            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 📋 Manual Installation

<details>
<summary><b>Click to expand manual installation steps</b></summary>

#### Prerequisites
- ✅ Python 3.8 or higher
- ✅ Windows OS (7/8/10/11)
- ✅ Administrator privileges (for network scanning)

#### Step 1: Clone the Repository
```bash
git clone https://github.com/AshmitThakur23/wifi-security-analyzer.git
cd wifi-security-analyzer
```

#### Step 2: Install Dependencies
```bash
cd backend
pip install -r requirements.txt
```

#### Step 3: Start the Server
```bash
python app.py
```

You should see:
```
============================================================
🛡️  WiFi Security Analyzer v2.0 - ENHANCED
============================================================
✅ Feature 1: Check if current WiFi is safe
✅ Feature 2: Monitor your WiFi for intruders
🆕 Feature 3: 24/7 Continuous Monitoring (ON/OFF)
🆕 Feature 4: Historical analysis - See past activity
🆕 Feature 5: Works on ANY WiFi (home, office, anywhere)
============================================================
🌐 Server: http://127.0.0.1:5000
============================================================
```

#### Step 4: Open the Frontend
- Right-click `frontend/index.html`
- Choose "Open with Chrome" or "Open with Edge"
- Or simply open the file in any modern browser

</details>

---

## 🏗️ Architecture & How It Works

### System Architecture Diagram

```
┌───────────────────────────────────────────────────────────────────────────┐
│                         WIFI SECURITY ANALYZER                            │
└───────────────────────────────────────────────────────────────────────────┘
                                    │
                ┌───────────────────┴───────────────────┐
                │                                       │
        ┌───────▼────────┐                    ┌────────▼────────┐
        │   FRONTEND     │◄──── HTTP ────────►│    BACKEND      │
        │  (Web UI)      │      REST API      │  (Flask Server) │
        └────────────────┘                    └─────────────────┘
        │                                              │
        │  • HTML/CSS/JS                               │  • Python Flask
        │  • Interactive UI                            │  • SQLite Database
        │  • Real-time Updates                         │  • RESTful APIs
        │                                              │
        └───────────────────┐                          │
                            │                          │
                    ┌───────▼──────────────────────────▼──────────┐
                    │         SECURITY ANALYSIS ENGINE           │
                    └───────────────┬────────────────────────────┘
                                    │
            ┌───────────────────────┼───────────────────────┐
            │                       │                       │
    ┌───────▼────────┐    ┌────────▼────────┐    ┌────────▼────────┐
    │ CONNECTION     │    │  MONITORING     │    │  CONTINUOUS     │
    │ SERVICE        │    │  SERVICE        │    │  MONITOR        │
    └────────────────┘    └─────────────────┘    └─────────────────┘
    │                     │                      │
    │ • WiFi Scan         │ • ARP Scan          │ • Background Task
    │ • Encryption        │ • Device Discovery  │ • Periodic Checks
    │ • Evil Twin         │ • Vendor Lookup     │ • Alert System
    │ • DNS Check         │ • Threat Detection  │ • History Logging
    │                     │                      │
    └──────┬──────────────┴──────────────────────┴──────────┐
           │                                                 │
    ┌──────▼─────────────────────────────────────────────────▼──────┐
    │              WINDOWS NETWORK COMMANDS                         │
    │  • netsh wlan show interfaces     (WiFi info)                 │
    │  • netsh wlan show networks       (Available networks)        │
    │  • arp -a                          (Connected devices)         │
    │  • ipconfig                        (Network configuration)     │
    │  • nslookup                        (DNS queries)               │
    └───────────────────────────────────────────────────────────────┘
```

### Data Flow Diagram

```
USER ACTION                 BACKEND PROCESSING              RESULT DISPLAY
┌──────────────┐           ┌───────────────────┐          ┌──────────────┐
│ Click Button │           │ 1. Receive Request│          │ Show Detailed│
│  "Check      │  ──────►  │ 2. Execute Scan   │  ─────►  │ Security     │
│   WiFi"      │           │ 3. Analyze Data   │          │ Report       │
└──────────────┘           │ 4. Calculate Risk │          └──────────────┘
                           │ 5. Generate Report│
                           └───────────────────┘
                                    │
                           ┌────────┴────────┐
                           │                 │
                    ┌──────▼──────┐   ┌─────▼──────┐
                    │ Save to DB  │   │ Send JSON  │
                    │ (SQLite)    │   │ Response   │
                    └─────────────┘   └────────────┘
```

### Security Check Flow

```
WIFI NETWORK → CHECK #1 → CHECK #2 → CHECK #3 → RISK CALCULATION → VERDICT
               ────────   ────────   ────────   ───────────────   ────────
               Encryption  Evil Twin  DNS       Sum of all       Safe/
               WPA3/2/WEP  Detection  Security  risk scores      Unsafe
               ✅/⚠️/❌     ✅/⚠️/❌      ✅/⚠️/❌    0-100 points      + Tips
```

---

## 🔍 Detailed Features

### 🛡️ Feature 1: WiFi Security Analysis

#### What Gets Checked:

<table>
<tr>
<td width="33%">

**🔐 Encryption Check**
```
WPA3 ━━━━━━━━━━ ✅ 100%
     (Most Secure)

WPA2 ━━━━━━━━━━ ✅ 90%
     (Secure)

WPA  ━━━━━━     ⚠️ 60%
     (Weak)

WEP  ━━         ❌ 30%
     (Very Weak)

OPEN             ❌ 0%
     (No Security)
```

</td>
<td width="33%">

**👥 Evil Twin Detection**
```
┌─────────────┐
│ Real Router │
│ "HomeWiFi"  │
└─────────────┘
       ✅
       
┌─────────────┐
│ Fake Router │
│ "HomeWiFi"  │ ⚠️ ALERT!
└─────────────┘
  (Same SSID,
   Different MAC)
```

</td>
<td width="33%">

**🌐 DNS Security**
```
Normal DNS:
8.8.8.8 ━━━━━━ ✅
(Google DNS)

1.1.1.1 ━━━━━━ ✅
(Cloudflare)

Suspicious:
192.168.x.x ━━ ⚠️
(Local/Unknown)

Hijacked:
Unknown IP ━━━ ❌
(Malicious DNS)
```

</td>
</tr>
</table>

#### Risk Score Calculation:

```
┌─────────────────────────────────────────────────────────┐
│  RISK SCORE = Encryption (50%) + Evil Twin (30%)       │
│               + DNS Security (20%)                      │
│                                                         │
│  ┌──────────────────────────────────────────────────┐  │
│  │  0-29   │ 🟢 LOW RISK      │ ✅ Safe to Connect │  │
│  │  30-59  │ 🟡 MEDIUM RISK   │ ⚠️ Use with Caution│  │
│  │  60-100 │ 🔴 HIGH RISK     │ ❌ Do NOT Connect │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

### 🏠 Feature 2: Network Device Monitoring

#### Device Detection Process:

```
STEP 1: ARP SCAN          STEP 2: ANALYSIS         STEP 3: CLASSIFICATION
┌────────────────┐        ┌─────────────────┐      ┌──────────────────┐
│ Run: arp -a    │   →    │ For each device:│  →   │ Device Type:     │
│                │        │ • Get IP        │      │ • Smartphone     │
│ Returns:       │        │ • Get MAC       │      │ • Computer       │
│ IP  │  MAC     │        │ • Vendor Lookup │      │ • Smart TV       │
│ x.x.x.1 │ AA:  │        │ • Hostname      │      │ • IoT Device     │
│ x.x.x.2 │ BB:  │        │ • Type Detect   │      │ • Router         │
│ x.x.x.3 │ CC:  │        └─────────────────┘      │ • Unknown        │
└────────────────┘                                 └──────────────────┘
```

#### 7-Point Security Check Per Device:

```
FOR EACH DEVICE:
├─ ✅ CHECK 1: IP Address Detection
├─ ✅ CHECK 2: MAC Address Verification  
├─ ✅ CHECK 3: Vendor Identification (40,000+ database)
├─ ✅ CHECK 4: Device Type Classification
├─ ✅ CHECK 5: Hostname Resolution
├─ ✅ CHECK 6: Behavior Analysis (New? Suspicious?)
└─ ✅ CHECK 7: Risk Assessment (Safe/Unknown/Suspicious)
```

### ⏰ Feature 3: 24/7 Continuous Monitoring

```
┌──────────────────────────────────────────────────────────┐
│  🟢 MONITORING ON                                        │
│  ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐        │
│  │ Scan 1 │→ │ Scan 2 │→ │ Scan 3 │→ │ Scan 4 │→  ...  │
│  └────────┘  └────────┘  └────────┘  └────────┘        │
│   Every 5 minutes (configurable)                        │
│                                                          │
│  If new device detected:                                │
│  └─→ 🚨 ALERT TRIGGERED                                 │
│      └─→ 📧 Save to database                            │
│          └─→ 📊 Show in history                         │
└──────────────────────────────────────────────────────────┘
```

### Step 3: Open the Frontend

1. Open `frontend/index.html` in your web browser
2. Or visit: http://localhost:5000 and use the API directly

---

## 📱 How to Use Each Feature

### 🔍 Feature 1: Check WiFi Before Connecting

**Use Case:** You're at a coffee shop, airport, or public place with multiple WiFi networks. Which one is safe?

#### Method 1: Check Your Current Connection
1. Connect to a WiFi network
2. Click **"🔍 Check My WiFi Now"** button
3. The tool will analyze:
   - ✅ Encryption strength (WPA3/WPA2/WPA/WEP/Open)
   - ✅ Evil Twin indicators (fake WiFi hotspots)
   - ✅ DNS hijacking attempts
   - ✅ Signal strength anomalies
4. You'll get a verdict: **SAFE** 🟢, **CAUTION** 🟡, or **UNSAFE** 🔴

#### Method 2: Scan All Available Networks
1. Click **"📡 Scan Available Networks"** button
2. See ALL WiFi networks around you (like when you click WiFi icon)
3. Each network is marked as:
   - ✅ **SAFE** (good encryption)
   - 🔴 **UNSAFE** (weak/no encryption)
4. Only connect to SAFE networks!

#### Via API (For Developers):
```powershell
# Check current connection
curl -X POST http://localhost:5000/api/connection/check -H "Authorization: Bearer mysecrettoken"

# Scan available networks
curl http://localhost:5000/api/connection/available -H "Authorization: Bearer mysecrettoken"
```

---

### 👁️ Feature 2: Monitor Your Home WiFi

**Use Case:** You want to know who's using your home WiFi and detect unauthorized access.

#### Scan Your Network
1. Make sure you're connected to YOUR home WiFi
2. Click **"🔎 Scan My Network"** button
3. The tool will:
   - 🔍 Find ALL devices connected to your network
   - 🏷️ Identify each device (iPhone, laptop, smart TV, etc.)
   - ⚠️ Flag unknown/suspicious devices
   - 🔴 Alert you to potential intruders

#### View All Connected Devices
1. Click **"📱 View All Devices"** button
2. See complete list of devices on your WiFi:
   - Device name
   - IP address
   - MAC address
   - Device type (phone, computer, router, etc.)
   - Manufacturer/vendor

#### Via API:
```powershell
# Scan network for threats
curl -X POST http://localhost:5000/api/monitoring/scan -H "Authorization: Bearer mysecrettoken"

# View all devices
curl http://localhost:5000/api/monitoring/devices -H "Authorization: Bearer mysecrettoken"

# Get dashboard
curl http://localhost:5000/api/monitoring/dashboard -H "Authorization: Bearer mysecrettoken"
```

---

## 🔒 Security Checks Performed

### WiFi Connection Security (Feature 1)

| Check | Description |
|-------|-------------|
| **Encryption Analysis** | Detects Open, WEP, WPA, WPA2, WPA3 |
| **Cipher Strength** | Checks if using TKIP (weak) or AES (strong) |
| **Evil Twin Detection** | Finds multiple APs with same SSID (fake hotspots) |
| **Signal Anomalies** | Detects suspiciously strong signals (rogue AP nearby) |
| **DNS Hijacking** | Checks for suspicious DNS servers |

### Network Monitoring (Feature 2)

| Check | Description |
|-------|-------------|
| **Device Discovery** | Lists ALL devices on your network using ARP table |
| **Device Identification** | Identifies device type (phone, laptop, printer, etc.) |
| **Vendor Detection** | Identifies manufacturer from MAC address |
| **Unknown Device Alert** | Flags devices not in your known list |
| **MAC Spoofing Detection** | Detects randomized/spoofed MAC addresses |
| **Suspicious Names** | Alerts on devices with hacking tool names |
| **Rogue AP Detection** | Detects unauthorized routers on your network |

---

## 📊 API Endpoints

### Connection Security Endpoints

```
POST /api/connection/check          - Check current WiFi safety
GET  /api/connection/status          - Get connection status
GET  /api/connection/available       - Scan available networks
GET  /api/connection/history         - Get check history
```

### Network Monitoring Endpoints

```
POST /api/monitoring/scan            - Scan network for threats
GET  /api/monitoring/devices         - List all connected devices
GET  /api/monitoring/dashboard       - Get monitoring dashboard
GET  /api/monitoring/alerts          - Get security alerts
POST /api/monitoring/networks        - Add network to monitor
```

### Network Scanning Endpoints

```
POST /api/networks/scan              - Scan and save networks to DB
GET  /api/networks                   - List scanned networks
GET  /api/networks/<id>              - Get specific network
```

---

## 🎨 What You'll See

### When WiFi is SAFE ✅
```
✅ SAFE - Network appears secure
Risk Score: 10/100
Security Level: GOOD

Network Information:
SSID: MyHomeWiFi
Authentication: WPA2-Personal
Cipher: CCMP (AES)

✅ Good security - WPA2 with AES
💡 Consider upgrading to WPA3 for best security
```

### When WiFi is UNSAFE 🔴
```
🔴 UNSAFE - Do not use this network
Risk Score: 80/100
Security Level: CRITICAL

Network Information:
SSID: Free_Public_WiFi
Authentication: Open
Cipher: None

❌ No encryption - Anyone can intercept your data
🔴 DO NOT use this network for sensitive activities
⚠️ Multiple access points (3) broadcasting same network name
```

### Network Monitoring Results 👁️
```
✅ SAFE - Network appears secure
Risk Score: 15/100

Network Summary:
Total Devices: 8
Safe Devices: 6
Suspicious Devices: 0
Unknown Devices: 2

Connected Devices:
📡 WiFi Router (Gateway) - 192.168.1.1
📱 John's iPhone - 192.168.1.101
💻 My Laptop - 192.168.1.102
📱 Unknown Device - 192.168.1.105 ⚠️
```

---

## 🛠️ Technical Details

### How It Works

#### Feature 1: WiFi Connection Check
1. Uses Windows `netsh wlan` commands to get WiFi information
2. Analyzes encryption type (Open/WEP/WPA/WPA2/WPA3)
3. Scans for multiple APs with same SSID (Evil Twin)
4. Checks DNS server configuration
5. Calculates risk score based on findings
6. Provides security verdict and recommendations

#### Feature 2: Network Monitoring
1. Uses `arp -a` command to get all devices on local network
2. Uses `nslookup` to resolve hostnames
3. Identifies device vendors from MAC address OUI
4. Detects device types from hostname patterns
5. Flags unknown/suspicious devices
6. Generates security alerts for threats

### Technologies Used
- **Backend:** Python Flask
- **Network Scanning:** Windows `netsh`, `arp`, `ipconfig`
- **Database:** SQLite (stores scan history, alerts)
- **Frontend:** HTML/CSS/JavaScript
- **Security:** JWT authentication, CORS enabled

---

## ⚠️ Important Notes

### Permissions Required
- ✅ Works on **Windows** (PowerShell/CMD)
- ✅ Some features require **administrator** privileges
- ✅ WiFi adapter must be enabled

### Limitations
- Only works on **Windows** (uses `netsh` commands)
- Can only scan networks within WiFi range
- Cannot decrypt encrypted traffic (that would be illegal!)
- Cannot crack WiFi passwords
- Device identification is based on MAC address and hostname

### What This Tool DOES NOT Do
- ❌ Does NOT hack WiFi passwords
- ❌ Does NOT intercept network traffic
- ❌ Does NOT perform illegal activities
- ✅ ONLY provides security analysis and monitoring

---

## 🔐 Security Best Practices

### For Public WiFi:
1. ✅ Always check security before connecting
2. ✅ Use a VPN when on public WiFi
3. ✅ Avoid sensitive activities (banking, passwords) on public networks
4. ✅ Turn off "Auto-connect" for public networks
5. ✅ Forget public networks after use

### For Home WiFi:
1. ✅ Use WPA3 or WPA2-AES encryption
2. ✅ Use a strong, unique password (12+ characters)
3. ✅ Change default router password
4. ✅ Disable WPS (WiFi Protected Setup)
5. ✅ Enable MAC address filtering
6. ✅ Regularly check connected devices
7. ✅ Update router firmware
8. ✅ Hide SSID broadcast (optional)
9. ✅ Monitor for unknown devices regularly

---

## 🎯 Real-World Use Cases

### Use Case 1: Coffee Shop WiFi
**Scenario:** You're at Starbucks and see 3 WiFi networks: "Starbucks_WiFi", "FREE_WIFI", "Starbucks-Guest"

**Steps:**
1. Click "📡 Scan Available Networks"
2. Check which networks are marked SAFE
3. Look for:
   - ✅ Official network name
   - ✅ WPA2 encryption (not Open)
   - ⚠️ Multiple networks with same name (Evil Twin)
4. Connect to the SAFE network only
5. Click "🔍 Check My WiFi Now" after connecting
6. If unsafe, disconnect and use mobile data or VPN

### Use Case 2: New Neighbor or Guest
**Scenario:** Your WiFi seems slow. Someone might be stealing it.

**Steps:**
1. Click "🔎 Scan My Network"
2. Review all connected devices
3. Look for:
   - 📱 Your family's phones
   - 💻 Your computers
   - 📺 Smart TVs
   - ⚠️ Unknown devices
4. If you find unknown devices:
   - Note their MAC address
   - Change your WiFi password
   - Enable MAC filtering on router
   - Re-scan to verify they're gone

### Use Case 3: Hotel or Airport
**Scenario:** Multiple WiFi options, want to pick the safest one.

**Steps:**
1. Don't connect yet
2. Click "📡 Scan Available Networks"
3. Compare security levels:
   - 🔴 Open networks → AVOID
   - 🔴 WEP networks → AVOID
   - 🟡 WPA networks → Use with caution + VPN
   - ✅ WPA2/WPA3 → Best choice
4. Connect to most secure option
5. Verify with "🔍 Check My WiFi Now"
6. Use VPN regardless

---

## 📞 Support & Troubleshooting

### Issue: "WiFi adapter not found"
**Solution:** 
- Make sure WiFi is turned on
- Run PowerShell as Administrator
- Check: `netsh wlan show interfaces`

### Issue: "No devices found"
**Solution:**
- Make sure you're connected to WiFi
- Run as Administrator
- Wait 30 seconds after connecting, then scan
- Some devices might not appear immediately

### Issue: "Scan failed"
**Solution:**
- Run backend with Administrator privileges
- Check firewall settings
- Ensure WiFi adapter is active

### Issue: Too many unknown devices
**Solution:**
- This is normal for first scan
- Note down YOUR devices' MAC addresses
- Add them to monitored devices list
- Future scans will recognize them

---

## 🔮 Future Enhancements

- [ ] Email/SMS alerts for threats
- [ ] Desktop notifications (Windows Toast)
- [ ] Mobile app (iOS/Android)
- [ ] Automatic VPN activation on unsafe networks
- [ ] Network speed testing
- [ ] Historical tracking and analytics
- [ ] Machine learning for device identification
- [ ] Scheduled automatic scans
- [ ] Export reports (PDF/CSV)
- [ ] Integration with router admin panel
- [ ] Port scanning capabilities
- [ ] Packet capture analysis

---

## 📄 License & Legal

This tool is for **EDUCATIONAL and PERSONAL SECURITY purposes only**.

✅ **Legal Uses:**
- Check security of networks YOU own
- Check security of networks you have permission to test
- Monitor devices on YOUR network
- Protect yourself from WiFi threats

❌ **Illegal Uses:**
- Hacking into networks you don't own
- Accessing other people's networks without permission
- Intercepting traffic
- Any unauthorized network access

**Disclaimer:** Users are responsible for complying with local laws and regulations.

---

## 👨‍💻 Developer Information

### Project Structure
```
backend/
  ├── app.py                 # Main Flask application
  ├── models.py              # Database models
  ├── config.py              # Configuration
  ├── auth.py                # Authentication
  ├── requirements.txt       # Python dependencies
  ├── routes/
  │   ├── connection_routes.py   # Feature 1 endpoints
  │   ├── monitoring_routes.py   # Feature 2 endpoints
  │   └── network_routes.py      # Network scan endpoints
  └── services/
      ├── connection_service.py  # WiFi security checks
      ├── monitoring_service.py  # Network monitoring
      ├── scan_service.py        # Network scanning
      └── alert_service.py       # Alert system

frontend/
  └── index.html            # Web interface
```

### Contributing
Feel free to improve this tool! Focus areas:
- Cross-platform support (Linux, macOS)
- Better device identification
- More security checks
- Better UI/UX
- Automated testing

---

## 🎓 Learn More

### Resources
- [WiFi Security Basics](https://www.cisa.gov/wifi-security)
- [WPA3 Explained](https://www.wi-fi.org/discover-wi-fi/security)
- [Network Security Best Practices](https://www.nist.gov/)

### Related Tools
- Wireshark (packet analysis)
- Nmap (network scanning)
- Aircrack-ng (WiFi security auditing)

---

**Made with ❤️ for WiFi Security**

Stay safe online! 🛡️🔒


---

##  Screenshots

### Main Dashboard
```

               WiFi Security Analyzer v2.0                   
                                                                
              
    Server Connected    10.165.13.234                     
              
                                                                
              
    Feature 1: Check Current WiFi                        
   Check if the WiFi you're connected to is                
   safe from hackers                                        
                                                            
    [  Check My WiFi Now  ]  [ Scan Networks ]             
              
                                                                
              
    Feature 2: Monitor My Network                        
   Detect unauthorized devices and suspicious              
   activity on your WiFi                                    
                                                            
    [   START Monitoring   ]   24/7                      
    [ Quick Scan Now ] [ View All Devices ]                
              

```

---

##  Documentation

### Complete Feature List
 WiFi encryption analysis (WPA3/WPA2/WPA/WEP/Open)
 Evil Twin attack detection
 DNS hijacking detection
 Network device discovery
 Device vendor identification (40,000+ manufacturers)
 Device type classification
 24/7 continuous monitoring
 Real-time alerts
 Historical tracking
 Weekly reports
 Risk scoring algorithm
 Beautiful web interface
 RESTful API
 SQLite database
 One-click launcher

---

##  Contributing

Contributions are welcome! Here's how:

```bash
# Fork the repository
# Create a new branch
git checkout -b feature/amazing-feature

# Make your changes
# Commit your changes
git commit -m 'Add amazing feature'

# Push to your branch
git push origin feature/amazing-feature

# Open a Pull Request
```

---

##  License

This project is licensed under the MIT License - see below:

```
MIT License

Copyright (c) 2025 Ashmit Thakur

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

##  Author

**Ashmit Thakur**
- GitHub: [@AshmitThakur23](https://github.com/AshmitThakur23)
- Repository: [wifi-security-analyzer](https://github.com/AshmitThakur23/wifi-security-analyzer)

---

##  Acknowledgments

- Built with  using Flask and Python
- Inspired by the need for better WiFi security awareness
- Thanks to the open-source community

---

##  Support

If you encounter issues or have questions:

1. **Check the [STATUS.md](STATUS.md)** file for quick troubleshooting
2. **Open an issue** on GitHub with details
3. **Read the documentation** above thoroughly

---

##  Star This Project!

If you found this tool helpful, please give it a star  on GitHub!

```bash
# Star the repository
https://github.com/AshmitThakur23/wifi-security-analyzer
```

---

<div align="center">

### Made with  by Ashmit Thakur

**Protect Your Network. Stay Secure. **

[ Back to Top](#%EF%B8%8F-wifi-security-analyzer)

</div>
