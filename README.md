# 🛡️ WiFi Security Analyzer - Real-World Version

## 🎯 What This Tool Does

This is a **REAL** WiFi security analyzer that works with your actual WiFi networks in Windows. It has two main features:

### ✅ Feature 1: Check WiFi Safety Before/While Connecting
- **Scan all WiFi networks** in your area (4, 5, or more networks)
- **Analyze security** of each network (WPA3, WPA2, WEP, Open, etc.)
- **Check if network is safe** before you connect
- **Detect potential threats**: Evil Twin attacks, weak encryption, suspicious DNS
- **Get recommendations** on whether it's safe to connect

### ✅ Feature 2: Monitor Your Home WiFi
- **Scan all devices** connected to YOUR WiFi network
- **Detect unauthorized devices** (guests, hackers, unknown devices)
- **Identify each device** (phones, computers, smart TVs, etc.)
- **Get alerts** when suspicious activity is detected
- **Monitor in real-time** who is using your WiFi
- **Protect your personal data** from WiFi thieves

---

## 🚀 Quick Start (EASIEST WAY)

### Option 1: Use the Batch Files (Windows)

1. **Start Server**: Double-click `START_SERVER.bat`
2. **Open Frontend**: Double-click `OPEN_FRONTEND.bat`
3. That's it! The app will open in your browser.

### Option 2: Manual Start

**Step 1: Install Dependencies**

Open PowerShell in the `backend` folder and run:

```powershell
cd backend
pip install -r requirements.txt
```

**Step 2: Start the Backend Server**

```powershell
python app.py
```

You should see:
```
============================================================
🛡️  WiFi Security Analyzer v2.0
============================================================
✅ Feature 1: Check if current WiFi is safe
✅ Feature 2: Monitor your WiFi for intruders
============================================================
🌐 Server: http://0.0.0.0:5000
============================================================
```

**Step 3: Open the Frontend**

Right-click `frontend\index.html` and choose "Open with Chrome" or "Open with Edge"

Or simply double-click `OPEN_FRONTEND.bat`

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
