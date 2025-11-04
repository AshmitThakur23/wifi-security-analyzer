"""
Monitoring Service - Monitor your home WiFi network
Detect unauthorized devices, suspicious activity, and security threats
"""
import subprocess
import re
import uuid
import datetime
from typing import Dict, List, Any, Optional

def get_router_gateway() -> Optional[str]:
    """Get the default gateway (router) IP address"""
    try:
        result = subprocess.run(
            ['ipconfig'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            # Find default gateway
            match = re.search(r'Default Gateway[.\s]+:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', result.stdout)
            if match:
                return match.group(1)
        
        return None
    except Exception:
        return None


def get_connected_devices() -> List[Dict[str, Any]]:
    """
    Get all devices connected to your WiFi network using ARP table
    This shows devices on your local network
    """
    devices = []
    
    try:
        # Get ARP table (shows all devices that communicated on network)
        result = subprocess.run(
            ['arp', '-a'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode != 0:
            return []
        
        output = result.stdout
        
        # Get router IP for identification
        router_ip = get_router_gateway()
        
        # Parse ARP table
        # Format: Internet Address    Physical Address      Type
        current_interface = None
        
        for line in output.split('\n'):
            line = line.strip()
            
            # Track which network interface we're looking at
            if 'Interface:' in line:
                match = re.search(r'Interface:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if match:
                    current_interface = match.group(1)
                continue
            
            # Look for device entries: IP address followed by MAC address
            match = re.match(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+((?:[0-9a-f]{2}-){5}[0-9a-f]{2})\s+(\w+)', line, re.IGNORECASE)
            
            if match:
                ip = match.group(1)
                mac = match.group(2).upper().replace('-', ':')
                entry_type = match.group(3).lower()
                
                # Skip invalid entries
                if entry_type == 'invalid':
                    continue
                
                # Skip broadcast and multicast addresses (not real devices)
                if ip.startswith('224.') or ip.startswith('239.') or ip.endswith('.255') or ip == '255.255.255.255':
                    continue
                
                # Skip broadcast MAC addresses
                if mac == 'FF:FF:FF:FF:FF:FF' or mac.startswith('01:00:5E'):
                    continue
                
                # Identify device type
                device = {
                    "id": str(uuid.uuid4()),
                    "ip_address": ip,
                    "mac_address": mac,
                    "device_type": "unknown",
                    "device_name": "Unknown Device",
                    "vendor": identify_vendor_from_mac(mac),
                    "is_router": ip == router_ip,
                    "connection_type": entry_type,
                    "last_seen": datetime.datetime.utcnow().isoformat() + "Z",
                    "risk_level": "unknown"
                }
                
                # Identify router
                if ip == router_ip:
                    device["device_type"] = "router"
                    device["device_name"] = "WiFi Router (Gateway)"
                    device["risk_level"] = "safe"
                
                # Try to get hostname
                hostname = get_device_hostname(ip)
                if hostname and hostname != ip:
                    device["device_name"] = hostname
                    device["hostname"] = hostname
                
                # Detect device type from hostname or vendor
                device_type = detect_device_type(device["device_name"], device["vendor"])
                if device_type:
                    device["device_type"] = device_type
                
                devices.append(device)
        
        return devices
    
    except Exception as e:
        return []


def get_device_hostname(ip: str) -> Optional[str]:
    """Try to get hostname for an IP address"""
    try:
        result = subprocess.run(
            ['nslookup', ip],
            capture_output=True,
            text=True,
            timeout=2
        )
        
        if result.returncode == 0:
            # Look for "Name:" in output
            match = re.search(r'Name:\s+(.+)', result.stdout)
            if match:
                return match.group(1).strip()
        
        return None
    except Exception:
        return None


def identify_vendor_from_mac(mac: str) -> str:
    """Identify device vendor/manufacturer from MAC address"""
    # MAC address OUI (first 3 octets) to vendor mapping
    # This is a small subset - in production, use a full OUI database
    mac_prefix = mac.upper()[:8]  # First 3 octets (XX:XX:XX)
    
    vendors = {
        "00:50:F2": "Microsoft",
        "00:15:5D": "Microsoft Hyper-V",
        "3C:5A:B4": "Google",
        "F4:F5:D8": "Google",
        "AC:37:43": "Apple",
        "00:03:93": "Apple",
        "00:05:02": "Apple",
        "00:0A:27": "Apple",
        "00:0A:95": "Apple",
        "00:0D:93": "Apple",
        "F0:18:98": "Apple",
        "B8:27:EB": "Raspberry Pi",
        "DC:A6:32": "Raspberry Pi",
        "E4:5F:01": "Raspberry Pi",
        "28:CD:C1": "Raspberry Pi",
        "00:1A:7D": "Samsung",
        "00:12:FB": "Samsung",
        "00:15:B9": "Samsung",
        "00:16:32": "Samsung",
        "5C:0A:5B": "Samsung",
        "70:5A:0F": "Samsung",
        "D0:C5:D3": "Samsung",
        "E8:50:8B": "Samsung",
        "00:1F:3F": "Cisco",
        "00:25:84": "Cisco",
        "00:40:96": "Cisco",
        "00:50:73": "Cisco",
        "00:0C:29": "VMware",
        "00:50:56": "VMware",
        "00:1C:14": "Dell",
        "00:14:22": "Dell",
        "D4:AE:52": "Dell",
        "00:1B:21": "HP",
        "00:30:C1": "HP",
        "00:01:E6": "TP-Link",
        "00:27:19": "TP-Link",
        "50:C7:BF": "TP-Link",
        "A0:F3:C1": "TP-Link",
    }
    
    return vendors.get(mac_prefix, "Unknown Vendor")


def detect_device_type(hostname: str, vendor: str) -> str:
    """Detect device type from hostname and vendor"""
    hostname_lower = hostname.lower() if hostname else ""
    vendor_lower = vendor.lower() if vendor else ""
    
    # Check hostname patterns
    if any(x in hostname_lower for x in ["iphone", "ipad", "ipod"]):
        return "smartphone"
    if any(x in hostname_lower for x in ["android", "samsung", "pixel"]):
        return "smartphone"
    if any(x in hostname_lower for x in ["laptop", "desktop", "pc", "computer"]):
        return "computer"
    if any(x in hostname_lower for x in ["router", "gateway", "ap"]):
        return "router"
    if any(x in hostname_lower for x in ["tv", "television", "roku", "chromecast"]):
        return "smart_tv"
    if any(x in hostname_lower for x in ["printer", "hp-", "canon-", "epson-"]):
        return "printer"
    if "raspberry" in hostname_lower or "raspberry" in vendor_lower:
        return "iot_device"
    
    # Check vendor patterns
    if "apple" in vendor_lower:
        return "smartphone"
    if "samsung" in vendor_lower:
        return "smartphone"
    if "google" in vendor_lower:
        return "smartphone"
    
    return "unknown"


def analyze_device_behavior(device: Dict[str, Any], known_devices: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze if device shows suspicious behavior"""
    issues = []
    risk_score = 0
    is_suspicious = False
    
    # Check if device is known
    mac = device.get("mac_address")
    is_known = any(d.get("mac_address") == mac for d in known_devices)
    
    if not is_known:
        issues.append(f"⚠️ Unknown device detected: {device.get('device_name')}")
        issues.append(f"   MAC: {mac}, IP: {device.get('ip_address')}")
        risk_score += 40
        is_suspicious = True
    
    # Check for randomized MAC address (privacy feature or spoofing)
    if mac and (mac.startswith("02:") or mac.startswith("06:") or mac.startswith("0A:") or mac.startswith("0E:")):
        issues.append("⚠️ Device using randomized MAC address")
        issues.append("   This could be privacy feature or MAC spoofing")
        risk_score += 20
    
    # Check for suspicious device names
    suspicious_names = ["kali", "parrot", "pentoo", "hack", "attacker", "evil", "rogue"]
    device_name_lower = device.get("device_name", "").lower()
    
    if any(name in device_name_lower for name in suspicious_names):
        issues.append(f"🔴 Suspicious device name detected: {device.get('device_name')}")
        risk_score += 50
        is_suspicious = True
    
    return {
        "is_suspicious": is_suspicious,
        "is_known": is_known,
        "risk_score": risk_score,
        "issues": issues
    }


def detect_network_anomalies(devices: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Detect network-level anomalies"""
    anomalies = []
    risk_score = 0
    
    # Count routers (should typically be 1)
    router_count = sum(1 for d in devices if d.get("is_router"))
    
    if router_count > 1:
        anomalies.append(f"⚠️ Multiple routers detected ({router_count})")
        anomalies.append("   This could indicate a rogue access point")
        risk_score += 40
    
    if router_count == 0:
        anomalies.append("⚠️ No router detected in device list")
        risk_score += 10
    
    # Count devices
    total_devices = len(devices)
    
    if total_devices > 50:
        anomalies.append(f"⚠️ Unusually high number of devices: {total_devices}")
        anomalies.append("   Could indicate network scanning or attack")
        risk_score += 30
    
    return {
        "has_anomalies": len(anomalies) > 0,
        "total_devices": total_devices,
        "router_count": router_count,
        "anomalies": anomalies,
        "risk_score": risk_score
    }


def perform_network_monitoring(known_devices: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    Main monitoring function - scans network and detects threats
    """
    if known_devices is None:
        known_devices = []
    
    # Get all connected devices
    devices = get_connected_devices()
    
    if not devices:
        return {
            "success": False,
            "error": "Could not scan network devices",
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
        }
    
    # Analyze each device
    suspicious_devices = []
    safe_devices = []
    unknown_devices = []
    
    for device in devices:
        behavior = analyze_device_behavior(device, known_devices)
        device["behavior_analysis"] = behavior
        
        if behavior["is_suspicious"]:
            suspicious_devices.append(device)
        elif behavior["is_known"]:
            safe_devices.append(device)
        else:
            unknown_devices.append(device)
    
    # Detect network-level anomalies
    network_analysis = detect_network_anomalies(devices)
    
    # Calculate overall risk
    total_risk_score = network_analysis["risk_score"]
    for device in suspicious_devices:
        total_risk_score += device["behavior_analysis"]["risk_score"]
    
    # Determine security status
    if total_risk_score >= 80:
        security_status = "critical"
        alert_level = "🔴 CRITICAL"
        verdict = "Potential security threat detected!"
    elif total_risk_score >= 40:
        security_status = "warning"
        alert_level = "🟡 WARNING"
        verdict = "Suspicious activity detected"
    else:
        security_status = "good"
        alert_level = "✅ SAFE"
        verdict = "Network appears secure"
    
    # Collect all issues
    all_issues = []
    all_issues.extend(network_analysis.get("anomalies", []))
    for device in suspicious_devices:
        all_issues.extend(device["behavior_analysis"].get("issues", []))
    
    return {
        "success": True,
        "security_status": security_status,
        "alert_level": alert_level,
        "verdict": verdict,
        "risk_score": total_risk_score,
        "summary": {
            "total_devices": len(devices),
            "safe_devices": len(safe_devices),
            "suspicious_devices": len(suspicious_devices),
            "unknown_devices": len(unknown_devices)
        },
        "devices": {
            "all": devices,
            "suspicious": suspicious_devices,
            "safe": safe_devices,
            "unknown": unknown_devices
        },
        "network_analysis": network_analysis,
        "issues": all_issues,
        "recommendations": generate_security_recommendations(
            suspicious_devices, 
            unknown_devices, 
            network_analysis
        ),
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
    }


def generate_security_recommendations(
    suspicious_devices: List[Dict],
    unknown_devices: List[Dict],
    network_analysis: Dict
) -> List[str]:
    """Generate security recommendations based on findings"""
    recommendations = []
    
    if suspicious_devices:
        recommendations.append("🔴 Investigate suspicious devices immediately")
        recommendations.append("   - Check if you recognize these devices")
        recommendations.append("   - Consider changing WiFi password")
        recommendations.append("   - Enable MAC address filtering on router")
    
    if unknown_devices:
        recommendations.append("🟡 Review unknown devices on your network")
        recommendations.append("   - Identify each device")
        recommendations.append("   - Remove any unauthorized devices")
    
    if network_analysis.get("router_count", 0) > 1:
        recommendations.append("🔴 Multiple routers detected - check for rogue access points")
        recommendations.append("   - Only your router should be broadcasting")
    
    if not suspicious_devices and not unknown_devices:
        recommendations.append("✅ Network security looks good")
        recommendations.append("💡 Continue monitoring regularly")
        recommendations.append("💡 Use strong WPA3 or WPA2 encryption")
        recommendations.append("💡 Change WiFi password periodically")
    
    return recommendations


def get_wifi_security_settings() -> Dict[str, Any]:
    """Get current WiFi security configuration"""
    try:
        result = subprocess.run(
            ['netsh', 'wlan', 'show', 'interfaces'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            output = result.stdout
            
            settings = {}
            
            patterns = {
                "ssid": r"SSID\s+:\s+(.+)",
                "authentication": r"Authentication\s+:\s+(.+)",
                "cipher": r"Cipher\s+:\s+(.+)",
            }
            
            for key, pattern in patterns.items():
                match = re.search(pattern, output, re.IGNORECASE)
                if match:
                    settings[key] = match.group(1).strip()
            
            return settings
        
        return {}
    except Exception:
        return {}
