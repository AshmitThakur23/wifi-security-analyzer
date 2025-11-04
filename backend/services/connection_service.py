"""
Connection Service - Check if current WiFi connection is safe
Real-time WiFi security analysis
"""
import subprocess
import re
import uuid
import datetime
from typing import Dict, List, Any

def get_current_wifi_info() -> Dict[str, Any]:
    """Get information about currently connected WiFi network"""
    try:
        result = subprocess.run(
            ['netsh', 'wlan', 'show', 'interfaces'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode != 0:
            return {"connected": False, "error": "WiFi adapter not found or disabled"}
        
        output = result.stdout
        
        # Check if connected
        if "State" in output and "connected" not in output.lower():
            return {"connected": False, "message": "Not connected to any WiFi"}
        
        info = {"connected": True}
        
        # Extract WiFi details
        patterns = {
            "ssid": r"SSID\s+:\s+(.+)",
            "bssid": r"BSSID\s+:\s+((?:[0-9a-f]{2}:){5}[0-9a-f]{2})",
            "authentication": r"Authentication\s+:\s+(.+)",
            "cipher": r"Cipher\s+:\s+(.+)",
            "channel": r"Channel\s+:\s+(\d+)",
            "signal": r"Signal\s+:\s+(\d+)%"
        }
        
        for key, pattern in patterns.items():
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                info[key] = match.group(1).strip()
        
        # Convert signal to dBm (approximate)
        if "signal" in info:
            signal_percent = int(info["signal"])
            info["signal_dbm"] = -100 + signal_percent
            info["signal_percent"] = signal_percent
        
        return info
        
    except subprocess.TimeoutExpired:
        return {"connected": False, "error": "Command timeout"}
    except Exception as e:
        return {"connected": False, "error": f"Failed to get WiFi info: {str(e)}"}


def check_encryption_security(auth: str, cipher: str) -> Dict[str, Any]:
    """Analyze encryption strength"""
    auth_lower = auth.lower() if auth else ""
    cipher_lower = cipher.lower() if cipher else ""
    
    result = {
        "is_secure": False,
        "encryption_level": "unknown",
        "issues": [],
        "recommendations": []
    }
    
    # Open network - CRITICAL
    if "open" in auth_lower or not auth:
        result["is_secure"] = False
        result["encryption_level"] = "none"
        result["issues"].append("❌ No encryption - Anyone can intercept your data")
        result["recommendations"].append("🔴 DO NOT use this network for sensitive activities")
        result["recommendations"].append("Use a VPN if you must connect")
        return result
    
    # WEP - CRITICAL (easily cracked)
    if "wep" in auth_lower:
        result["is_secure"] = False
        result["encryption_level"] = "wep"
        result["issues"].append("❌ WEP is extremely insecure (can be cracked in minutes)")
        result["recommendations"].append("🔴 DO NOT use this network")
        result["recommendations"].append("Ask network owner to upgrade to WPA2/WPA3")
        return result
    
    # WPA (original) - VULNERABLE
    if "wpa" in auth_lower and "wpa2" not in auth_lower and "wpa3" not in auth_lower:
        result["is_secure"] = False
        result["encryption_level"] = "wpa"
        result["issues"].append("⚠️ WPA1 is outdated and vulnerable")
        result["recommendations"].append("🟡 Use caution - upgrade to WPA2/WPA3 recommended")
        return result
    
    # WPA2-Personal - GOOD (if using AES)
    if "wpa2" in auth_lower:
        if "aes" in cipher_lower or "ccmp" in cipher_lower:
            result["is_secure"] = True
            result["encryption_level"] = "wpa2-aes"
            result["recommendations"].append("✅ Good security - WPA2 with AES")
            result["recommendations"].append("💡 Consider upgrading to WPA3 for best security")
        elif "tkip" in cipher_lower:
            result["is_secure"] = False
            result["encryption_level"] = "wpa2-tkip"
            result["issues"].append("⚠️ TKIP cipher is vulnerable")
            result["recommendations"].append("🟡 Ask network owner to use AES instead of TKIP")
        else:
            result["is_secure"] = True
            result["encryption_level"] = "wpa2"
            result["recommendations"].append("✅ WPA2 security enabled")
        return result
    
    # WPA3 - EXCELLENT
    if "wpa3" in auth_lower:
        result["is_secure"] = True
        result["encryption_level"] = "wpa3"
        result["recommendations"].append("✅ Excellent security - WPA3 is the latest standard")
        result["recommendations"].append("✅ Protected against offline password attacks")
        return result
    
    return result


def check_evil_twin_indicators(ssid: str, bssid: str, signal: int) -> Dict[str, Any]:
    """Check for Evil Twin / Rogue AP indicators"""
    issues = []
    risk_score = 0
    
    try:
        # Get all networks with same SSID
        result = subprocess.run(
            ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            output = result.stdout
            
            # Find all BSSIDs for this SSID
            ssid_blocks = []
            current_block = []
            in_target_ssid = False
            
            for line in output.split('\n'):
                line = line.strip()
                
                if line.startswith('SSID') and ':' in line:
                    if current_block:
                        if in_target_ssid:
                            ssid_blocks.append('\n'.join(current_block))
                    current_block = []
                    found_ssid = line.split(':', 1)[1].strip()
                    in_target_ssid = (found_ssid == ssid)
                
                if in_target_ssid:
                    current_block.append(line)
            
            if current_block and in_target_ssid:
                ssid_blocks.append('\n'.join(current_block))
            
            # Count access points with same SSID
            bssid_count = len(re.findall(r'BSSID', '\n'.join(ssid_blocks)))
            
            if bssid_count > 1:
                issues.append(f"⚠️ Multiple access points ({bssid_count}) broadcasting same network name")
                issues.append("This could be normal (mesh network) or an Evil Twin attack")
                risk_score += 30
            
            # Check for suspicious signal strength (very strong signal in public area)
            if signal > -30:
                issues.append(f"⚠️ Unusually strong signal ({signal} dBm) - possible rogue AP nearby")
                risk_score += 20
    
    except Exception as e:
        pass  # Non-critical check
    
    return {
        "has_indicators": len(issues) > 0,
        "issues": issues,
        "risk_score": risk_score
    }


def check_dns_hijacking() -> Dict[str, Any]:
    """Check for potential DNS hijacking"""
    issues = []
    risk_score = 0
    
    try:
        # Get DNS servers for WiFi interface
        result = subprocess.run(
            ['netsh', 'interface', 'ipv4', 'show', 'dnsservers', 'name=Wi-Fi'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            output = result.stdout
            
            # Look for suspicious DNS servers
            dns_ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', output)
            
            # Common legitimate DNS servers
            trusted_dns = [
                '8.8.8.8', '8.8.4.4',  # Google
                '1.1.1.1', '1.0.0.1',  # Cloudflare
                '208.67.222.222', '208.67.220.220'  # OpenDNS
            ]
            
            for dns_ip in dns_ips:
                # Check if it's a private IP (router DNS is normal)
                octets = dns_ip.split('.')
                first_octet = int(octets[0])
                
                if first_octet in [192, 172, 10]:
                    continue  # Router DNS is normal
                
                if dns_ip not in trusted_dns:
                    issues.append(f"⚠️ Unusual DNS server detected: {dns_ip}")
                    issues.append("Could be normal ISP DNS or potential DNS hijacking")
                    risk_score += 15
    
    except Exception:
        pass  # Non-critical check
    
    return {
        "suspicious_dns": len(issues) > 0,
        "issues": issues,
        "risk_score": risk_score
    }


def perform_connection_security_check() -> Dict[str, Any]:
    """Main function to check if current WiFi connection is safe"""
    
    # Get current connection info
    wifi_info = get_current_wifi_info()
    
    if not wifi_info.get("connected"):
        return {
            "success": False,
            "connected": False,
            "message": wifi_info.get("error", "Not connected to WiFi"),
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
        }
    
    # Initialize security check result
    security_check = {
        "success": True,
        "connected": True,
        "network": {
            "ssid": wifi_info.get("ssid", "Unknown"),
            "bssid": wifi_info.get("bssid", "Unknown"),
            "channel": wifi_info.get("channel", "Unknown"),
            "signal_percent": wifi_info.get("signal_percent", 0),
            "signal_dbm": wifi_info.get("signal_dbm", -100),
            "authentication": wifi_info.get("authentication", "Unknown"),
            "cipher": wifi_info.get("cipher", "Unknown")
        },
        "is_safe": True,
        "risk_score": 0,
        "security_level": "unknown",
        "checks": {
            "encryption": {},
            "evil_twin": {},
            "dns": {}
        },
        "all_issues": [],
        "recommendations": [],
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
    }
    
    # Check 1: Encryption Security
    encryption_check = check_encryption_security(
        wifi_info.get("authentication", ""),
        wifi_info.get("cipher", "")
    )
    security_check["checks"]["encryption"] = encryption_check
    
    if not encryption_check["is_secure"]:
        security_check["is_safe"] = False
        security_check["risk_score"] += 60
    
    security_check["all_issues"].extend(encryption_check.get("issues", []))
    security_check["recommendations"].extend(encryption_check.get("recommendations", []))
    
    # Check 2: Evil Twin Indicators
    evil_twin_check = check_evil_twin_indicators(
        wifi_info.get("ssid", ""),
        wifi_info.get("bssid", ""),
        wifi_info.get("signal_dbm", -100)
    )
    security_check["checks"]["evil_twin"] = evil_twin_check
    
    if evil_twin_check["has_indicators"]:
        security_check["risk_score"] += evil_twin_check["risk_score"]
        security_check["all_issues"].extend(evil_twin_check["issues"])
    
    # Check 3: DNS Hijacking
    dns_check = check_dns_hijacking()
    security_check["checks"]["dns"] = dns_check
    
    if dns_check["suspicious_dns"]:
        security_check["risk_score"] += dns_check["risk_score"]
        security_check["all_issues"].extend(dns_check["issues"])
    
    # Calculate final security level
    if security_check["risk_score"] >= 60:
        security_check["security_level"] = "critical"
        security_check["is_safe"] = False
        security_check["verdict"] = "🔴 UNSAFE - Do not use this network"
    elif security_check["risk_score"] >= 30:
        security_check["security_level"] = "medium"
        security_check["verdict"] = "🟡 CAUTION - Use with care, enable VPN"
    else:
        security_check["security_level"] = "good"
        security_check["verdict"] = "✅ SAFE - Network appears secure"
    
    return security_check


def get_available_networks_with_security() -> List[Dict[str, Any]]:
    """Scan and return all available WiFi networks with security analysis"""
    networks = []
    
    try:
        result = subprocess.run(
            ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
            capture_output=True,
            text=True,
            timeout=15
        )
        
        if result.returncode != 0:
            return []
        
        output = result.stdout
        current_network = {}
        
        for line in output.split('\n'):
            line = line.strip()
            
            if line.startswith('SSID') and ':' in line:
                # Save previous network
                if current_network.get('bssid'):
                    # Analyze security
                    enc_check = check_encryption_security(
                        current_network.get('authentication', ''),
                        current_network.get('cipher', '')
                    )
                    current_network['is_secure'] = enc_check['is_secure']
                    current_network['security_level'] = enc_check['encryption_level']
                    current_network['security_icon'] = '🔴' if not enc_check['is_secure'] else '✅'
                    
                    networks.append(current_network)
                
                # Start new network
                ssid = line.split(':', 1)[1].strip()
                current_network = {
                    'ssid': ssid if ssid else 'Hidden Network',
                    'id': str(uuid.uuid4())
                }
            
            elif 'Authentication' in line and ':' in line:
                current_network['authentication'] = line.split(':', 1)[1].strip()
            
            elif 'Cipher' in line and ':' in line:
                current_network['cipher'] = line.split(':', 1)[1].strip()
            
            elif 'BSSID' in line:
                bssid_match = re.search(r'([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})', line, re.I)
                if bssid_match:
                    current_network['bssid'] = bssid_match.group(1).upper()
            
            elif 'Signal' in line:
                signal_match = re.search(r'(\d+)%', line)
                if signal_match:
                    signal_percent = int(signal_match.group(1))
                    current_network['signal_percent'] = signal_percent
                    current_network['signal_dbm'] = -100 + signal_percent
            
            elif 'Channel' in line:
                channel_match = re.search(r'(\d+)', line)
                if channel_match:
                    current_network['channel'] = int(channel_match.group(1))
        
        # Don't forget the last network
        if current_network.get('bssid'):
            enc_check = check_encryption_security(
                current_network.get('authentication', ''),
                current_network.get('cipher', '')
            )
            current_network['is_secure'] = enc_check['is_secure']
            current_network['security_level'] = enc_check['encryption_level']
            current_network['security_icon'] = '🔴' if not enc_check['is_secure'] else '✅'
            networks.append(current_network)
        
        return networks
    
    except Exception as e:
        return []
