"""Scan Service - Real WiFi Scanning"""
import subprocess
import re
import uuid

def real_scan():
    """Scan real WiFi networks using Windows netsh"""
    networks = []
    try:
        result = subprocess.run(['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                               capture_output=True, text=True, timeout=10)
        
        if result.returncode != 0:
            raise Exception("WiFi scan failed")
        
        current_network = {}
        for line in result.stdout.split('\n'):
            line = line.strip()
            if line.startswith('SSID') and ':' in line:
                if current_network.get('bssid'):
                    networks.append(current_network)
                ssid = line.split(':', 1)[1].strip()
                current_network = {'ssid': ssid if ssid else 'Hidden Network'}
            elif 'Authentication' in line:
                current_network['encryption'] = line.split(':', 1)[1].strip()
            elif 'BSSID' in line:
                bssid_match = re.search(r'([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})', line, re.I)
                if bssid_match:
                    current_network['bssid'] = bssid_match.group(1).upper()
            elif 'Signal' in line:
                signal_match = re.search(r'(\d+)%', line)
                if signal_match:
                    current_network['signal'] = -100 + int(signal_match.group(1))
            elif 'Channel' in line:
                channel_match = re.search(r'(\d+)', line)
                if channel_match:
                    current_network['channel'] = int(channel_match.group(1))
        
        if current_network.get('bssid'):
            networks.append(current_network)
        
        for network in networks:
            network.setdefault('ssid', 'Hidden')
            network.setdefault('encryption', 'Unknown')
            network.setdefault('signal', -70)
            network.setdefault('channel', 0)
        
        return networks
    except Exception as e:
        raise Exception(f"WiFi scan failed: {str(e)}")

def save_networks_to_db(db, Network, networks_data):
    """Save networks to database"""
    saved = []
    for n in networks_data:
        net = Network(id=str(uuid.uuid4()), ssid=n["ssid"], bssid=n["bssid"],
                     channel=n["channel"], signal=n["signal"], encryption=n["encryption"])
        db.session.add(net)
        saved.append(net.to_dict())
    db.session.commit()
    return saved

def perform_security_audit(network):
    """Perform security audit"""
    result = {
        "weak_cipher": False if network.encryption and "WPA3" in network.encryption else True,
        "open_network": True if network.encryption and network.encryption.lower() == "open" else False,
        "signal_strength": network.signal,
        "risk_level": "low"
    }
    if result["open_network"]:
        result["risk_level"] = "high"
    elif result["weak_cipher"]:
        result["risk_level"] = "medium"
    result["details"] = []
    if result["open_network"]:
        result["details"].append("Network is unencrypted")
    if result["weak_cipher"]:
        result["details"].append("Network uses weak encryption")
    return result
