"""
Continuous 24/7 WiFi Monitoring Service
Runs in background, monitors any WiFi network continuously
"""
import threading
import time
import datetime
import json
from typing import Dict, Any, List, Optional
from services.monitoring_service import (
    get_connected_devices,
    analyze_device_behavior,
    detect_network_anomalies
)
from services.connection_service import get_current_wifi_info


class ContinuousMonitor:
    """24/7 Background WiFi Monitor"""
    
    def __init__(self, db, models):
        self.db = db
        self.models = models
        self.is_running = False
        self.monitor_thread = None
        self.check_interval = 300  # 5 minutes default
        self.scan_history = []
        self.known_devices = {}  # MAC -> device info
        self.alerts_queue = []
        
    def start_monitoring(self, check_interval: int = 300) -> Dict[str, Any]:
        """
        Start 24/7 monitoring
        check_interval: seconds between checks (default 300 = 5 minutes)
        """
        if self.is_running:
            return {
                "success": False,
                "message": "Monitoring is already running",
                "status": "already_active"
            }
        
        self.is_running = True
        self.check_interval = check_interval
        
        # Start monitoring in background thread
        self.monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            daemon=True
        )
        self.monitor_thread.start()
        
        # Save monitoring state to database
        self._save_monitoring_state(True)
        
        return {
            "success": True,
            "message": f"✅ 24/7 Monitoring Started! Checking every {check_interval // 60} minutes",
            "status": "active",
            "check_interval": check_interval,
            "started_at": datetime.datetime.utcnow().isoformat() + "Z"
        }
    
    def stop_monitoring(self) -> Dict[str, Any]:
        """Stop monitoring"""
        if not self.is_running:
            return {
                "success": False,
                "message": "Monitoring is not running",
                "status": "inactive"
            }
        
        self.is_running = False
        
        # Save monitoring state
        self._save_monitoring_state(False)
        
        return {
            "success": True,
            "message": "⏸️ Monitoring Stopped",
            "status": "inactive",
            "stopped_at": datetime.datetime.utcnow().isoformat() + "Z",
            "total_scans": len(self.scan_history)
        }
    
    def get_status(self) -> Dict[str, Any]:
        """Get current monitoring status"""
        return {
            "is_running": self.is_running,
            "status": "active" if self.is_running else "inactive",
            "check_interval_seconds": self.check_interval,
            "check_interval_minutes": self.check_interval // 60,
            "total_scans": len(self.scan_history),
            "total_alerts": len(self.alerts_queue),
            "unread_alerts": len([a for a in self.alerts_queue if not a.get("read", False)]),
            "known_devices_count": len(self.known_devices),
            "last_scan": self.scan_history[-1] if self.scan_history else None
        }
    
    def _monitoring_loop(self):
        """Main monitoring loop - runs in background"""
        print(f"\n{'='*60}")
        print("🔄 24/7 Monitoring Started")
        print(f"📡 Will scan every {self.check_interval // 60} minutes")
        print(f"{'='*60}\n")
        
        while self.is_running:
            try:
                # Perform network scan
                self._perform_scan()
                
                # Sleep until next check
                time.sleep(self.check_interval)
                
            except Exception as e:
                print(f"❌ Monitoring error: {e}")
                time.sleep(60)  # Wait 1 minute before retry
    
    def _perform_scan(self):
        """Perform a single network scan"""
        timestamp = datetime.datetime.utcnow()
        
        # Get current WiFi info
        wifi_info = get_current_wifi_info()
        
        if not wifi_info.get("connected"):
            # Not connected to WiFi - skip this scan
            print(f"⏭️ [{timestamp.strftime('%Y-%m-%d %H:%M:%S')}] Not connected to WiFi - skipping scan")
            return
        
        current_ssid = wifi_info.get("ssid", "Unknown")
        current_bssid = wifi_info.get("bssid", "Unknown")
        
        print(f"\n🔍 [{timestamp.strftime('%Y-%m-%d %H:%M:%S')}] Scanning: {current_ssid}")
        
        # Get all connected devices
        devices = get_connected_devices()
        
        # Analyze devices
        suspicious_devices = []
        new_devices = []
        
        for device in devices:
            mac = device.get("mac_address")
            
            # Check if device is new
            if mac not in self.known_devices:
                new_devices.append(device)
                print(f"  🆕 New device: {device.get('device_name')} ({mac})")
            
            # Analyze behavior
            behavior = analyze_device_behavior(
                device,
                list(self.known_devices.values())
            )
            
            if behavior.get("is_suspicious"):
                suspicious_devices.append(device)
                print(f"  ⚠️ Suspicious: {device.get('device_name')} ({mac})")
        
        # Detect network anomalies
        network_analysis = detect_network_anomalies(devices)
        
        # Calculate risk score
        risk_score = network_analysis.get("risk_score", 0)
        for device in suspicious_devices:
            risk_score += device.get("behavior_analysis", {}).get("risk_score", 0)
        
        # Create scan record
        scan_record = {
            "id": f"scan_{len(self.scan_history) + 1}",
            "timestamp": timestamp.isoformat() + "Z",
            "wifi_ssid": current_ssid,
            "wifi_bssid": current_bssid,
            "wifi_security": wifi_info.get("authentication", "Unknown"),
            "total_devices": len(devices),
            "new_devices": len(new_devices),
            "suspicious_devices": len(suspicious_devices),
            "risk_score": risk_score,
            "devices": devices,
            "network_analysis": network_analysis
        }
        
        # Save to history
        self.scan_history.append(scan_record)
        
        # Save to database
        self._save_scan_to_db(scan_record)
        
        # Generate alerts if needed
        if suspicious_devices or new_devices or risk_score >= 40:
            self._generate_alert(
                scan_record,
                suspicious_devices,
                new_devices,
                risk_score
            )
        
        print(f"  ✅ Scan complete: {len(devices)} devices, Risk: {risk_score}/100")
        
        # Auto-learn new devices (mark as known after first scan)
        for device in new_devices:
            mac = device.get("mac_address")
            if mac:
                self.known_devices[mac] = device
    
    def _generate_alert(
        self,
        scan_record: Dict,
        suspicious_devices: List[Dict],
        new_devices: List[Dict],
        risk_score: int
    ):
        """Generate alert for suspicious activity"""
        alert = {
            "id": f"alert_{len(self.alerts_queue) + 1}",
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "scan_id": scan_record["id"],
            "wifi_ssid": scan_record["wifi_ssid"],
            "severity": "critical" if risk_score >= 80 else "high" if risk_score >= 40 else "medium",
            "risk_score": risk_score,
            "read": False,
            "details": {}
        }
        
        # Build alert message
        messages = []
        
        if suspicious_devices:
            alert["details"]["suspicious_devices"] = suspicious_devices
            messages.append(f"🔴 {len(suspicious_devices)} suspicious device(s) detected")
        
        if new_devices:
            alert["details"]["new_devices"] = new_devices
            messages.append(f"🆕 {len(new_devices)} new device(s) connected")
        
        if scan_record["network_analysis"].get("has_anomalies"):
            alert["details"]["anomalies"] = scan_record["network_analysis"]["anomalies"]
            messages.append("⚠️ Network anomalies detected")
        
        alert["title"] = f"Security Alert: {scan_record['wifi_ssid']}"
        alert["message"] = "\n".join(messages)
        
        # Add to alerts queue
        self.alerts_queue.append(alert)
        
        # Save to database
        self._save_alert_to_db(alert)
        
        # Print alert
        print(f"\n{'='*60}")
        print(f"🚨 SECURITY ALERT!")
        print(f"{'='*60}")
        print(f"Network: {scan_record['wifi_ssid']}")
        print(f"Time: {alert['timestamp']}")
        print(f"Severity: {alert['severity'].upper()}")
        print(alert["message"])
        print(f"{'='*60}\n")
    
    def get_history(
        self,
        days: int = 7,
        wifi_ssid: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get scan history for past X days
        Useful for: "What happened while I was away?"
        """
        cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=days)
        
        # Filter history
        filtered_history = []
        for scan in self.scan_history:
            scan_time = datetime.datetime.fromisoformat(scan["timestamp"].replace("Z", ""))
            
            if scan_time >= cutoff:
                if wifi_ssid is None or scan.get("wifi_ssid") == wifi_ssid:
                    filtered_history.append(scan)
        
        # Calculate statistics
        total_scans = len(filtered_history)
        total_devices_seen = set()
        total_alerts = 0
        suspicious_count = 0
        
        for scan in filtered_history:
            for device in scan.get("devices", []):
                total_devices_seen.add(device.get("mac_address"))
            
            if scan.get("suspicious_devices", 0) > 0:
                suspicious_count += 1
        
        # Get alerts in this period
        alerts_in_period = [
            a for a in self.alerts_queue
            if datetime.datetime.fromisoformat(a["timestamp"].replace("Z", "")) >= cutoff
        ]
        
        return {
            "period": f"Last {days} days",
            "from": cutoff.isoformat() + "Z",
            "to": datetime.datetime.utcnow().isoformat() + "Z",
            "statistics": {
                "total_scans": total_scans,
                "unique_devices": len(total_devices_seen),
                "scans_with_suspicious_activity": suspicious_count,
                "total_alerts": len(alerts_in_period)
            },
            "scans": filtered_history,
            "alerts": alerts_in_period
        }
    
    def get_weekly_report(self, wifi_ssid: Optional[str] = None) -> Dict[str, Any]:
        """Generate weekly report"""
        return self.get_history(days=7, wifi_ssid=wifi_ssid)
    
    def get_alerts(self, unread_only: bool = False) -> List[Dict[str, Any]]:
        """Get all alerts"""
        if unread_only:
            return [a for a in self.alerts_queue if not a.get("read", False)]
        return self.alerts_queue
    
    def mark_alert_read(self, alert_id: str) -> bool:
        """Mark alert as read"""
        for alert in self.alerts_queue:
            if alert["id"] == alert_id:
                alert["read"] = True
                return True
        return False
    
    def clear_alerts(self):
        """Clear all read alerts"""
        self.alerts_queue = [a for a in self.alerts_queue if not a.get("read", False)]
    
    def add_known_device(self, mac_address: str, device_info: Dict[str, Any]):
        """Manually add a device to known devices list"""
        self.known_devices[mac_address] = device_info
    
    def remove_known_device(self, mac_address: str):
        """Remove device from known devices"""
        if mac_address in self.known_devices:
            del self.known_devices[mac_address]
    
    def get_known_devices(self) -> List[Dict[str, Any]]:
        """Get list of known devices"""
        return list(self.known_devices.values())
    
    def _save_monitoring_state(self, is_active: bool):
        """Save monitoring state to database"""
        try:
            # You can implement saving to database here
            pass
        except Exception as e:
            print(f"Error saving monitoring state: {e}")
    
    def _save_scan_to_db(self, scan_record: Dict[str, Any]):
        """Save scan record to database"""
        try:
            MonitoringScan = self.models.get("MonitoringScan")
            if MonitoringScan:
                scan = MonitoringScan(
                    id=scan_record["id"],
                    wifi_ssid=scan_record["wifi_ssid"],
                    wifi_bssid=scan_record["wifi_bssid"],
                    total_devices=scan_record["total_devices"],
                    suspicious_devices=scan_record["suspicious_devices"],
                    risk_score=scan_record["risk_score"],
                    scan_data=scan_record
                )
                self.db.session.add(scan)
                self.db.session.commit()
        except Exception as e:
            print(f"Error saving scan to DB: {e}")
    
    def _save_alert_to_db(self, alert: Dict[str, Any]):
        """Save alert to database"""
        try:
            SecurityAlert = self.models.get("SecurityAlert")
            if SecurityAlert:
                alert_record = SecurityAlert(
                    id=alert["id"],
                    network_bssid=alert.get("wifi_ssid", "unknown"),
                    alert_type="continuous_monitoring",
                    severity=alert["severity"],
                    description=alert["message"],
                    details=alert["details"]
                )
                self.db.session.add(alert_record)
                self.db.session.commit()
        except Exception as e:
            print(f"Error saving alert to DB: {e}")


# Global monitor instance
_monitor_instance = None


def get_monitor(db=None, models=None) -> ContinuousMonitor:
    """Get or create global monitor instance"""
    global _monitor_instance
    if _monitor_instance is None and db and models:
        _monitor_instance = ContinuousMonitor(db, models)
    return _monitor_instance
