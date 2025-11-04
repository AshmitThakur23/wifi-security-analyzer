"""
Alert/Notification Service
Send alerts when security threats are detected
"""
import datetime
from typing import Dict, Any, List
import json

class AlertManager:
    """Manages security alerts and notifications"""
    
    def __init__(self):
        self.alert_log = []
    
    def create_alert(
        self, 
        alert_type: str, 
        severity: str, 
        title: str, 
        description: str, 
        details: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Create a new security alert"""
        
        alert = {
            "id": f"alert_{len(self.alert_log) + 1}",
            "type": alert_type,
            "severity": severity,  # critical, high, medium, low
            "title": title,
            "description": description,
            "details": details or {},
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "resolved": False
        }
        
        self.alert_log.append(alert)
        
        # In a real application, you would:
        # 1. Send email notification
        # 2. Send SMS
        # 3. Push notification to mobile app
        # 4. Desktop notification
        # 5. Log to file or external monitoring service
        
        self._send_notification(alert)
        
        return alert
    
    def _send_notification(self, alert: Dict[str, Any]):
        """Send notification to user"""
        severity_icons = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵"
        }
        
        icon = severity_icons.get(alert["severity"], "ℹ️")
        
        notification_message = f"""
{icon} WiFi Security Alert!

Title: {alert['title']}
Severity: {alert['severity'].upper()}
Time: {alert['timestamp']}

{alert['description']}

Details: {json.dumps(alert['details'], indent=2)}
"""
        
        # Log to console (in production, this would send actual notifications)
        print("=" * 60)
        print("SECURITY ALERT")
        print("=" * 60)
        print(notification_message)
        print("=" * 60)
        
        # TODO: Implement actual notification methods:
        # - Email via SMTP
        # - SMS via Twilio/AWS SNS
        # - Desktop notification via plyer or win10toast
        # - Mobile push via Firebase Cloud Messaging
    
    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get all unresolved alerts"""
        return [a for a in self.alert_log if not a["resolved"]]
    
    def resolve_alert(self, alert_id: str):
        """Mark an alert as resolved"""
        for alert in self.alert_log:
            if alert["id"] == alert_id:
                alert["resolved"] = True
                alert["resolved_at"] = datetime.datetime.utcnow().isoformat() + "Z"
                return True
        return False
    
    def get_alert_summary(self) -> Dict[str, Any]:
        """Get summary of alerts"""
        active = self.get_active_alerts()
        
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
        
        for alert in active:
            severity = alert.get("severity", "low")
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return {
            "total_alerts": len(self.alert_log),
            "active_alerts": len(active),
            "resolved_alerts": len(self.alert_log) - len(active),
            "by_severity": severity_counts
        }


# Global alert manager instance
alert_manager = AlertManager()


def send_suspicious_device_alert(device: Dict[str, Any], issues: List[str]):
    """Send alert for suspicious device detected on network"""
    
    description = f"A suspicious device was detected on your network.\n\n"
    description += f"Device: {device.get('device_name', 'Unknown')}\n"
    description += f"IP: {device.get('ip_address', 'Unknown')}\n"
    description += f"MAC: {device.get('mac_address', 'Unknown')}\n\n"
    description += "Issues:\n" + "\n".join(issues)
    
    return alert_manager.create_alert(
        alert_type="suspicious_device",
        severity="high",
        title=f"Suspicious Device: {device.get('device_name', 'Unknown')}",
        description=description,
        details=device
    )


def send_unsafe_wifi_alert(network: Dict[str, Any], risk_score: int):
    """Send alert for unsafe WiFi connection"""
    
    description = f"The WiFi network you're connected to may be unsafe.\n\n"
    description += f"Network: {network.get('ssid', 'Unknown')}\n"
    description += f"Security: {network.get('authentication', 'Unknown')}\n"
    description += f"Risk Score: {risk_score}/100\n\n"
    description += "⚠️ Avoid sensitive activities on this network."
    
    severity = "critical" if risk_score >= 80 else "high" if risk_score >= 50 else "medium"
    
    return alert_manager.create_alert(
        alert_type="unsafe_wifi",
        severity=severity,
        title=f"Unsafe WiFi: {network.get('ssid', 'Unknown')}",
        description=description,
        details=network
    )


def send_network_anomaly_alert(anomaly_type: str, description: str, details: Dict[str, Any]):
    """Send alert for network anomaly"""
    
    return alert_manager.create_alert(
        alert_type="network_anomaly",
        severity="medium",
        title=f"Network Anomaly: {anomaly_type}",
        description=description,
        details=details
    )


def get_alert_manager():
    """Get the global alert manager instance"""
    return alert_manager
