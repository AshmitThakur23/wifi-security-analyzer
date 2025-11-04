from flask_sqlalchemy import SQLAlchemy
import datetime
import json

db = SQLAlchemy()

class Network(db.Model):
    id = db.Column(db.String, primary_key=True)
    ssid = db.Column(db.String, nullable=True)
    bssid = db.Column(db.String, unique=True, nullable=False)
    channel = db.Column(db.Integer, nullable=True)
    signal = db.Column(db.Integer, nullable=True)
    encryption = db.Column(db.String, nullable=True)
    discovered_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "ssid": self.ssid,
            "bssid": self.bssid,
            "channel": self.channel,
            "signal": self.signal,
            "encryption": self.encryption,
            "discovered_at": self.discovered_at.isoformat() + "Z" if self.discovered_at else None
        }

class Audit(db.Model):
    id = db.Column(db.String, primary_key=True)
    network_bssid = db.Column(db.String, db.ForeignKey('network.bssid'), nullable=False)
    started_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    result_json = db.Column(db.Text, nullable=True)

    @property
    def result(self):
        return json.loads(self.result_json) if self.result_json else None

    @result.setter
    def result(self, value):
        self.result_json = json.dumps(value)

    def to_dict(self):
        return {
            "id": self.id,
            "network_bssid": self.network_bssid,
            "started_at": self.started_at.isoformat() + "Z" if self.started_at else None,
            "result": self.result
        }

class MonitoredNetwork(db.Model):
    id = db.Column(db.String, primary_key=True)
    ssid = db.Column(db.String, nullable=False)
    bssid = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=True)
    is_owned = db.Column(db.Boolean, default=True)
    monitoring_enabled = db.Column(db.Boolean, default=True)
    check_interval = db.Column(db.Integer, default=604800)
    last_checked = db.Column(db.DateTime, nullable=True)
    added_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    def to_dict(self):
        return {
            "id": self.id,
            "ssid": self.ssid,
            "bssid": self.bssid,
            "is_owned": self.is_owned,
            "monitoring_enabled": self.monitoring_enabled,
            "check_interval": self.check_interval,
            "last_checked": self.last_checked.isoformat() + "Z" if self.last_checked else None,
            "added_at": self.added_at.isoformat() + "Z" if self.added_at else None
        }

class SecurityAlert(db.Model):
    id = db.Column(db.String, primary_key=True)
    network_bssid = db.Column(db.String, db.ForeignKey('monitored_network.bssid'), nullable=False)
    alert_type = db.Column(db.String, nullable=False)
    severity = db.Column(db.String, nullable=False)
    description = db.Column(db.Text, nullable=False)
    details_json = db.Column(db.Text, nullable=True)
    detected_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    resolved = db.Column(db.Boolean, default=False)
    
    @property
    def details(self):
        return json.loads(self.details_json) if self.details_json else {}

    @details.setter
    def details(self, value):
        self.details_json = json.dumps(value)
    
    def to_dict(self):
        return {
            "id": self.id,
            "network_bssid": self.network_bssid,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "description": self.description,
            "details": self.details,
            "detected_at": self.detected_at.isoformat() + "Z" if self.detected_at else None,
            "resolved": self.resolved
        }

class ConnectionCheck(db.Model):
    id = db.Column(db.String, primary_key=True)
    ssid = db.Column(db.String, nullable=True)
    bssid = db.Column(db.String, nullable=False)
    is_safe = db.Column(db.Boolean, nullable=False)
    risk_score = db.Column(db.Integer, default=0)
    checks_json = db.Column(db.Text, nullable=True)
    checked_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    @property
    def checks(self):
        return json.loads(self.checks_json) if self.checks_json else {}

    @checks.setter
    def checks(self, value):
        self.checks_json = json.dumps(value)
    
    def to_dict(self):
        return {
            "id": self.id,
            "ssid": self.ssid,
            "bssid": self.bssid,
            "is_safe": self.is_safe,
            "risk_score": self.risk_score,
            "checks": self.checks,
            "checked_at": self.checked_at.isoformat() + "Z" if self.checked_at else None
        }

class MonitoringScan(db.Model):
    """Stores 24/7 monitoring scan results"""
    id = db.Column(db.String, primary_key=True)
    wifi_ssid = db.Column(db.String, nullable=False)
    wifi_bssid = db.Column(db.String, nullable=False)
    total_devices = db.Column(db.Integer, default=0)
    suspicious_devices = db.Column(db.Integer, default=0)
    risk_score = db.Column(db.Integer, default=0)
    scan_data_json = db.Column(db.Text, nullable=True)
    scanned_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    @property
    def scan_data(self):
        return json.loads(self.scan_data_json) if self.scan_data_json else {}

    @scan_data.setter
    def scan_data(self, value):
        self.scan_data_json = json.dumps(value)
    
    def to_dict(self):
        return {
            "id": self.id,
            "wifi_ssid": self.wifi_ssid,
            "wifi_bssid": self.wifi_bssid,
            "total_devices": self.total_devices,
            "suspicious_devices": self.suspicious_devices,
            "risk_score": self.risk_score,
            "scan_data": self.scan_data,
            "scanned_at": self.scanned_at.isoformat() + "Z" if self.scanned_at else None
        }

class MonitoringState(db.Model):
    """Stores monitoring on/off state"""
    id = db.Column(db.Integer, primary_key=True)
    is_active = db.Column(db.Boolean, default=False)
    check_interval = db.Column(db.Integer, default=300)
    started_at = db.Column(db.DateTime, nullable=True)
    stopped_at = db.Column(db.DateTime, nullable=True)
    
    def to_dict(self):
        return {
            "id": self.id,
            "is_active": self.is_active,
            "check_interval": self.check_interval,
            "started_at": self.started_at.isoformat() + "Z" if self.started_at else None,
            "stopped_at": self.stopped_at.isoformat() + "Z" if self.stopped_at else None
        }
