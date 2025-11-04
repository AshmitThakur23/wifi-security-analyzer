"""Monitoring Routes - Monitor your WiFi"""
from flask import Blueprint, jsonify, request
from auth import require_auth
from services.monitoring_service import (
    perform_network_monitoring,
    get_connected_devices,
    get_wifi_security_settings
)
from services.continuous_monitor import get_monitor
from models import db, MonitoredNetwork, SecurityAlert, MonitoringScan
import uuid
import datetime

monitoring_bp = Blueprint('monitoring', __name__, url_prefix='/api/monitoring')


# ============================================
# 24/7 CONTINUOUS MONITORING ENDPOINTS
# ============================================

@monitoring_bp.route('/continuous/start', methods=['POST'])
@require_auth
def start_continuous_monitoring():
    """
    🟢 START 24/7 Monitoring
    Turn ON the monitoring system - it will run continuously
    """
    try:
        data = request.get_json() or {}
        check_interval = data.get('check_interval', 300)  # Default: 5 minutes
        
        monitor = get_monitor(db, {
            "MonitoringScan": MonitoringScan,
            "SecurityAlert": SecurityAlert
        })
        
        result = monitor.start_monitoring(check_interval)
        return jsonify(result), 200
    
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@monitoring_bp.route('/continuous/stop', methods=['POST'])
@require_auth
def stop_continuous_monitoring():
    """
    🔴 STOP 24/7 Monitoring
    Turn OFF the monitoring system
    """
    try:
        monitor = get_monitor()
        
        if not monitor:
            return jsonify({
                "success": False,
                "message": "Monitor not initialized"
            }), 400
        
        result = monitor.stop_monitoring()
        return jsonify(result), 200
    
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@monitoring_bp.route('/continuous/status', methods=['GET'])
@require_auth
def get_continuous_monitoring_status():
    """
    Get current monitoring status (ON/OFF)
    """
    try:
        monitor = get_monitor()
        
        if not monitor:
            return jsonify({
                "is_running": False,
                "status": "not_initialized",
                "message": "Monitoring system not started yet"
            }), 200
        
        status = monitor.get_status()
        return jsonify(status), 200
    
    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500


@monitoring_bp.route('/continuous/history', methods=['GET'])
@require_auth
def get_monitoring_history():
    """
    Get scan history - What happened while you were away?
    Query params:
    - days: number of days (default 7)
    - wifi_ssid: filter by specific network (optional)
    """
    try:
        monitor = get_monitor()
        
        if not monitor:
            return jsonify({
                "success": False,
                "message": "No monitoring data available"
            }), 400
        
        days = request.args.get('days', 7, type=int)
        wifi_ssid = request.args.get('wifi_ssid', None)
        
        history = monitor.get_history(days, wifi_ssid)
        return jsonify(history), 200
    
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@monitoring_bp.route('/continuous/weekly-report', methods=['GET'])
@require_auth
def get_weekly_report():
    """
    Get weekly report for any WiFi network
    Shows: Who connected, suspicious activity, all devices seen
    """
    try:
        monitor = get_monitor()
        
        if not monitor:
            return jsonify({
                "success": False,
                "message": "No monitoring data available"
            }), 400
        
        wifi_ssid = request.args.get('wifi_ssid', None)
        report = monitor.get_weekly_report(wifi_ssid)
        
        return jsonify({
            "success": True,
            "report": report
        }), 200
    
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@monitoring_bp.route('/continuous/alerts', methods=['GET'])
@require_auth
def get_continuous_alerts():
    """
    Get all alerts from continuous monitoring
    Query params:
    - unread_only: true/false (default false)
    """
    try:
        monitor = get_monitor()
        
        if not monitor:
            return jsonify({
                "total": 0,
                "alerts": []
            }), 200
        
        unread_only = request.args.get('unread_only', 'false').lower() == 'true'
        alerts = monitor.get_alerts(unread_only)
        
        return jsonify({
            "total": len(alerts),
            "alerts": alerts
        }), 200
    
    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500


@monitoring_bp.route('/continuous/alerts/<alert_id>/read', methods=['POST'])
@require_auth
def mark_alert_read(alert_id):
    """Mark alert as read"""
    try:
        monitor = get_monitor()
        
        if not monitor:
            return jsonify({
                "success": False,
                "message": "Monitor not found"
            }), 400
        
        success = monitor.mark_alert_read(alert_id)
        
        if success:
            return jsonify({
                "success": True,
                "message": "Alert marked as read"
            }), 200
        else:
            return jsonify({
                "success": False,
                "message": "Alert not found"
            }), 404
    
    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500


@monitoring_bp.route('/continuous/known-devices', methods=['GET'])
@require_auth
def get_known_devices():
    """Get list of known/trusted devices"""
    try:
        monitor = get_monitor()
        
        if not monitor:
            return jsonify({
                "total": 0,
                "devices": []
            }), 200
        
        devices = monitor.get_known_devices()
        
        return jsonify({
            "total": len(devices),
            "devices": devices
        }), 200
    
    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500


@monitoring_bp.route('/continuous/known-devices', methods=['POST'])
@require_auth
def add_known_device():
    """Add a device to trusted/known devices list"""
    try:
        data = request.get_json()
        
        if not data or not data.get('mac_address'):
            return jsonify({
                "error": "mac_address is required"
            }), 400
        
        monitor = get_monitor()
        
        if not monitor:
            return jsonify({
                "success": False,
                "message": "Monitor not initialized"
            }), 400
        
        monitor.add_known_device(data['mac_address'], data)
        
        return jsonify({
            "success": True,
            "message": f"Device {data['mac_address']} added to known devices"
        }), 200
    
    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500


# ============================================
# ONE-TIME SCAN ENDPOINTS (Original)
# ============================================

@monitoring_bp.route('/scan', methods=['POST'])
@require_auth
def scan_network():
    """
    Scan your network for connected devices and threats
    This is Feature #2: Monitor your home WiFi (ONE-TIME SCAN)
    """
    try:
        # Get known devices from database (if any)
        monitored = MonitoredNetwork.query.filter_by(monitoring_enabled=True).all()
        known_devices = []
        
        # Perform network monitoring
        result = perform_network_monitoring(known_devices)
        
        if not result.get("success"):
            return jsonify(result), 400
        
        # Save alerts for suspicious devices
        if result.get("devices", {}).get("suspicious"):
            for device in result["devices"]["suspicious"]:
                # Check if we already have an alert for this device
                existing_alert = SecurityAlert.query.filter_by(
                    network_bssid=device.get("mac_address"),
                    resolved=False
                ).first()
                
                if not existing_alert:
                    alert = SecurityAlert(
                        id=str(uuid.uuid4()),
                        network_bssid=device.get("mac_address"),
                        alert_type="suspicious_device",
                        severity="high" if result["risk_score"] >= 80 else "medium",
                        description=f"Suspicious device detected: {device.get('device_name')}",
                        details=device
                    )
                    db.session.add(alert)
            
            db.session.commit()
        
        return jsonify(result), 200
    
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Network scan failed: {str(e)}"
        }), 500


@monitoring_bp.route('/dashboard', methods=['GET'])
@require_auth
def get_monitoring_dashboard():
    """Get monitoring dashboard with summary"""
    try:
        # Get active alerts
        alerts = SecurityAlert.query.filter_by(resolved=False).all()
        
        # Get monitored networks
        monitored_networks = MonitoredNetwork.query.filter_by(
            monitoring_enabled=True
        ).all()
        
        # Get WiFi settings
        wifi_settings = get_wifi_security_settings()
        
        # Get recent devices
        devices = get_connected_devices()
        
        dashboard = {
            "summary": {
                "total_monitored_networks": len(monitored_networks),
                "active_alerts": len(alerts),
                "devices_online": len(devices),
                "security_status": "warning" if alerts else "good"
            },
            "current_wifi": wifi_settings,
            "recent_alerts": [a.to_dict() for a in alerts[:5]],
            "monitored_networks": [n.to_dict() for n in monitored_networks],
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
        }
        
        return jsonify(dashboard), 200
    
    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500


@monitoring_bp.route('/devices', methods=['GET'])
@require_auth
def list_connected_devices():
    """List all devices currently connected to your network"""
    try:
        devices = get_connected_devices()
        
        return jsonify({
            "success": True,
            "total": len(devices),
            "devices": devices,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
        }), 200
    
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@monitoring_bp.route('/networks', methods=['GET'])
@require_auth
def list_monitored_networks():
    """List networks being monitored"""
    networks = MonitoredNetwork.query.all()
    return jsonify({
        "total": len(networks),
        "networks": [n.to_dict() for n in networks]
    }), 200


@monitoring_bp.route('/networks', methods=['POST'])
@require_auth
def add_monitored_network():
    """Add a network to monitor (your home WiFi)"""
    try:
        data = request.get_json()
        
        if not data or not data.get('ssid'):
            return jsonify({"error": "SSID is required"}), 400
        
        # Check if already exists
        existing = MonitoredNetwork.query.filter_by(
            ssid=data['ssid']
        ).first()
        
        if existing:
            return jsonify({"error": "Network already being monitored"}), 400
        
        network = MonitoredNetwork(
            id=str(uuid.uuid4()),
            ssid=data['ssid'],
            bssid=data.get('bssid', 'unknown'),
            password=data.get('password'),
            is_owned=data.get('is_owned', True),
            monitoring_enabled=True
        )
        
        db.session.add(network)
        db.session.commit()
        
        return jsonify({
            "success": True,
            "message": f"Now monitoring network: {data['ssid']}",
            "network": network.to_dict()
        }), 201
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@monitoring_bp.route('/alerts', methods=['GET'])
@require_auth
def list_alerts():
    """List all security alerts"""
    try:
        show_resolved = request.args.get('resolved', 'false').lower() == 'true'
        
        if show_resolved:
            alerts = SecurityAlert.query.all()
        else:
            alerts = SecurityAlert.query.filter_by(resolved=False).all()
        
        return jsonify({
            "total": len(alerts),
            "alerts": [a.to_dict() for a in alerts]
        }), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@monitoring_bp.route('/alerts/<alert_id>/resolve', methods=['POST'])
@require_auth
def resolve_alert(alert_id):
    """Mark an alert as resolved"""
    try:
        alert = SecurityAlert.query.filter_by(id=alert_id).first()
        
        if not alert:
            return jsonify({"error": "Alert not found"}), 404
        
        alert.resolved = True
        db.session.commit()
        
        return jsonify({
            "success": True,
            "message": "Alert resolved"
        }), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500
