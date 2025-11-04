"""Connection Routes - Check current WiFi security"""
from flask import Blueprint, jsonify, request
from auth import require_auth
from services.connection_service import (
    perform_connection_security_check,
    get_current_wifi_info,
    get_available_networks_with_security
)
from models import db, ConnectionCheck
import uuid

connection_bp = Blueprint('connection', __name__, url_prefix='/api/connection')

@connection_bp.route('/check', methods=['POST'])
@require_auth
def check_current_connection():
    """
    Check if your CURRENT WiFi connection is safe
    This is Feature #1: Check WiFi before/while connected
    """
    try:
        # Perform comprehensive security check
        result = perform_connection_security_check()
        
        if not result.get("success"):
            return jsonify(result), 400
        
        # Save to database
        check_record = ConnectionCheck(
            id=str(uuid.uuid4()),
            ssid=result["network"]["ssid"],
            bssid=result["network"]["bssid"],
            is_safe=result["is_safe"],
            risk_score=result["risk_score"],
            checks=result["checks"]
        )
        db.session.add(check_record)
        db.session.commit()
        
        return jsonify(result), 200
    
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Security check failed: {str(e)}"
        }), 500


@connection_bp.route('/status', methods=['GET'])
def get_connection_status():
    """Get current WiFi connection status"""
    try:
        wifi_info = get_current_wifi_info()
        return jsonify(wifi_info), 200
    except Exception as e:
        return jsonify({
            "connected": False,
            "error": str(e)
        }), 500


@connection_bp.route('/available', methods=['GET'])
@require_auth
def list_available_networks():
    """
    Scan and list all available WiFi networks with security analysis
    Shows which networks are safe to connect to
    """
    try:
        networks = get_available_networks_with_security()
        
        return jsonify({
            "success": True,
            "total": len(networks),
            "networks": networks,
            "message": "Scan complete - check 'is_secure' field for each network"
        }), 200
    
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@connection_bp.route('/history', methods=['GET'])
@require_auth
def get_check_history():
    """Get history of connection checks"""
    try:
        limit = request.args.get('limit', 10, type=int)
        checks = ConnectionCheck.query.order_by(
            ConnectionCheck.checked_at.desc()
        ).limit(limit).all()
        
        return jsonify({
            "total": len(checks),
            "checks": [c.to_dict() for c in checks]
        }), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500
