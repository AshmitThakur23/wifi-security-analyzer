"""Network Routes"""
from flask import Blueprint, jsonify
from models import db, Network
from services.scan_service import real_scan, save_networks_to_db
from auth import require_auth

network_bp = Blueprint('networks', __name__, url_prefix='/api/networks')

@network_bp.route('/scan', methods=['POST'])
@require_auth
def scan_networks():
    try:
        networks_data = real_scan()
        saved = save_networks_to_db(db, Network, networks_data)
        return jsonify({"success": True, "found": len(saved), "networks": saved}), 201
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@network_bp.route('', methods=['GET'])
@require_auth
def list_networks():
    nets = Network.query.all()
    return jsonify([n.to_dict() for n in nets])

@network_bp.route('/<network_id>', methods=['GET'])
@require_auth
def get_network(network_id):
    net = Network.query.filter_by(id=network_id).first()
    if not net:
        return jsonify({"error": "Network not found"}), 404
    return jsonify(net.to_dict())
