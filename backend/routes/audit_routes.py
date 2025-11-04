"""Audit Routes"""
from flask import Blueprint, jsonify
import datetime
import uuid
from models import db, Network, Audit
from services.scan_service import perform_security_audit
from auth import require_auth

audit_bp = Blueprint('audits', __name__, url_prefix='/api/audits')

@audit_bp.route('/start/<bssid>', methods=['POST'])
@require_auth
def start_audit(bssid):
    net = Network.query.filter_by(bssid=bssid).first()
    if not net:
        return jsonify({"error": "Network not found"}), 404
    result = perform_security_audit(net)
    audit = Audit(id=str(uuid.uuid4()), network_bssid=bssid,
                 started_at=datetime.datetime.utcnow(), result=result)
    db.session.add(audit)
    db.session.commit()
    return jsonify({"audit_id": audit.id, "result": result}), 201

@audit_bp.route('', methods=['GET'])
@require_auth
def list_audits():
    audits = Audit.query.all()
    return jsonify([a.to_dict() for a in audits])

@audit_bp.route('/<audit_id>', methods=['GET'])
@require_auth
def get_audit(audit_id):
    a = Audit.query.filter_by(id=audit_id).first()
    if not a:
        return jsonify({"error": "Audit not found"}), 404
    return jsonify(a.to_dict())
