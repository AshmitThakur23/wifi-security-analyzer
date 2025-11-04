"""
WiFi Security Analyzer Backend
Main Flask application - API ONLY
"""
from flask import Flask, jsonify
from flask_cors import CORS
from models import db, MonitoringScan, SecurityAlert
from config import config
from routes.network_routes import network_bp
from routes.audit_routes import audit_bp
from routes.connection_routes import connection_bp
from routes.monitoring_routes import monitoring_bp
from services.continuous_monitor import get_monitor
import os


def create_app(config_name='default'):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    
    CORS(app)
    db.init_app(app)
    
    app.register_blueprint(network_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(connection_bp)
    app.register_blueprint(monitoring_bp)
    
    @app.route('/health', methods=['GET'])
    def health():
        import datetime
        return jsonify({
            "status": "ok",
            "time": datetime.datetime.utcnow().isoformat() + "Z",
            "version": "2.0.0"
        })
    
    @app.route('/', methods=['GET'])
    def root():
        return jsonify({
            "message": "🛡️ WiFi Security Analyzer API v2.0",
            "features": {
                "1": "Check if your current WiFi is safe",
                "2": "Monitor your WiFi for hackers (24/7)",
                "3": "View history of all networks you've connected to"
            },
            "endpoints": {
                "connection_check": "POST /api/connection/check",
                "connection_status": "GET /api/connection/status",
                "monitoring_start": "POST /api/monitoring/continuous/start",
                "monitoring_stop": "POST /api/monitoring/continuous/stop",
                "monitoring_status": "GET /api/monitoring/continuous/status",
                "monitoring_history": "GET /api/monitoring/continuous/history",
                "monitoring_alerts": "GET /api/monitoring/continuous/alerts"
            }
        })
    
    with app.app_context():
        db.create_all()
        
        # Initialize continuous monitor
        get_monitor(db, {
            "MonitoringScan": MonitoringScan,
            "SecurityAlert": SecurityAlert
        })
    
    return app


if __name__ == "__main__":
    env = os.getenv('FLASK_ENV', 'development')
    app = create_app(env)
    
    print("\n" + "="*60)
    print("🛡️  WiFi Security Analyzer v2.0 - ENHANCED")
    print("="*60)
    print("✅ Feature 1: Check if current WiFi is safe")
    print("✅ Feature 2: Monitor your WiFi for intruders")
    print("🆕 Feature 3: 24/7 Continuous Monitoring (ON/OFF)")
    print("🆕 Feature 4: Historical analysis - See past activity")
    print("🆕 Feature 5: Works on ANY WiFi (home, office, anywhere)")
    print("="*60)
    print(f"🌐 Server: http://{app.config['HOST']}:{app.config['PORT']}")
    print(f"🌐 Frontend: Open frontend/index.html in browser")
    print("="*60 + "\n")
    
    app.run(
        debug=app.config['DEBUG'],
        host=app.config['HOST'],
        port=app.config['PORT']
    )
