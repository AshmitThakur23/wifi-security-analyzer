from functools import wraps
from flask import request, jsonify
import os

API_TOKEN = os.getenv('API_TOKEN', 'mysecrettoken')

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            return jsonify({"error": "No authorization header"}), 401
        
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return jsonify({"error": "Invalid authorization header format"}), 401
        
        token = parts[1]
        if token != API_TOKEN:
            return jsonify({"error": "Invalid token"}), 403
        
        return f(*args, **kwargs)
    
    return decorated_function
