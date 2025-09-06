"""
TSP Example - Software Licensing Demo
Copyright (c) 2025 Vladislav Dunaev
Licensed under AGPL-3.0-or-Commercial
"""

"""
Modern TSP Authentication Server
"""

import sys
import json
import base64
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional
from flask import Flask, request, jsonify

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from tsp import TSP
    from source.signature import SignatureHandler
except ImportError as e:
    print(f"ERROR: Failed to import TSP modules: {e}")
    sys.exit(1)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)


class TSPAuthServer:
    """TSP Authentication Server - stateless session management."""

    def __init__(self, server_keys_dir: str = "server_keys"):
        self.server_keys_dir = Path(server_keys_dir)
        self.server_password = b"TSP-Auth-Server-2025-SecurePassword!"
        self._ensure_server_keys()

        self.users_db = {
            "alice": {
                "password": "alice123",
                "user_id": 1001,
                "role": "admin",
                "avatar": "👩‍💼",
            },
            "bob": {
                "password": "bob456",
                "user_id": 1002,
                "role": "user",
                "avatar": "👨‍💻",
            },
            "charlie": {
                "password": "charlie789",
                "user_id": 1003,
                "role": "user",
                "avatar": "👨‍🔬",
            },
            "demo": {
                "password": "demo",
                "user_id": 1004,
                "role": "guest",
                "avatar": "🎭",
            },
        }

        logger.info("TSP Auth Server initialized")

    def _ensure_server_keys(self):
        """Create server keys if they don't exist."""
        self.server_keys_dir.mkdir(exist_ok=True)

        private_key_path = self.server_keys_dir / "private.pem"
        public_key_path = self.server_keys_dir / "public.pem"

        if not private_key_path.exists() or not public_key_path.exists():
            logger.info("Generating server keys...")
            SignatureHandler(
                private_key_path=str(private_key_path),
                public_key_path=str(public_key_path),
                password=self.server_password,
            )
            logger.info("Server keys generated successfully")

    def authenticate_user(self, username: str, password: str) -> Optional[Dict]:
        """Authenticate user credentials."""
        user = self.users_db.get(username)
        if user and user["password"] == password:
            return user
        return None

    def create_session_token(
        self, user_id: int, username: str, duration_hours: int = 24
    ) -> Dict:
        """Create TSP artifact as session token."""
        try:
            logger.info(f"Creating session token for user {username} (ID: {user_id})")

            tsp = TSP(
                private_key_path=str(self.server_keys_dir / "private.pem"),
                public_key_path=str(self.server_keys_dir / "public.pem"),
                key_password=self.server_password,
                model="WEB_AUTH",
                mode="create",
            )

            logger.info("Mining TSP artifact...")
            artifact = tsp.create_artifact()

            now = datetime.utcnow()
            session_metadata = {
                "user_id": user_id,
                "username": username,
                "created_at": now.isoformat(),
                "expires_at": (now + timedelta(hours=duration_hours)).isoformat(),
                "server_public_key": tsp.signature.get_public_bytes().hex(),
                "artifact_info": {
                    "artifact_id": artifact["artifact_id"],
                    "config_hash": artifact["config_hash"],
                    "combined_hash": artifact["combined_hash"],
                    "rarity": artifact["rarity"],
                    "is_personalized": artifact["is_personalized"],
                },
            }

            metadata_bytes = json.dumps(session_metadata, sort_keys=True).encode()
            metadata_signature = tsp.signature.sign(metadata_bytes).hex()

            token_data = {
                "session": session_metadata,
                "signature": metadata_signature,
                "protocol_version": "TSP-1.0.0",
            }

            token_json = json.dumps(token_data, separators=(",", ":"))
            token_b64 = base64.b64encode(token_json.encode()).decode()

            logger.info(f"Session token created successfully for {username}")

            return {
                "success": True,
                "token": token_b64,
                "metadata": session_metadata,
                "artifact": artifact,
            }

        except Exception as e:
            logger.error(f"Failed to create session token: {e}")
            return {"success": False, "error": str(e)}

    def verify_session_token(self, token_b64: str) -> Dict:
        """Verify TSP session token."""
        try:
            token_json = base64.b64decode(token_b64).decode()
            token_data = json.loads(token_json)

            session = token_data.get("session", {})
            signature = token_data.get("signature")
            protocol_version = token_data.get("protocol_version")

            if protocol_version != "TSP-1.0.0":
                return {"valid": False, "error": "Unsupported protocol version"}

            expires_at = datetime.fromisoformat(session.get("expires_at", ""))
            if datetime.utcnow() > expires_at:
                return {"valid": False, "error": "Token expired"}

            server_pubkey = bytes.fromhex(session.get("server_public_key", ""))
            server_signature = SignatureHandler.create_verify_only(server_pubkey)

            metadata_bytes = json.dumps(session, sort_keys=True).encode()
            if not server_signature.verify(metadata_bytes, bytes.fromhex(signature)):
                return {"valid": False, "error": "Invalid metadata signature"}

            artifact_id = session["artifact_info"]["artifact_id"]

            tsp = TSP(
                private_key_path=str(self.server_keys_dir / "private.pem"),
                public_key_path=str(self.server_keys_dir / "public.pem"),
                key_password=self.server_password,
                model="WEB_AUTH",
                mode="verify",
            )

            verification = tsp.verify_artifact(artifact_id, verify_merkle=True)
            print(f"DEBUG verify_all results: {verification}")
            print(f"PoW check result: {verification.get('pow_valid', 'N/A')}")

            # Manual PoW check for diagnostics
            try:
                tsp_session = tsp.restore_artifact(artifact_id)
                manual_pow = tsp_session.protocol._check_pow(
                    tsp_session.protocol.seed, tsp_session.protocol.POW_DIFFICULTY
                )
                print(f"Manual PoW check: {manual_pow}")
            except Exception as e:
                print(f"Manual PoW error: {e}")

            if verification.get("all_valid", False):
                # FIX: Return correct data
                return {
                    "valid": True,
                    "session_data": session,  # Session data for request.user
                    "tsp_session": tsp_session,  # TSPProtocolSession for additional checks
                    "verification": verification,
                }
            else:
                return {
                    "valid": False,
                    "error": "TSP artifact verification failed",
                    "details": verification,
                }

        except Exception as e:
            logger.error(f"Token verification error: {e}")
            return {"valid": False, "error": f"Token verification error: {str(e)}"}


# Initialize server
auth_server = TSPAuthServer()


def require_auth(f):
    """Decorator for authentication verification."""

    def decorated_function(*args, **kwargs):
        token = request.headers.get("Authorization")
        if token and token.startswith("Bearer "):
            token = token[7:]
        else:
            token = request.cookies.get("tsp_session")

        if not token:
            return jsonify({"error": "Missing authentication token"}), 401

        verification = auth_server.verify_session_token(token)

        if not verification.get("valid", False):
            return (
                jsonify(
                    {"error": "Invalid token", "details": verification.get("error")}
                ),
                401,
            )

        request.user = verification["session_data"]
        request.tsp_session = verification["tsp_session"]

        return f(*args, **kwargs)

    decorated_function.__name__ = f.__name__
    return decorated_function


@app.route("/")
def index():
    """Modern homepage with beautiful UI."""
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>TSP Authentication Platform</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }

            :root {
                --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                --secondary-gradient: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
                --success-color: #10b981;
                --error-color: #ef4444;
                --warning-color: #f59e0b;
                --border-radius: 16px;
                --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            }

            body {
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
                background: var(--primary-gradient);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
                position: relative;
                overflow: hidden;
            }

            /* Animated background */
            body::before {
                content: '';
                position: fixed;
                top: -50%;
                left: -50%;
                width: 200%;
                height: 200%;
                background: radial-gradient(circle, rgba(255,255,255,0.1) 1px, transparent 1px);
                background-size: 50px 50px;
                animation: backgroundMove 60s linear infinite;
                z-index: 0;
            }

            @keyframes backgroundMove {
                0% { transform: translate(0, 0); }
                100% { transform: translate(50px, 50px); }
            }

            .app-container {
                background: rgba(255, 255, 255, 0.98);
                backdrop-filter: blur(20px);
                border-radius: 24px;
                box-shadow: 
                    0 20px 40px rgba(0, 0, 0, 0.1),
                    0 0 0 1px rgba(255, 255, 255, 0.5) inset;
                width: 100%;
                max-width: 1200px;
                min-height: 600px;
                display: grid;
                grid-template-columns: 1fr 1fr;
                overflow: hidden;
                position: relative;
                z-index: 1;
                animation: containerEntry 0.6s ease-out;
            }

            @keyframes containerEntry {
                from {
                    opacity: 0;
                    transform: scale(0.95) translateY(20px);
                }
                to {
                    opacity: 1;
                    transform: scale(1) translateY(0);
                }
            }

            .welcome-section {
                background: var(--secondary-gradient);
                color: white;
                padding: 60px 40px;
                display: flex;
                flex-direction: column;
                justify-content: center;
                position: relative;
                overflow: hidden;
            }

            .welcome-section::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: 
                    radial-gradient(circle at 20% 80%, rgba(255,255,255,0.1) 0%, transparent 50%),
                    radial-gradient(circle at 80% 20%, rgba(255,255,255,0.1) 0%, transparent 50%);
                animation: pulse 4s ease-in-out infinite;
            }

            @keyframes pulse {
                0%, 100% { opacity: 0.5; }
                50% { opacity: 1; }
            }

            .welcome-content {
                position: relative;
                z-index: 1;
            }

            .logo {
                font-size: 3rem;
                font-weight: 700;
                margin-bottom: 20px;
                background: linear-gradient(45deg, #ffffff, #a8edea, #fed6e3);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                animation: gradientShift 3s ease infinite;
                filter: drop-shadow(0 2px 4px rgba(0,0,0,0.1));
            }

            @keyframes gradientShift {
                0%, 100% { background-position: 0% 50%; }
                50% { background-position: 100% 50%; }
            }

            .tagline {
                font-size: 1.3rem;
                margin-bottom: 30px;
                opacity: 0.95;
                line-height: 1.6;
                text-shadow: 0 1px 2px rgba(0,0,0,0.1);
            }

            .features {
                list-style: none;
            }

            .features li {
                display: flex;
                align-items: center;
                margin-bottom: 15px;
                font-size: 1rem;
                opacity: 0.9;
                transform: translateX(0);
                transition: var(--transition);
            }

            .features li:hover {
                transform: translateX(5px);
                opacity: 1;
            }

            .features li::before {
                content: '✦';
                margin-right: 12px;
                color: #a8edea;
                font-size: 1.2rem;
                animation: sparkle 2s ease-in-out infinite;
            }

            @keyframes sparkle {
                0%, 100% { opacity: 0.5; transform: scale(1); }
                50% { opacity: 1; transform: scale(1.2); }
            }

            .auth-section {
                padding: 60px 40px;
                display: flex;
                flex-direction: column;
                justify-content: center;
            }

            .auth-header {
                text-align: center;
                margin-bottom: 40px;
                animation: fadeInUp 0.6s ease-out;
            }

            @keyframes fadeInUp {
                from {
                    opacity: 0;
                    transform: translateY(20px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }

            .auth-title {
                font-size: 2rem;
                font-weight: 600;
                color: #1a202c;
                margin-bottom: 8px;
            }

            .auth-subtitle {
                color: #718096;
                font-size: 1rem;
            }

            .login-form {
                display: none;
                animation: fadeIn 0.5s ease-out;
            }

            .login-form.active {
                display: block;
            }

            @keyframes fadeIn {
                from { opacity: 0; }
                to { opacity: 1; }
            }

            .form-group {
                margin-bottom: 24px;
                position: relative;
            }

            .form-label {
                display: block;
                font-weight: 500;
                color: #374151;
                margin-bottom: 8px;
                font-size: 0.9rem;
                transition: var(--transition);
            }

            .form-input {
                width: 100%;
                padding: 16px 20px;
                border: 2px solid #e5e7eb;
                border-radius: 12px;
                font-size: 1rem;
                transition: var(--transition);
                background: #ffffff;
            }

            .form-input:focus {
                outline: none;
                border-color: #3b82f6;
                box-shadow: 
                    0 0 0 4px rgba(59, 130, 246, 0.1),
                    0 4px 6px rgba(0, 0, 0, 0.05);
                transform: translateY(-1px);
            }

            .form-input:hover {
                border-color: #cbd5e0;
            }

            .form-button {
                width: 100%;
                padding: 16px;
                background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%);
                color: white;
                border: none;
                border-radius: 12px;
                font-size: 1rem;
                font-weight: 600;
                cursor: pointer;
                transition: var(--transition);
                position: relative;
                overflow: hidden;
                box-shadow: 0 4px 15px rgba(59, 130, 246, 0.3);
            }

            .form-button::before {
                content: '';
                position: absolute;
                top: 50%;
                left: 50%;
                width: 0;
                height: 0;
                border-radius: 50%;
                background: rgba(255, 255, 255, 0.3);
                transform: translate(-50%, -50%);
                transition: width 0.6s, height 0.6s;
            }

            .form-button:hover::before {
                width: 300px;
                height: 300px;
            }

            .form-button:hover {
                transform: translateY(-2px);
                box-shadow: 
                    0 10px 25px rgba(59, 130, 246, 0.4),
                    0 4px 8px rgba(0, 0, 0, 0.1);
            }

            .form-button:active {
                transform: translateY(0);
            }

            .form-button:disabled {
                opacity: 0.7;
                cursor: not-allowed;
                transform: none;
                box-shadow: none;
            }

            .form-button .loading-spinner {
                display: none;
                width: 20px;
                height: 20px;
                border: 2px solid transparent;
                border-top: 2px solid white;
                border-radius: 50%;
                animation: spin 1s linear infinite;
                margin-right: 8px;
            }

            .form-button.loading .loading-spinner {
                display: inline-block;
            }

            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }

            .demo-users {
                margin-top: 30px;
                padding: 20px;
                background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%);
                border-radius: 12px;
                border: 1px solid #e2e8f0;
                box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
            }

            .demo-title {
                font-weight: 600;
                color: #374151;
                margin-bottom: 15px;
                font-size: 0.9rem;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }

            .user-grid {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 12px;
            }

            .user-card {
                background: white;
                padding: 16px;
                border-radius: 10px;
                border: 2px solid #e5e7eb;
                cursor: pointer;
                transition: var(--transition);
                text-align: center;
                position: relative;
                overflow: hidden;
            }

            .user-card::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%);
                opacity: 0;
                transition: opacity 0.3s;
                z-index: 0;
            }

            .user-card:hover::before {
                opacity: 0.05;
            }

            .user-card:hover {
                border-color: #3b82f6;
                transform: translateY(-2px);
                box-shadow: 0 8px 16px rgba(59, 130, 246, 0.15);
            }

            .user-card > * {
                position: relative;
                z-index: 1;
            }

            .user-avatar {
                font-size: 2rem;
                margin-bottom: 8px;
                filter: drop-shadow(0 2px 4px rgba(0,0,0,0.1));
            }

            .user-name {
                font-weight: 600;
                font-size: 0.9rem;
                color: #374151;
                margin-bottom: 4px;
            }

            .user-role {
                font-size: 0.75rem;
                color: #6b7280;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                padding: 2px 8px;
                background: #f3f4f6;
                border-radius: 4px;
                display: inline-block;
            }

            .status-card {
                margin-top: 20px;
                padding: 20px;
                border-radius: 12px;
                background: #f8fafc;
                border-left: 4px solid #3b82f6;
                display: none;
                position: relative;
                overflow: hidden;
            }

            .status-card::before {
                content: '';
                position: absolute;
                top: 0;
                right: 0;
                width: 100px;
                height: 100px;
                background: radial-gradient(circle, rgba(59, 130, 246, 0.1) 0%, transparent 70%);
                animation: statusPulse 2s ease-in-out infinite;
            }

            @keyframes statusPulse {
                0%, 100% { transform: scale(1); opacity: 0.5; }
                50% { transform: scale(1.2); opacity: 1; }
            }

            .status-card.show {
                display: block;
                animation: slideIn 0.3s ease;
            }

            @keyframes slideIn {
                from { 
                    opacity: 0; 
                    transform: translateY(20px);
                }
                to { 
                    opacity: 1; 
                    transform: translateY(0);
                }
            }

            .status-title {
                font-weight: 600;
                color: #374151;
                margin-bottom: 8px;
                position: relative;
                z-index: 1;
            }

            .status-text {
                color: #6b7280;
                font-size: 0.9rem;
                line-height: 1.5;
                position: relative;
                z-index: 1;
            }

            .success { 
                border-left-color: var(--success-color); 
                background: linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%);
            }
            .success .status-title { color: #065f46; }
            .success .status-text { color: #047857; }

            .error { 
                border-left-color: var(--error-color); 
                background: linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%);
            }
            .error .status-title { color: #991b1b; }
            .error .status-text { color: #dc2626; }

            .dashboard {
                display: none;
                grid-template-columns: 1fr;
                gap: 0;
            }

            .dashboard.active {
                display: grid;
            }

            .dashboard-header {
                background: var(--secondary-gradient);
                color: white;
                padding: 30px 40px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                position: relative;
                overflow: hidden;
            }

            .dashboard-header::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: radial-gradient(circle at 50% 50%, rgba(255,255,255,0.1) 0%, transparent 50%);
                animation: pulse 4s ease-in-out infinite;
            }

            .user-info {
                display: flex;
                align-items: center;
                gap: 15px;
                position: relative;
                z-index: 1;
            }

            .user-avatar-large {
                font-size: 2.5rem;
                filter: drop-shadow(0 2px 4px rgba(0,0,0,0.2));
            }

            .user-details h2 {
                font-size: 1.5rem;
                margin-bottom: 4px;
                text-shadow: 0 1px 2px rgba(0,0,0,0.1);
            }

            .user-details p {
                opacity: 0.9;
                font-size: 0.9rem;
            }

            .logout-button {
                background: rgba(255, 255, 255, 0.2);
                border: 1px solid rgba(255, 255, 255, 0.3);
                color: white;
                padding: 12px 24px;
                border-radius: 8px;
                cursor: pointer;
                transition: var(--transition);
                font-weight: 500;
                backdrop-filter: blur(10px);
                position: relative;
                z-index: 1;
            }

            .logout-button:hover {
                background: rgba(255, 255, 255, 0.3);
                transform: translateY(-1px);
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            }

            .dashboard-content {
                padding: 40px;
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 30px;
            }

            .dashboard-card {
                background: white;
                padding: 24px;
                border-radius: 16px;
                box-shadow: 
                    0 4px 12px rgba(0, 0, 0, 0.05),
                    0 0 0 1px rgba(0, 0, 0, 0.05);
                border: 1px solid #e5e7eb;
                transition: var(--transition);
            }

            .dashboard-card:hover {
                transform: translateY(-2px);
                box-shadow: 
                    0 8px 24px rgba(0, 0, 0, 0.1),
                    0 0 0 1px rgba(59, 130, 246, 0.2);
            }

            .card-title {
                font-weight: 600;
                color: #1f2937;
                margin-bottom: 16px;
                display: flex;
                align-items: center;
                gap: 8px;
                font-size: 1.1rem;
            }

            .card-content {
                color: #6b7280;
                font-size: 0.9rem;
                line-height: 1.8;
            }

            .card-content strong {
                color: #374151;
                font-weight: 600;
            }

            .api-button {
                background: linear-gradient(135deg, #f3f4f6 0%, #e5e7eb 100%);
                border: 1px solid #d1d5db;
                padding: 12px 20px;
                border-radius: 8px;
                cursor: pointer;
                transition: var(--transition);
                margin: 8px 8px 8px 0;
                font-size: 0.85rem;
                font-weight: 500;
                position: relative;
                overflow: hidden;
            }

            .api-button::before {
                content: '';
                position: absolute;
                top: 50%;
                left: 50%;
                width: 0;
                height: 0;
                background: rgba(59, 130, 246, 0.1);
                border-radius: 50%;
                transform: translate(-50%, -50%);
                transition: width 0.3s, height 0.3s;
            }

            .api-button:hover::before {
                width: 100px;
                height: 100px;
            }

            .api-button:hover {
                background: linear-gradient(135deg, #e5e7eb 0%, #d1d5db 100%);
                border-color: #9ca3af;
                transform: translateY(-1px);
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            }

            .response-area {
                background: linear-gradient(135deg, #1f2937 0%, #111827 100%);
                color: #e5e7eb;
                padding: 16px;
                border-radius: 8px;
                font-family: 'SF Mono', Monaco, monospace;
                font-size: 0.8rem;
                margin-top: 16px;
                max-height: 200px;
                overflow-y: auto;
                box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.3);
                border: 1px solid #374151;
            }

            /* Scrollbar styling */
            .response-area::-webkit-scrollbar {
                width: 8px;
            }

            .response-area::-webkit-scrollbar-track {
                background: #374151;
                border-radius: 4px;
            }

            .response-area::-webkit-scrollbar-thumb {
                background: #6b7280;
                border-radius: 4px;
            }

            .response-area::-webkit-scrollbar-thumb:hover {
                background: #9ca3af;
            }

            @media (max-width: 768px) {
                .app-container {
                    grid-template-columns: 1fr;
                    max-width: 500px;
                }

                .welcome-section {
                    padding: 40px 30px;
                    min-height: auto;
                }

                .auth-section {
                    padding: 40px 30px;
                }

                .dashboard-content {
                    grid-template-columns: 1fr;
                    padding: 30px;
                }

                .user-grid {
                    grid-template-columns: 1fr;
                }
            }
        </style>
    </head>
    <body>
        <div class="app-container">
            <!-- Welcome Section -->
            <div class="welcome-section">
                <div class="welcome-content">
                    <div class="logo">🛡️ TSP</div>
                    <div class="tagline">
                        Next-generation authentication powered by cryptographic proof-of-work
                    </div>
                    <ul class="features">
                        <li>Stateless session management</li>
                        <li>Anti-spam PoW protection</li>
                        <li>Cryptographically secure tokens</li>
                        <li>No server-side storage required</li>
                    </ul>
                </div>
            </div>

            <!-- Authentication Section -->
            <div class="auth-section">
                <div class="login-form active" id="login-form">
                    <div class="auth-header">
                        <h1 class="auth-title">Welcome Back</h1>
                        <p class="auth-subtitle">Sign in to your account using TSP authentication</p>
                    </div>

                    <form onsubmit="handleLogin(event)">
                        <div class="form-group">
                            <label class="form-label">Username</label>
                            <input type="text" class="form-input" id="username" required placeholder="Enter your username">
                        </div>

                        <div class="form-group">
                            <label class="form-label">Password</label>
                            <input type="password" class="form-input" id="password" required placeholder="Enter your password">
                        </div>

                        <button type="submit" class="form-button" id="login-button">
                            <span class="loading-spinner"></span>
                            <span class="button-text">Sign In with TSP</span>
                        </button>
                    </form>

                    <div class="demo-users">
                        <div class="demo-title">🎯 Quick Demo Access</div>
                        <div class="user-grid">
                            <div class="user-card" onclick="selectUser('alice', 'alice123')">
                                <div class="user-avatar">👩‍💼</div>
                                <div class="user-name">Alice</div>
                                <div class="user-role">Admin</div>
                            </div>
                            <div class="user-card" onclick="selectUser('bob', 'bob456')">
                                <div class="user-avatar">👨‍💻</div>
                                <div class="user-name">Bob</div>
                                <div class="user-role">User</div>
                            </div>
                            <div class="user-card" onclick="selectUser('charlie', 'charlie789')">
                                <div class="user-avatar">👨‍🔬</div>
                                <div class="user-name">Charlie</div>
                                <div class="user-role">User</div>
                            </div>
                            <div class="user-card" onclick="selectUser('demo', 'demo')">
                                <div class="user-avatar">🎭</div>
                                <div class="user-name">Demo</div>
                                <div class="user-role">Guest</div>
                            </div>
                        </div>
                    </div>

                    <div class="status-card" id="status-card">
                        <div class="status-title" id="status-title">Status</div>
                        <div class="status-text" id="status-text">Ready to authenticate</div>
                    </div>
                </div>

                <!-- Dashboard -->
                <div class="dashboard" id="dashboard">
                    <div class="dashboard-header">
                        <div class="user-info">
                            <div class="user-avatar-large" id="user-avatar">👤</div>
                            <div class="user-details">
                                <h2 id="user-name">User</h2>
                                <p id="user-role">Role</p>
                            </div>
                        </div>
                        <button class="logout-button" onclick="logout()">Sign Out</button>
                    </div>

                    <div class="dashboard-content">
                        <div class="dashboard-card">
                            <div class="card-title">🔐 Session Information</div>
                            <div class="card-content" id="session-info">
                                Loading session data...
                            </div>
                        </div>

                        <div class="dashboard-card">
                            <div class="card-title">🚀 API Testing</div>
                            <div class="card-content">
                                Test protected endpoints with your TSP token:
                                <br><br>
                                <button class="api-button" onclick="testAPI('/api/profile')">Get Profile</button>
                                <button class="api-button" onclick="testAPI('/api/secret')">Secret Data</button>
                                <button class="api-button" onclick="testAPI('/api/stats')">Server Stats</button>
                                <div class="response-area" id="api-response" style="display: none;"></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <script>
            let currentToken = null;
            let currentUser = null;

            function selectUser(username, password) {
                document.getElementById('username').value = username;
                document.getElementById('password').value = password;
                // Add visual feedback
                document.querySelectorAll('.user-card').forEach(card => {
                    card.style.transform = 'scale(1)';
                });
                event.currentTarget.style.transform = 'scale(0.95)';
                setTimeout(() => {
                    event.currentTarget.style.transform = '';
                }, 200);
            }

            function showStatus(title, text, type = 'info') {
                const card = document.getElementById('status-card');
                const titleEl = document.getElementById('status-title');
                const textEl = document.getElementById('status-text');

                titleEl.textContent = title;
                textEl.innerHTML = text;

                card.className = `status-card show ${type}`;
            }

            async function handleLogin(event) {
                event.preventDefault();

                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                const button = document.getElementById('login-button');
                const buttonText = button.querySelector('.button-text');

                if (!username || !password) {
                    showStatus('Error', 'Please fill in all fields', 'error');
                    return;
                }

                // Show loading state
                button.classList.add('loading');
                button.disabled = true;
                buttonText.textContent = 'Creating TSP Token...';

                showStatus('⚡ Authentication', 'Mining cryptographic proof-of-work token...', 'info');

                try {
                    const response = await fetch('/api/login', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({username, password})
                    });

                    const data = await response.json();

                    if (data.success) {
                        currentToken = data.token;
                        currentUser = data.user;

                        showStatus('✅ Success!', 
                            `<strong>TSP token created successfully!</strong><br>
                             <span style="font-size: 0.85rem; opacity: 0.9;">
                             Artifact ID: ${data.artifact.artifact_id}<br>
                             Rarity: ${data.artifact.rarity}<br>
                             Hash: ${data.artifact.config_hash.substring(0, 16)}...<br>
                             </span>
                             <span style="font-size: 0.9rem;">Redirecting to dashboard...</span>`, 'success');

                        setTimeout(() => {
                            showDashboard(data.user, data.artifact);
                        }, 2000);

                    } else {
                        showStatus('❌ Authentication Failed', data.error, 'error');
                    }
                } catch (error) {
                    showStatus('⚠️ Error', `Network error: ${error.message}`, 'error');
                } finally {
                    button.classList.remove('loading');
                    button.disabled = false;
                    buttonText.textContent = 'Sign In with TSP';
                }
            }

            function showDashboard(user, artifact) {
                document.getElementById('login-form').classList.remove('active');
                document.getElementById('dashboard').classList.add('active');

                // Update user info
                const userAvatars = {
                    'alice': '👩‍💼',
                    'bob': '👨‍💻', 
                    'charlie': '👨‍🔬',
                    'demo': '🎭'
                };

                document.getElementById('user-avatar').textContent = userAvatars[user.username] || '👤';
                document.getElementById('user-name').textContent = user.username.charAt(0).toUpperCase() + user.username.slice(1);
                document.getElementById('user-role').textContent = user.role.charAt(0).toUpperCase() + user.role.slice(1);

                // Update session info with better formatting
                const createdAt = new Date().toLocaleString();
                document.getElementById('session-info').innerHTML = `
                    <strong>User ID:</strong> ${user.user_id}<br>
                    <strong>Username:</strong> ${user.username}<br>
                    <strong>Role:</strong> <span style="display: inline-block; padding: 2px 8px; background: #f3f4f6; border-radius: 4px; font-size: 0.85rem;">${user.role.toUpperCase()}</span><br>
                    <strong>Artifact ID:</strong> ${artifact.artifact_id}<br>
                    <strong>Config Hash:</strong> <code style="background: #f3f4f6; padding: 2px 4px; border-radius: 3px; font-size: 0.85rem;">${artifact.config_hash.substring(0, 20)}...</code><br>
                    <strong>Rarity:</strong> <span style="color: #3b82f6; font-weight: 600;">${artifact.rarity}</span><br>
                    <strong>Session Created:</strong> ${createdAt}
                `;
            }

            async function testAPI(endpoint) {
                if (!currentToken) {
                    showAPIResponse('Error: No authentication token');
                    return;
                }

                showAPIResponse('⏳ Loading...');

                try {
                    const response = await fetch(endpoint, {
                        headers: {'Authorization': `Bearer ${currentToken}`}
                    });

                    const data = await response.json();
                    showAPIResponse(JSON.stringify(data, null, 2));
                } catch (error) {
                    showAPIResponse(`❌ Error: ${error.message}`);
                }
            }

            function showAPIResponse(content) {
                const responseArea = document.getElementById('api-response');
                responseArea.textContent = content;
                responseArea.style.display = 'block';
                // Smooth scroll to response
                responseArea.scrollTop = 0;
            }

            function logout() {
                currentToken = null;
                currentUser = null;

                document.getElementById('dashboard').classList.remove('active');
                document.getElementById('login-form').classList.add('active');

                // Clear form
                document.getElementById('username').value = '';
                document.getElementById('password').value = '';

                showStatus('👋 Signed Out', 'You have been successfully signed out', 'info');
            }

            // Add keyboard shortcut for quick demo login
            document.addEventListener('keydown', (e) => {
                if (e.ctrlKey && e.key === 'd') {
                    selectUser('demo', 'demo');
                    document.getElementById('login-button').click();
                }
            });
        </script>
    </body>
    </html>
    """


@app.route("/api/login", methods=["POST"])
def api_login():
    """API endpoint for login."""
    try:
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return (
                jsonify({"success": False, "error": "Username and password required"}),
                400,
            )

        user = auth_server.authenticate_user(username, password)
        if not user:
            return jsonify({"success": False, "error": "Invalid credentials"}), 401

        token_result = auth_server.create_session_token(
            user_id=user["user_id"], username=username, duration_hours=24
        )

        if token_result["success"]:
            response_data = {
                "success": True,
                "token": token_result["token"],
                "user": {
                    "user_id": user["user_id"],
                    "username": username,
                    "role": user["role"],
                    "avatar": user["avatar"],
                },
                "artifact": token_result["artifact"],
                "expires_at": token_result["metadata"]["expires_at"],
            }
            return jsonify(response_data)
        else:
            return jsonify({"success": False, "error": token_result["error"]}), 500

    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({"success": False, "error": "Internal server error"}), 500


@app.route("/api/profile")
@require_auth
def api_profile():
    """Protected endpoint - user profile."""
    return jsonify(
        {
            "user_id": request.user["user_id"],
            "username": request.user["username"],
            "created_at": request.user["created_at"],
            "expires_at": request.user["expires_at"],
            "artifact_info": request.user["artifact_info"],
            "session_age_minutes": int(
                (
                    datetime.utcnow()
                    - datetime.fromisoformat(request.user["created_at"])
                ).total_seconds()
                / 60
            ),
        }
    )


@app.route("/api/secret")
@require_auth
def api_secret():
    """Protected endpoint - secret data."""
    return jsonify(
        {
            "message": "This is highly classified information!",
            "user": request.user["username"],
            "server_time": datetime.utcnow().isoformat(),
            "access_level": "authenticated",
            "classified_data": {
                "security_clearance": "TOP SECRET",
                "access_code": "TSP-SECURE-2025",
                "account_balance": 2500000,
                "crypto_keys": ["rsa-4096", "ed25519", "secp256k1"],
                "permissions": ["read", "write", "admin", "deploy"],
            },
            "session_metadata": {
                "artifact_id": request.user["artifact_info"]["artifact_id"],
                "rarity": request.user["artifact_info"]["rarity"],
                "is_personalized": request.user["artifact_info"]["is_personalized"],
            },
        }
    )


@app.route("/api/stats")
def api_stats():
    """Public server statistics."""
    return jsonify(
        {
            "server": "Modern TSP Authentication Platform",
            "protocol_version": "TSP-1.0.0",
            "model": "WEB_AUTH",
            "registered_users": len(auth_server.users_db),
            "server_time": datetime.utcnow().isoformat(),
            "features": [
                "Stateless Authentication",
                "Proof-of-Work Security",
                "Cryptographic Verification",
                "Anti-Spam Protection",
            ],
            "demo_accounts": [
                {"username": "alice", "role": "admin"},
                {"username": "bob", "role": "user"},
                {"username": "charlie", "role": "user"},
                {"username": "demo", "role": "guest"},
            ],
        }
    )


if __name__ == "__main__":
    logger.info("Starting Modern TSP Authentication Server...")
    logger.info(
        "Demo accounts: alice/alice123, bob/bob456, charlie/charlie789, demo/demo"
    )
    logger.info("Navigate to http://localhost:5000 for modern interface")

    app.run(debug=True, host="0.0.0.0", port=5000)
