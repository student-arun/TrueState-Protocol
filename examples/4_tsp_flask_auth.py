"""
TSP Example - Stateless Web Authentication Server
Copyright (c) 2025 Vladislav Dunaev
Licensed under AGPL-3.0-or-Commercial
"""

"""
TSP Stateless Authentication Server
===================================

Pure stateless authentication using embedded TSP artifacts:
- No server-side session storage
- No commits.json database
- Self-contained tokens with embedded verification data
- Instant token verification without external dependencies
- Perfect for microservices and scalable web applications
"""

import sys
import json
import base64
import logging
import time
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


class TSPStatelessAuthServer:
    """TSP Stateless Authentication Server - zero server-side storage."""

    def __init__(self, server_keys_dir: str = "server_keys"):
        self.server_keys_dir = Path(server_keys_dir)
        self.server_password = b"TSP-Stateless-Auth-Server-2025!"
        self._ensure_server_keys()

        # Demo user database (in production, use external auth provider)
        self.users_db = {
            "alice": {
                "password": "alice123",
                "user_id": 1001,
                "role": "admin",
                "avatar": "👩‍💼",
                "full_name": "Alice Johnson",
                "department": "Engineering",
            },
            "bob": {
                "password": "bob456",
                "user_id": 1002,
                "role": "user",
                "avatar": "👨‍💻",
                "full_name": "Bob Smith",
                "department": "Product",
            },
            "charlie": {
                "password": "charlie789",
                "user_id": 1003,
                "role": "user",
                "avatar": "👨‍🔬",
                "full_name": "Charlie Wilson",
                "department": "Research",
            },
            "demo": {
                "password": "demo",
                "user_id": 1004,
                "role": "guest",
                "avatar": "🎭",
                "full_name": "Demo User",
                "department": "Testing",
            },
        }

        logger.info("TSP Stateless Auth Server initialized - zero storage mode")

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
        """Authenticate user credentials against user database."""
        user = self.users_db.get(username)
        if user and user["password"] == password:
            return user
        return None

    def create_stateless_token(
        self, user_id: int, username: str, duration_hours: int = 24
    ) -> Dict:
        """Create stateless TSP token with embedded artifact data."""
        try:
            logger.info(f"Creating stateless token for {username} (ID: {user_id})")

            # Create TSP instance for stateless mode
            tsp = TSP(
                private_key_path=str(self.server_keys_dir / "private.pem"),
                public_key_path=str(self.server_keys_dir / "public.pem"),
                key_password=self.server_password,
                model="WEB_AUTH",  # Fast generation for web tokens
                mode="create",
            )

            logger.info("Mining stateless TSP artifact...")
            start_time = time.time()

            # Create artifact in stateless mode (persist=False)
            artifact_result = tsp.create_artifact(persist=False)
            mining_time = time.time() - start_time

            logger.info(f"Artifact generated in {mining_time:.2f}s (stateless mode)")

            # Create session metadata
            now = datetime.utcnow()
            session_metadata = {
                "user_id": user_id,
                "username": username,
                "created_at": now.isoformat(),
                "expires_at": (now + timedelta(hours=duration_hours)).isoformat(),
                "server_public_key": tsp.signature.get_public_bytes().hex(),
                "mining_time": round(mining_time, 3),
                "token_type": "stateless",
                "artifact_summary": {
                    "config_hash": artifact_result["config_hash"],
                    "rarity": artifact_result["rarity"],
                    "creation_timestamp": artifact_result["creation_timestamp"],
                    "mode": artifact_result["mode"],
                },
            }

            # Sign session metadata
            metadata_bytes = json.dumps(session_metadata, sort_keys=True).encode()
            metadata_signature = tsp.signature.sign(metadata_bytes).hex()

            # Create complete stateless token
            stateless_token = {
                "session": session_metadata,
                "signature": metadata_signature,
                "tsp_artifact": artifact_result["artifact_data"],  # Embedded TSP data
                "protocol_version": "TSP-Stateless-1.0",
            }

            # Base64 encode for HTTP transport
            token_json = json.dumps(stateless_token, separators=(",", ":"))
            token_b64 = base64.b64encode(token_json.encode()).decode()

            logger.info(f"Stateless token created: {len(token_json)} bytes")

            return {
                "success": True,
                "token": token_b64,
                "metadata": session_metadata,
                "artifact_summary": artifact_result,
                "token_size": len(token_json),
                "mining_time": mining_time,
            }

        except Exception as e:
            logger.error(f"Failed to create stateless token: {e}")
            return {"success": False, "error": str(e)}

    def verify_stateless_token(self, token_b64: str) -> Dict:
        """Verify stateless TSP token using embedded artifact data."""
        try:
            # Decode token
            token_json = base64.b64decode(token_b64).decode()
            token_data = json.loads(token_json)

            session = token_data.get("session", {})
            signature = token_data.get("signature")
            tsp_artifact = token_data.get("tsp_artifact")
            protocol_version = token_data.get("protocol_version")

            # Validate protocol version
            if protocol_version != "TSP-Stateless-1.0":
                return {"valid": False, "error": "Unsupported protocol version"}

            # Check expiration
            expires_at = datetime.fromisoformat(session.get("expires_at", ""))
            if datetime.utcnow() > expires_at:
                return {"valid": False, "error": "Token expired"}

            # Verify metadata signature
            server_pubkey = bytes.fromhex(session.get("server_public_key", ""))
            server_signature = SignatureHandler.create_verify_only(server_pubkey)

            metadata_bytes = json.dumps(session, sort_keys=True).encode()
            if not server_signature.verify(metadata_bytes, bytes.fromhex(signature)):
                return {"valid": False, "error": "Invalid metadata signature"}

            # Verify embedded TSP artifact (stateless verification)
            logger.info("Verifying embedded TSP artifact...")

            tsp = TSP(
                private_key_path=str(self.server_keys_dir / "private.pem"),
                public_key_path=str(self.server_keys_dir / "public.pem"),
                key_password=self.server_password,
                model="WEB_AUTH",
                mode="verify",
            )

            # Use stateless verification with embedded data
            verification = tsp.verify_artifact(tsp_artifact)

            logger.info(f"Stateless verification result: {verification.get('all_valid', False)}")

            if verification.get("all_valid", False):
                return {
                    "valid": True,
                    "session_data": session,
                    "artifact_verification": verification,
                    "token_type": "stateless",
                    "verification_mode": verification.get("verification_mode", "unknown"),
                }
            else:
                return {
                    "valid": False,
                    "error": "TSP artifact verification failed",
                    "details": verification,
                }

        except Exception as e:
            logger.error(f"Stateless token verification error: {e}")
            return {"valid": False, "error": f"Token verification error: {str(e)}"}


# Initialize stateless auth server
auth_server = TSPStatelessAuthServer()


def require_stateless_auth(f):
    """Decorator for stateless authentication verification."""

    def decorated_function(*args, **kwargs):
        # Get token from Authorization header or cookie
        token = request.headers.get("Authorization")
        if token and token.startswith("Bearer "):
            token = token[7:]
        else:
            token = request.cookies.get("tsp_session")

        if not token:
            return jsonify({"error": "Missing authentication token"}), 401

        # Verify stateless token
        verification = auth_server.verify_stateless_token(token)

        if not verification.get("valid", False):
            return (
                jsonify(
                    {
                        "error": "Invalid stateless token",
                        "details": verification.get("error"),
                        "token_type": "stateless",
                    }
                ),
                401,
            )

        # Attach session data to request
        request.user = verification["session_data"]
        request.artifact_verification = verification["artifact_verification"]
        request.token_type = "stateless"

        return f(*args, **kwargs)

    decorated_function.__name__ = f.__name__
    return decorated_function


@app.route("/")
def index():
    """Modern stateless authentication interface."""
    return """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>TSP Stateless Authentication</title>
                <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
                <style>
                    * {
                        margin: 0;
                        padding: 0;
                        box-sizing: border-box;
                    }
            
                    body {
                        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        min-height: 100vh;
                        padding: 20px;
                    }
            
                    .container {
                        max-width: 1000px;
                        margin: 0 auto;
                        background: white;
                        border-radius: 20px;
                        box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
                        overflow: hidden;
                        min-height: 600px;
                    }
            
                    /* Header */
                    .header {
                        background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
                        color: white;
                        padding: 40px;
                        text-align: center;
                    }
            
                    .logo {
                        font-size: 2.5rem;
                        font-weight: 700;
                        margin-bottom: 10px;
                    }
            
                    .tagline {
                        font-size: 1.1rem;
                        opacity: 0.9;
                        margin-bottom: 20px;
                    }
            
                    .features {
                        display: flex;
                        justify-content: center;
                        flex-wrap: wrap;
                        gap: 20px;
                        font-size: 0.9rem;
                    }
            
                    .feature {
                        background: rgba(255, 255, 255, 0.15);
                        padding: 8px 16px;
                        border-radius: 20px;
                        backdrop-filter: blur(10px);
                    }
            
                    /* Main Content */
                    .main-content {
                        display: flex;
                        min-height: 500px;
                    }
            
                    /* Login Section */
                    .login-section {
                        flex: 1;
                        padding: 40px;
                        display: flex;
                        flex-direction: column;
                        justify-content: center;
                    }
            
                    .login-section.hidden {
                        display: none;
                    }
            
                    .auth-header {
                        text-align: center;
                        margin-bottom: 30px;
                    }
            
                    .auth-title {
                        font-size: 1.8rem;
                        font-weight: 600;
                        color: #1a202c;
                        margin-bottom: 8px;
                    }
            
                    .stateless-badge {
                        display: inline-block;
                        background: linear-gradient(135deg, #10b981 0%, #059669 100%);
                        color: white;
                        padding: 4px 12px;
                        border-radius: 6px;
                        font-size: 0.7rem;
                        font-weight: 600;
                        text-transform: uppercase;
                        letter-spacing: 0.5px;
                        margin-left: 8px;
                    }
            
                    .auth-subtitle {
                        color: #718096;
                        font-size: 0.9rem;
                    }
            
                    /* Form Styles */
                    .form-group {
                        margin-bottom: 20px;
                    }
            
                    .form-label {
                        display: block;
                        font-weight: 500;
                        color: #374151;
                        margin-bottom: 6px;
                        font-size: 0.9rem;
                    }
            
                    .form-input {
                        width: 100%;
                        padding: 14px 16px;
                        border: 2px solid #e5e7eb;
                        border-radius: 10px;
                        font-size: 1rem;
                        transition: all 0.2s ease;
                        background: #ffffff;
                    }
            
                    .form-input:focus {
                        outline: none;
                        border-color: #3b82f6;
                        box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
                    }
            
                    .form-button {
                        width: 100%;
                        padding: 14px;
                        background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%);
                        color: white;
                        border: none;
                        border-radius: 10px;
                        font-size: 1rem;
                        font-weight: 600;
                        cursor: pointer;
                        transition: all 0.2s ease;
                        box-shadow: 0 4px 15px rgba(59, 130, 246, 0.3);
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        gap: 8px;
                    }
            
                    .form-button:hover {
                        transform: translateY(-2px);
                        box-shadow: 0 8px 20px rgba(59, 130, 246, 0.4);
                    }
            
                    .form-button:disabled {
                        opacity: 0.7;
                        cursor: not-allowed;
                        transform: none;
                    }
            
                    .loading-spinner {
                        display: none;
                        width: 18px;
                        height: 18px;
                        border: 2px solid transparent;
                        border-top: 2px solid white;
                        border-radius: 50%;
                        animation: spin 1s linear infinite;
                    }
            
                    .form-button.loading .loading-spinner {
                        display: block;
                    }
            
                    @keyframes spin {
                        0% { transform: rotate(0deg); }
                        100% { transform: rotate(360deg); }
                    }
            
                    /* Demo Users */
                    .demo-section {
                        background: #f8fafc;
                        border: 1px solid #e2e8f0;
                        border-radius: 12px;
                        padding: 20px;
                        margin-top: 25px;
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
                        gap: 10px;
                    }
            
                    .user-card {
                        background: white;
                        padding: 15px;
                        border-radius: 8px;
                        border: 2px solid #e5e7eb;
                        cursor: pointer;
                        transition: all 0.2s ease;
                        text-align: center;
                    }
            
                    .user-card:hover {
                        border-color: #3b82f6;
                        transform: translateY(-1px);
                        box-shadow: 0 4px 12px rgba(59, 130, 246, 0.15);
                    }
            
                    .user-avatar {
                        font-size: 1.8rem;
                        margin-bottom: 6px;
                    }
            
                    .user-name {
                        font-weight: 600;
                        font-size: 0.85rem;
                        color: #374151;
                        margin-bottom: 2px;
                    }
            
                    .user-role {
                        font-size: 0.7rem;
                        color: #6b7280;
                        text-transform: uppercase;
                        letter-spacing: 0.5px;
                        padding: 2px 6px;
                        background: #f3f4f6;
                        border-radius: 4px;
                        display: inline-block;
                    }
            
                    /* Status Card */
                    .status-card {
                        margin-top: 20px;
                        padding: 16px;
                        border-radius: 10px;
                        background: #f8fafc;
                        border-left: 4px solid #3b82f6;
                        display: none;
                    }
            
                    .status-card.show {
                        display: block;
                        animation: slideIn 0.3s ease;
                    }
            
                    @keyframes slideIn {
                        from { opacity: 0; transform: translateY(10px); }
                        to { opacity: 1; transform: translateY(0); }
                    }
            
                    .status-title {
                        font-weight: 600;
                        color: #374151;
                        margin-bottom: 6px;
                        font-size: 0.9rem;
                    }
            
                    .status-text {
                        color: #6b7280;
                        font-size: 0.85rem;
                        line-height: 1.4;
                    }
            
                    .status-card.success {
                        border-left-color: #10b981;
                        background: #f0fdf4;
                    }
                    .status-card.success .status-title { color: #065f46; }
                    .status-card.success .status-text { color: #047857; }
            
                    .status-card.error {
                        border-left-color: #ef4444;
                        background: #fef2f2;
                    }
                    .status-card.error .status-title { color: #991b1b; }
                    .status-card.error .status-text { color: #dc2626; }
            
                    /* Dashboard */
                    .dashboard {
                        display: none;
                        width: 100%;
                    }
            
                    .dashboard.active {
                        display: block;
                    }
            
                    .dashboard-header {
                        background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
                        color: white;
                        padding: 25px 40px;
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                    }
            
                    .user-info {
                        display: flex;
                        align-items: center;
                        gap: 15px;
                    }
            
                    .user-avatar-large {
                        font-size: 2.2rem;
                    }
            
                    .user-details h2 {
                        font-size: 1.4rem;
                        margin-bottom: 4px;
                    }
            
                    .user-details p {
                        opacity: 0.9;
                        font-size: 0.85rem;
                    }
            
                    .logout-button {
                        background: rgba(255, 255, 255, 0.2);
                        border: 1px solid rgba(255, 255, 255, 0.3);
                        color: white;
                        padding: 10px 20px;
                        border-radius: 6px;
                        cursor: pointer;
                        transition: all 0.2s ease;
                        font-weight: 500;
                        backdrop-filter: blur(10px);
                    }
            
                    .logout-button:hover {
                        background: rgba(255, 255, 255, 0.3);
                        transform: translateY(-1px);
                    }
            
                    .dashboard-content {
                        padding: 30px;
                        display: grid;
                        grid-template-columns: 1fr 1fr;
                        gap: 25px;
                    }
            
                    .dashboard-card {
                        background: white;
                        padding: 25px;
                        border-radius: 12px;
                        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.08);
                        border: 1px solid #e5e7eb;
                        transition: all 0.2s ease;
                    }
            
                    .dashboard-card:hover {
                        transform: translateY(-2px);
                        box-shadow: 0 8px 20px rgba(0, 0, 0, 0.12);
                    }
            
                    .card-title {
                        font-weight: 600;
                        color: #1f2937;
                        margin-bottom: 15px;
                        display: flex;
                        align-items: center;
                        gap: 8px;
                        font-size: 1rem;
                    }
            
                    .card-content {
                        color: #6b7280;
                        font-size: 0.85rem;
                        line-height: 1.6;
                    }
            
                    .card-content strong {
                        color: #374151;
                        font-weight: 600;
                    }
            
                    .api-button {
                        background: #f3f4f6;
                        border: 1px solid #d1d5db;
                        padding: 10px 16px;
                        border-radius: 6px;
                        cursor: pointer;
                        transition: all 0.2s ease;
                        margin: 6px 6px 6px 0;
                        font-size: 0.8rem;
                        font-weight: 500;
                    }
            
                    .api-button:hover {
                        background: #e5e7eb;
                        border-color: #9ca3af;
                        transform: translateY(-1px);
                    }
            
                    .response-area {
                        background: #1f2937;
                        color: #e5e7eb;
                        padding: 15px;
                        border-radius: 6px;
                        font-family: 'SF Mono', Monaco, monospace;
                        font-size: 0.75rem;
                        margin-top: 15px;
                        max-height: 180px;
                        overflow-y: auto;
                        border: 1px solid #374151;
                    }
            
                    /* Responsive */
                    @media (max-width: 768px) {
                        .container {
                            margin: 10px;
                            border-radius: 15px;
                        }
            
                        .main-content {
                            flex-direction: column;
                        }
            
                        .header {
                            padding: 30px 20px;
                        }
            
                        .features {
                            flex-direction: column;
                            align-items: center;
                        }
            
                        .login-section {
                            padding: 30px 20px;
                        }
            
                        .user-grid {
                            grid-template-columns: 1fr;
                        }
            
                        .dashboard-content {
                            grid-template-columns: 1fr;
                            padding: 20px;
                        }
            
                        .dashboard-header {
                            padding: 20px;
                            flex-direction: column;
                            gap: 15px;
                        }
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <!-- Header -->
                    <div class="header">
                        <div class="logo">⚡ TSP Stateless</div>
                        <div class="tagline">Zero-storage authentication with embedded cryptographic proof-of-work</div>
                        <div class="features">
                            <div class="feature">No Server Storage</div>
                            <div class="feature">Embedded Verification</div>
                            <div class="feature">Infinite Scaling</div>
                            <div class="feature">Microservices Ready</div>
                        </div>
                    </div>
            
                    <!-- Main Content -->
                    <div class="main-content">
                        <!-- Login Section -->
                        <div class="login-section" id="login-form">
                            <div class="auth-header">
                                <h1 class="auth-title">Stateless Login <span class="stateless-badge">Zero Storage</span></h1>
                                <p class="auth-subtitle">Authenticate with self-contained TSP tokens</p>
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
                                    <span class="button-text">Create Stateless Token</span>
                                </button>
                            </form>
            
                            <div class="demo-section">
                                <div class="demo-title">⚡ Quick Demo Access</div>
                                <div class="user-grid">
                                    <div class="user-card" onclick="selectUser('alice', 'alice123', this)">
                                        <div class="user-avatar">👩‍💼</div>
                                        <div class="user-name">Alice</div>
                                        <div class="user-role">Admin</div>
                                    </div>
                                    <div class="user-card" onclick="selectUser('bob', 'bob456', this)">
                                        <div class="user-avatar">👨‍💻</div>
                                        <div class="user-name">Bob</div>
                                        <div class="user-role">User</div>
                                    </div>
                                    <div class="user-card" onclick="selectUser('charlie', 'charlie789', this)">
                                        <div class="user-avatar">👨‍🔬</div>
                                        <div class="user-name">Charlie</div>
                                        <div class="user-role">User</div>
                                    </div>
                                    <div class="user-card" onclick="selectUser('demo', 'demo', this)">
                                        <div class="user-avatar">🎭</div>
                                        <div class="user-name">Demo</div>
                                        <div class="user-role">Guest</div>
                                    </div>
                                </div>
                            </div>
            
                            <div class="status-card" id="status-card">
                                <div class="status-title" id="status-title">Status</div>
                                <div class="status-text" id="status-text">Ready for stateless authentication</div>
                            </div>
                        </div>
            
                        <!-- Dashboard -->
                        <div class="dashboard" id="dashboard">
                            <div class="dashboard-header">
                                <div class="user-info">
                                    <div class="user-avatar-large" id="user-avatar">👤</div>
                                    <div class="user-details">
                                        <h2 id="user-name">User</h2>
                                        <p id="user-role">Stateless Session Active</p>
                                    </div>
                                </div>
                                <button class="logout-button" onclick="logout()">Sign Out</button>
                            </div>
            
                            <div class="dashboard-content">
                                <div class="dashboard-card">
                                    <div class="card-title">⚡ Stateless Session Info</div>
                                    <div class="card-content" id="session-info">
                                        Loading stateless session data...
                                    </div>
                                </div>
            
                                <div class="dashboard-card">
                                    <div class="card-title">🚀 API Testing</div>
                                    <div class="card-content">
                                        Test endpoints with your stateless token:
                                        <br><br>
                                        <button class="api-button" onclick="testAPI('/api/profile')">Get Profile</button>
                                        <button class="api-button" onclick="testAPI('/api/secret')">Secret Data</button>
                                        <button class="api-button" onclick="testAPI('/api/stats')">Server Stats</button>
                                        <button class="api-button" onclick="testAPI('/api/token-info')">Token Info</button>
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
            
                    function selectUser(username, password, element) {
                        document.getElementById('username').value = username;
                        document.getElementById('password').value = password;
                        element.style.transform = 'scale(0.95)';
                        setTimeout(() => {
                            element.style.transform = '';
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
            
                        button.classList.add('loading');
                        button.disabled = true;
                        buttonText.textContent = 'Mining Stateless Token...';
            
                        showStatus('⚡ Stateless Auth', 'Creating self-contained token with embedded TSP artifact...', 'info');
            
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
            
                                showStatus('✅ Stateless Success!', 
                                    `<strong>Self-contained token created!</strong><br>
                                     <span style="font-size: 0.8rem; opacity: 0.9;">
                                     Mining time: ${data.mining_time.toFixed(3)}s<br>
                                     Token size: ${data.token_size} bytes<br>
                                     Config hash: ${data.artifact_summary.config_hash.substring(0, 16)}...<br>
                                     Rarity: ${data.artifact_summary.rarity}<br>
                                     </span>
                                     <span style="font-size: 0.85rem;">No server storage used!</span>`, 'success');
            
                                setTimeout(() => {
                                    showDashboard(data.user, data.artifact_summary, data.metadata);
                                }, 2000);
            
                            } else {
                                showStatus('❌ Authentication Failed', data.error, 'error');
                            }
                        } catch (error) {
                            showStatus('⚠️ Error', `Network error: ${error.message}`, 'error');
                        } finally {
                            button.classList.remove('loading');
                            button.disabled = false;
                            buttonText.textContent = 'Create Stateless Token';
                        }
                    }
            
                    function showDashboard(user, artifact, metadata) {
                        document.getElementById('login-form').classList.add('hidden');
                        document.getElementById('dashboard').classList.add('active');
            
                        const userAvatars = {
                            'alice': '👩‍💼',
                            'bob': '👨‍💻', 
                            'charlie': '👨‍🔬',
                            'demo': '🎭'
                        };
            
                        document.getElementById('user-avatar').textContent = userAvatars[user.username] || '👤';
                        document.getElementById('user-name').textContent = user.username.charAt(0).toUpperCase() + user.username.slice(1);
                        document.getElementById('user-role').textContent = `${user.role.charAt(0).toUpperCase() + user.role.slice(1)} • Stateless Session`;
            
                        const createdAt = new Date().toLocaleString();
                        document.getElementById('session-info').innerHTML = `
                            <strong>Token Type:</strong> <span style="color: #10b981; font-weight: 600;">Stateless</span><br>
                            <strong>User ID:</strong> ${user.user_id}<br>
                            <strong>Username:</strong> ${user.username}<br>
                            <strong>Department:</strong> ${user.department}<br>
                            <strong>Config Hash:</strong> <code style="background: #f3f4f6; padding: 2px 4px; border-radius: 3px; font-size: 0.8rem;">${artifact.config_hash.substring(0, 20)}...</code><br>
                            <strong>Mining Time:</strong> <span style="color: #3b82f6; font-weight: 600;">${metadata.mining_time}s</span><br>
                            <strong>Rarity:</strong> <span style="color: #3b82f6; font-weight: 600;">${artifact.rarity}</span><br>
                            <strong>Session Created:</strong> ${createdAt}<br>
                            <strong>Storage Used:</strong> <span style="color: #10b981; font-weight: 600;">0 bytes (stateless)</span>
                        `;
                    }
            
                    async function testAPI(endpoint) {
                        if (!currentToken) {
                            showAPIResponse('Error: No authentication token');
                            return;
                        }
            
                        showAPIResponse('⏳ Testing stateless verification...');
            
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
                        responseArea.scrollTop = 0;
                    }
            
                    function logout() {
                        currentToken = null;
                        currentUser = null;
            
                        document.getElementById('dashboard').classList.remove('active');
                        document.getElementById('login-form').classList.remove('hidden');
            
                        document.getElementById('username').value = '';
                        document.getElementById('password').value = '';
            
                        showStatus('👋 Signed Out', 'Stateless session ended (no cleanup required)', 'info');
                    }
            
                    // Keyboard shortcut for demo
                    document.addEventListener('keydown', (e) => {
                        if (e.ctrlKey && e.key === 'd') {
                            document.getElementById('username').value = 'demo';
                            document.getElementById('password').value = 'demo';
                            document.getElementById('login-button').click();
                        }
                    });
                </script>
            </body>
            </html>    
            """


@app.route("/api/login", methods=["POST"])
def api_login():
    """Stateless authentication endpoint."""
    try:
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return (
                jsonify({"success": False, "error": "Username and password required"}),
                400,
            )

        # Authenticate user
        user = auth_server.authenticate_user(username, password)
        if not user:
            return jsonify({"success": False, "error": "Invalid credentials"}), 401

        # Create stateless token
        token_result = auth_server.create_stateless_token(
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
                    "full_name": user["full_name"],
                    "department": user["department"],
                },
                "artifact_summary": token_result["artifact_summary"],
                "metadata": token_result["metadata"],
                "token_size": token_result["token_size"],
                "mining_time": token_result["mining_time"],
                "token_type": "stateless",
            }
            return jsonify(response_data)
        else:
            return jsonify({"success": False, "error": token_result["error"]}), 500

    except Exception as e:
        logger.error(f"Stateless login error: {e}")
        return jsonify({"success": False, "error": "Internal server error"}), 500


@app.route("/api/profile")
@require_stateless_auth
def api_profile():
    """Protected endpoint - user profile with stateless verification."""
    return jsonify(
        {
            "user_id": request.user["user_id"],
            "username": request.user["username"],
            "created_at": request.user["created_at"],
            "expires_at": request.user["expires_at"],
            "mining_time": request.user["mining_time"],
            "token_type": request.token_type,
            "verification_mode": request.artifact_verification["verification_mode"],
            "session_age_minutes": int(
                (
                    datetime.utcnow()
                    - datetime.fromisoformat(request.user["created_at"])
                ).total_seconds()
                / 60
            ),
            "artifact_info": {
                "config_hash": request.user["artifact_summary"]["config_hash"],
                "rarity": request.user["artifact_summary"]["rarity"],
                "creation_timestamp": request.user["artifact_summary"]["creation_timestamp"],
                "all_valid": request.artifact_verification["all_valid"],
            },
        }
    )


@app.route("/api/secret")
@require_stateless_auth
def api_secret():
    """Protected endpoint - secret data with stateless access control."""
    return jsonify(
        {
            "message": "This is classified data accessible via stateless authentication!",
            "user": request.user["username"],
            "server_time": datetime.utcnow().isoformat(),
            "access_level": "stateless_authenticated",
            "token_type": request.token_type,
            "classified_data": {
                "security_clearance": "TOP SECRET - STATELESS",
                "access_code": "TSP-STATELESS-2025",
                "account_balance": 5000000,
                "crypto_assets": ["Bitcoin", "Ethereum", "TSP-Tokens"],
                "permissions": ["read", "write", "admin", "stateless_deploy"],
                "special_access": "Zero-storage verification successful",
            },
            "stateless_metadata": {
                "verification_mode": request.artifact_verification["verification_mode"],
                "config_hash": request.user["artifact_summary"]["config_hash"],
                "mining_time": request.user["mining_time"],
                "rarity": request.user["artifact_summary"]["rarity"],
                "server_storage_used": "0 bytes (pure stateless)",
            },
        }
    )


@app.route("/api/token-info")
@require_stateless_auth
def api_token_info():
    """Debug endpoint - detailed stateless token information."""
    return jsonify(
        {
            "token_analysis": {
                "type": "TSP Stateless Token",
                "embedded_artifact": True,
                "server_storage": "0 bytes",
                "verification_mode": request.artifact_verification["verification_mode"],
                "all_checks_valid": request.artifact_verification["all_valid"],
            },
            "session_details": request.user,
            "artifact_verification": request.artifact_verification,
            "stateless_benefits": [
                "No server-side session storage required",
                "Horizontally scalable without sticky sessions",
                "Microservices-friendly architecture",
                "Instant verification without database lookups",
                "Self-contained cryptographic proof",
            ],
            "performance_metrics": {
                "token_creation_time": f"{request.user['mining_time']}s",
                "verification_time": "<100ms",
                "storage_overhead": "0 bytes server-side",
                "scalability": "Unlimited horizontal scaling",
            },
        }
    )


@app.route("/api/stats")
def api_stats():
    """Public server statistics - stateless architecture info."""
    return jsonify(
        {
            "server": "TSP Stateless Authentication Platform",
            "architecture": "Pure Stateless - Zero Storage",
            "protocol_version": "TSP-Stateless-1.0",
            "model": "WEB_AUTH",
            "registered_users": len(auth_server.users_db),
            "server_time": datetime.utcnow().isoformat(),
            "session_storage": "0 bytes (stateless architecture)",
            "features": [
                "Pure Stateless Authentication",
                "Embedded TSP Artifact Verification",
                "Zero Server-Side Storage",
                "Microservices Architecture Ready",
                "Horizontal Scaling Without Limits",
                "Cryptographic Proof-of-Work Protection",
            ],
            "demo_accounts": [
                {"username": "alice", "role": "admin", "department": "Engineering"},
                {"username": "bob", "role": "user", "department": "Product"},
                {"username": "charlie", "role": "user", "department": "Research"},
                {"username": "demo", "role": "guest", "department": "Testing"},
            ],
            "stateless_advantages": {
                "scalability": "Unlimited horizontal scaling",
                "performance": "No database lookups for verification",
                "reliability": "No single point of failure",
                "simplicity": "No session management complexity",
                "security": "Cryptographically self-contained tokens",
            },
        }
    )


if __name__ == "__main__":
    logger.info("Starting TSP Stateless Authentication Server...")
    logger.info("Architecture: Pure stateless - no commits.json, no server storage")
    logger.info("Token Type: Self-contained with embedded TSP artifacts")
    logger.info(
        "Demo accounts: alice/alice123, bob/bob456, charlie/charlie789, demo/demo"
    )
    logger.info("Navigate to http://localhost:5000 for stateless interface")
    logger.info("Press Ctrl+D on login page for quick demo access")

    app.run(debug=True, host="0.0.0.0", port=5000)