"""
TSP Example - Software Licensing Demo
Copyright (c) 2025 Vladislav Dunaev
Licensed under AGPL-3.0-or-Commercial
"""

"""
TSP CAPTCHA Demo
"""

import os
import time
import logging
import hashlib
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional

from flask import Flask, request, jsonify

# Исправленные импорты TSP модулей
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from tsp import TSP
    from source.signature import SignatureHandler
except ImportError as e:
    print(f"ОШИБКА: Не удалось импортировать TSP модули: {e}")
    print("Убедитесь что tsp.py и source/signature.py доступны")
    print(f"Текущий путь: {os.getcwd()}")
    print(f"Поиск в: {Path(__file__).parent.parent}")
    sys.exit(1)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)


class TSPCaptchaSystem:
    """Исправленная TSP CAPTCHA система."""

    def __init__(self, server_keys_dir: str = "captcha_keys"):
        self.server_keys_dir = Path(server_keys_dir)
        self.server_password = b"TSP-CAPTCHA-SERVER-2025"
        self.captcha_cache = {}
        self.max_cache_size = 1000
        self._cache_lock = threading.Lock()  # Добавляем потокобезопасность

        self._ensure_server_keys()

        self.difficulty_levels = {
            "easy": {"model": "WEB_AUTH", "expected_time": 5},
            "medium": {"model": "LICENSE", "expected_time": 15},
            "hard": {"model": "CERTIFICATE", "expected_time": 30},
        }

        logger.info("TSP CAPTCHA system initialized")

    def _ensure_server_keys(self):
        """Создает серверные ключи."""
        try:
            self.server_keys_dir.mkdir(exist_ok=True, parents=True)

            private_key_path = self.server_keys_dir / "private.pem"
            public_key_path = self.server_keys_dir / "public.pem"

            if not private_key_path.exists() or not public_key_path.exists():
                logger.info("Generating CAPTCHA server keys...")

                # ИСПРАВЛЕНИЕ: Правильно создаем и сохраняем ключи
                signature_handler = SignatureHandler(
                    private_key_path=str(private_key_path),
                    public_key_path=str(public_key_path),
                    password=self.server_password,
                )

                # Убеждаемся что ключи действительно созданы
                if not private_key_path.exists() or not public_key_path.exists():
                    raise Exception("Failed to create key files")

                logger.info(
                    f"CAPTCHA keys generated: {private_key_path}, {public_key_path}"
                )
            else:
                logger.info("Using existing CAPTCHA server keys")

        except Exception as e:
            logger.error(f"Error creating server keys: {e}")
            raise

    def create_challenge(self, difficulty: str = "easy", client_id: str = None) -> Dict:
        """Создает TSP CAPTCHA challenge."""
        if difficulty not in self.difficulty_levels:
            difficulty = "easy"

        config = self.difficulty_levels[difficulty]
        challenge_id = hashlib.sha256(
            f"{time.time()}-{client_id}-{difficulty}-{os.urandom(8).hex()}".encode()
        ).hexdigest()[:16]

        try:
            logger.info(f"Creating {difficulty} CAPTCHA challenge {challenge_id}")
            start_time = time.time()

            # ИСПРАВЛЕНИЕ: Проверяем существование ключей перед созданием TSP
            private_key_path = self.server_keys_dir / "private.pem"
            public_key_path = self.server_keys_dir / "public.pem"

            if not private_key_path.exists() or not public_key_path.exists():
                raise Exception(
                    f"Key files not found: {private_key_path}, {public_key_path}"
                )

            tsp = TSP(
                private_key_path=str(private_key_path),
                public_key_path=str(public_key_path),
                key_password=self.server_password,
                model=config["model"],
                mode="create",
            )

            artifact = tsp.create_artifact()
            generation_time = time.time() - start_time

            # ИСПРАВЛЕНИЕ: Проверяем что artifact был создан корректно
            if not artifact or "artifact_id" not in artifact:
                raise Exception("Failed to create TSP artifact")

            # Сохраняем в кэш потокобезопасно
            challenge_data = {
                "artifact_id": artifact["artifact_id"],
                "config_hash": artifact.get("config_hash", ""),
                "combined_hash": artifact.get("combined_hash", ""),
                "difficulty": difficulty,
                "created_at": datetime.utcnow().isoformat(),
                "expires_at": (datetime.utcnow() + timedelta(minutes=10)).isoformat(),
                "generation_time": generation_time,
                "used": False,
                "model": config["model"],  # Сохраняем модель для верификации
            }

            self._cache_challenge(challenge_id, challenge_data)

            logger.info(f"Challenge {challenge_id} created in {generation_time:.1f}s")

            return {
                "success": True,
                "challenge_id": challenge_id,
                "artifact_id": artifact["artifact_id"],
                "config_hash": artifact.get("config_hash", ""),
                "difficulty": difficulty,
                "generation_time": generation_time,
                "expected_time": config["expected_time"],
                "rarity": artifact.get("rarity", "unknown"),
                "expires_in_minutes": 10,
            }

        except Exception as e:
            logger.error(f"Failed to create challenge: {e}")
            return {"success": False, "error": str(e)}

    def verify_challenge(self, challenge_id: str, consume: bool = False) -> Dict:
        """Верифицирует CAPTCHA challenge."""
        try:
            with self._cache_lock:
                challenge_data = self.captcha_cache.get(challenge_id)
                if not challenge_data:
                    return {"valid": False, "error": "Challenge not found or expired"}

                # Проверяем срок действия
                expires_at = datetime.fromisoformat(challenge_data["expires_at"])
                if datetime.utcnow() > expires_at:
                    self._remove_from_cache_unsafe(challenge_id)
                    return {"valid": False, "error": "Challenge expired"}

                # Проверяем не использован ли уже challenge
                if challenge_data.get("used", False):
                    return {"valid": False, "error": "Challenge already used"}

                # Копируем данные для работы вне блокировки
                artifact_id = challenge_data["artifact_id"]
                model = challenge_data.get("model", "WEB_AUTH")

            logger.info(
                f"Verifying CAPTCHA challenge {challenge_id}, artifact {artifact_id}"
            )

            # ИСПРАВЛЕНИЕ: Создаем TSP для верификации с правильной моделью
            private_key_path = self.server_keys_dir / "private.pem"
            public_key_path = self.server_keys_dir / "public.pem"

            if not private_key_path.exists() or not public_key_path.exists():
                raise Exception(f"Key files not found for verification")

            tsp = TSP(
                private_key_path=str(private_key_path),
                public_key_path=str(public_key_path),
                key_password=self.server_password,
                model=model,
                mode="verify",
            )

            verification = tsp.verify_artifact(artifact_id, verify_merkle=True)

            print(f"DEBUG verify_all results: {verification}")
            print(f"PoW check result: {verification.get('pow_valid', 'N/A')}")

            # Ручная проверка PoW для диагностики
            try:
                session = tsp.restore_artifact(artifact_id)
                manual_pow = session.protocol._check_pow(
                    session.protocol.seed, session.protocol.POW_DIFFICULTY
                )
                print(f"Manual PoW check: {manual_pow}")
            except Exception as e:
                print(f"Manual PoW error: {e}")

            if verification and verification.get("all_valid", False):
                logger.info(f"CAPTCHA verification successful for {challenge_id}")

                if consume:
                    with self._cache_lock:
                        # Помечаем как использованный или удаляем
                        if challenge_id in self.captcha_cache:
                            self.captcha_cache[challenge_id]["used"] = True
                        self._remove_from_cache_unsafe(challenge_id)

                return {
                    "valid": True,
                    "challenge_id": challenge_id,
                    "artifact_id": artifact_id,
                    "difficulty": challenge_data["difficulty"],
                    "verification": verification,
                }
            else:
                logger.warning(f"CAPTCHA verification failed for {challenge_id}")
                return {
                    "valid": False,
                    "error": "TSP artifact verification failed",
                    "details": verification,
                }

        except Exception as e:
            logger.error(f"CAPTCHA verification error: {e}")
            return {"valid": False, "error": f"Verification error: {str(e)}"}

    def _cache_challenge(self, challenge_id: str, data: Dict):
        """Кэширует challenge данные потокобезопасно."""
        with self._cache_lock:
            if len(self.captcha_cache) >= self.max_cache_size:
                # Удаляем самый старый элемент
                oldest_key = min(
                    self.captcha_cache.keys(),
                    key=lambda k: self.captcha_cache[k]["created_at"],
                )
                del self.captcha_cache[oldest_key]
                logger.info(f"Removed oldest challenge {oldest_key} from cache")

            self.captcha_cache[challenge_id] = data

    def _remove_from_cache(self, challenge_id: str):
        """Удаляет challenge из кэша потокобезопасно."""
        with self._cache_lock:
            self._remove_from_cache_unsafe(challenge_id)

    def _remove_from_cache_unsafe(self, challenge_id: str):
        """Удаляет challenge из кэша (без блокировки - для внутреннего использования)."""
        self.captcha_cache.pop(challenge_id, None)

    def cleanup_expired_challenges(self):
        """Очищает просроченные challenges."""
        current_time = datetime.utcnow()
        expired_challenges = []

        with self._cache_lock:
            for challenge_id, data in self.captcha_cache.items():
                expires_at = datetime.fromisoformat(data["expires_at"])
                if current_time > expires_at:
                    expired_challenges.append(challenge_id)

            for challenge_id in expired_challenges:
                del self.captcha_cache[challenge_id]

        if expired_challenges:
            logger.info(f"Cleaned up {len(expired_challenges)} expired challenges")

    def get_stats(self) -> Dict:
        """Статистика системы."""
        with self._cache_lock:
            active_count = len(self.captcha_cache)
            used_count = sum(
                1 for data in self.captcha_cache.values() if data.get("used", False)
            )

        return {
            "active_challenges": active_count,
            "used_challenges": used_count,
            "max_cache_size": self.max_cache_size,
            "difficulty_levels": list(self.difficulty_levels.keys()),
            "server_keys_dir": str(self.server_keys_dir),
        }


# Инициализируем систему
try:
    captcha_system = TSPCaptchaSystem()
except Exception as e:
    logger.error(f"Failed to initialize CAPTCHA system: {e}")
    captcha_system = None


def require_valid_captcha(f):
    """Декоратор для проверки CAPTCHA."""

    def decorated_function(*args, **kwargs):
        if not captcha_system:
            return (
                jsonify({"success": False, "error": "CAPTCHA system not available"}),
                500,
            )

        try:
            data = request.get_json()
            if not data:
                return (
                    jsonify({"success": False, "error": "No JSON data provided"}),
                    400,
                )

            challenge_id = data.get("captcha_challenge_id")

            if not challenge_id:
                return jsonify({"success": False, "error": "CAPTCHA required"}), 400

            verification = captcha_system.verify_challenge(challenge_id, consume=True)

            if not verification.get("valid", False):
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "CAPTCHA verification failed",
                            "details": verification.get("error"),
                        }
                    ),
                    400,
                )

            # Добавляем данные CAPTCHA в request
            request.captcha = verification
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"CAPTCHA decorator error: {e}")
            return (
                jsonify({"success": False, "error": "CAPTCHA verification error"}),
                500,
            )

    decorated_function.__name__ = f.__name__
    return decorated_function


# === API ENDPOINTS ===


@app.route("/")
def index():
    """Главная страница с demo interface."""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>TSP CAPTCHA Demo</title>
        <style>
            body { 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                margin: 40px; 
                background: #f5f7fa;
            }
            .container { 
                max-width: 800px; 
                margin: 0 auto;
                background: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            .form-section { 
                margin: 30px 0; 
                padding: 25px; 
                border: 2px solid #e1e8ed; 
                border-radius: 8px;
                background: #fafbfc;
            }
            .captcha-section {
                border-color: #1da1f2;
                background: #f0f8ff;
            }
            button { 
                padding: 12px 24px; 
                margin: 8px; 
                border: none;
                border-radius: 6px;
                font-weight: 500;
                cursor: pointer;
                transition: all 0.2s;
            }
            .primary-btn {
                background: #1da1f2;
                color: white;
            }
            .primary-btn:hover {
                background: #1991db;
            }
            .primary-btn:disabled {
                background: #aab8c2;
                cursor: not-allowed;
            }
            .success { color: #17bf63; font-weight: 500; }
            .error { color: #e0245e; font-weight: 500; }
            .warning { color: #ff6600; font-weight: 500; }
            .info { color: #1da1f2; font-weight: 500; }
            input, textarea, select { 
                padding: 12px; 
                margin: 8px; 
                border: 2px solid #e1e8ed;
                border-radius: 6px;
                font-size: 14px;
                width: 300px;
            }
            input:focus, textarea:focus, select:focus {
                border-color: #1da1f2;
                outline: none;
            }
            .progress-bar {
                width: 100%;
                height: 20px;
                background: #e1e8ed;
                border-radius: 10px;
                overflow: hidden;
                margin: 10px 0;
            }
            .progress-fill {
                height: 100%;
                background: linear-gradient(90deg, #1da1f2, #17bf63);
                width: 0%;
                transition: width 0.3s ease;
            }
            .captcha-status {
                padding: 15px;
                border-radius: 8px;
                margin: 10px 0;
                font-weight: 500;
            }
            .challenge-info {
                background: #e6f3ff;
                border: 1px solid #1da1f2;
            }
            .solving {
                background: #fff3cd;
                border: 1px solid #ff6600;
            }
            .solved {
                background: #d4edda;
                border: 1px solid #17bf63;
            }
            .failed {
                background: #f8d7da;
                border: 1px solid #e0245e;
            }
            .debug-info {
                background: #f8f9fa;
                border: 1px solid #dee2e6;
                padding: 10px;
                border-radius: 4px;
                font-family: monospace;
                font-size: 12px;
                margin: 10px 0;
                white-space: pre-wrap;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ TSP CAPTCHA Demo</h1>
            <p>Демонстрация замены традиционных CAPTCHA на криптографическую защиту TSP</p>

            <div class="form-section">
                <h2>📝 Форма с TSP CAPTCHA защитой</h2>
                <p>Заполните форму. TSP CAPTCHA автоматически создаст криптографическое proof-of-work.</p>

                <div>
                    <input type="text" id="name" placeholder="Ваше имя" value="Alice Smith">
                </div>
                <div>
                    <input type="email" id="email" placeholder="Email" value="alice@example.com">
                </div>
                <div>
                    <textarea id="message" placeholder="Сообщение" rows="3">Тестирую TSP CAPTCHA систему!</textarea>
                </div>

                <div>
                    <label>Уровень защиты:</label>
                    <select id="difficulty">
                        <option value="easy">Easy (WEB_AUTH) - ~5 сек</option>
                        <option value="medium">Medium (LICENSE) - ~15 сек</option>
                        <option value="hard">Hard (CERTIFICATE) - ~30 сек</option>
                    </select>
                </div>

                <button class="primary-btn" onclick="submitForm()" id="submit-btn">
                    Submit with TSP CAPTCHA
                </button>
                <div id="form-result"></div>
            </div>

            <div class="form-section captcha-section">
                <h2>🔐 TSP CAPTCHA Status</h2>
                <div id="captcha-status">Ready to create cryptographic challenge...</div>
                <div class="progress-bar">
                    <div class="progress-fill" id="progress-fill"></div>
                </div>
                <div id="captcha-details"></div>
            </div>

            <div class="form-section">
                <h2>📊 CAPTCHA Statistics</h2>
                <button onclick="showStats()">Show System Stats</button>
                <button onclick="testSystem()">Test System</button>
                <div id="stats-result"></div>
            </div>
        </div>

        <script>
            let currentChallenge = null;
            let isProcessing = false;

            async function submitForm() {
                if (isProcessing) {
                    alert('CAPTCHA уже обрабатывается...');
                    return;
                }

                const name = document.getElementById('name').value;
                const email = document.getElementById('email').value;
                const message = document.getElementById('message').value;
                const difficulty = document.getElementById('difficulty').value;

                if (!name || !email || !message) {
                    alert('Заполните все поля');
                    return;
                }

                isProcessing = true;
                document.getElementById('submit-btn').disabled = true;

                try {
                    // Этап 1: Создание challenge
                    updateCaptchaStatus('🔄 Creating TSP challenge...', 'solving');
                    updateProgress(10);

                    const challengeResponse = await fetch('/api/captcha/challenge', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            difficulty: difficulty,
                            client_id: 'demo-client-' + Date.now()
                        })
                    });

                    if (!challengeResponse.ok) {
                        throw new Error(`HTTP ${challengeResponse.status}: ${challengeResponse.statusText}`);
                    }

                    const challengeData = await challengeResponse.json();

                    if (!challengeData.success) {
                        throw new Error(challengeData.error || 'Failed to create challenge');
                    }

                    currentChallenge = challengeData;
                    updateProgress(30);

                    updateCaptchaStatus(
                        `🧮 TSP Challenge created! Mining completed.
                         <br>Difficulty: ${difficulty.toUpperCase()}
                         <br>Generation time: ${challengeData.generation_time?.toFixed(1) || 'N/A'}s
                         <br>Artifact ID: ${challengeData.artifact_id || 'N/A'}`,
                        'solving'
                    );

                    // Этап 2: Верификация challenge
                    updateProgress(60);
                    updateCaptchaStatus('🔍 Verifying TSP solution...', 'solving');

                    const verifyResponse = await fetch('/api/captcha/verify', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            challenge_id: challengeData.challenge_id
                        })
                    });

                    if (!verifyResponse.ok) {
                        throw new Error(`HTTP ${verifyResponse.status}: ${verifyResponse.statusText}`);
                    }

                    const verifyData = await verifyResponse.json();

                    if (!verifyData.valid) {
                        throw new Error(verifyData.error || 'Verification failed');
                    }

                    updateProgress(90);
                    updateCaptchaStatus(
                        `✅ TSP CAPTCHA verified successfully!
                         <br>Rarity: ${challengeData.rarity || 'N/A'}
                         <br>Verification: PASSED`,
                        'solved'
                    );

                    // Этап 3: Отправка формы
                    updateCaptchaStatus('📤 Submitting form with TSP proof...', 'solving');

                    const submitResponse = await fetch('/api/submit', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            name: name,
                            email: email,
                            message: message,
                            captcha_challenge_id: challengeData.challenge_id
                        })
                    });

                    if (!submitResponse.ok) {
                        throw new Error(`HTTP ${submitResponse.status}: ${submitResponse.statusText}`);
                    }

                    const submitData = await submitResponse.json();

                    if (submitData.success) {
                        updateProgress(100);
                        updateCaptchaStatus('✅ Form submitted with TSP protection!', 'solved');

                        document.getElementById('form-result').innerHTML = 
                            `<p class="success">✅ Form submitted successfully!</p>
                             <p>Submission ID: ${submitData.submission_id || 'N/A'}</p>
                             <p>TSP Verification: PASSED</p>`;
                    } else {
                        throw new Error(submitData.error || 'Submission failed');
                    }

                } catch (error) {
                    console.error('Submit error:', error);
                    updateCaptchaStatus(`❌ Error: ${error.message}`, 'failed');
                    updateProgress(0);
                    document.getElementById('form-result').innerHTML = 
                        `<p class="error">❌ Error: ${error.message}</p>`;
                } finally {
                    isProcessing = false;
                    document.getElementById('submit-btn').disabled = false;
                }
            }

            function updateCaptchaStatus(message, type) {
                const statusDiv = document.getElementById('captcha-status');
                statusDiv.innerHTML = message;
                statusDiv.className = `captcha-status ${type}`;
            }

            function updateProgress(percent) {
                document.getElementById('progress-fill').style.width = percent + '%';
            }

            async function showStats() {
                try {
                    const response = await fetch('/api/captcha/stats');
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                    }

                    const data = await response.json();

                    document.getElementById('stats-result').innerHTML = 
                        `<h3>System Statistics:</h3>
                         <div class="debug-info">${JSON.stringify(data, null, 2)}</div>`;
                } catch (error) {
                    document.getElementById('stats-result').innerHTML = 
                        `<p class="error">Error loading stats: ${error.message}</p>`;
                }
            }

            async function testSystem() {
                try {
                    const response = await fetch('/api/captcha/challenge', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            difficulty: 'easy',
                            client_id: 'test-client'
                        })
                    });

                    const data = await response.json();

                    document.getElementById('stats-result').innerHTML = 
                        `<h3>System Test Result:</h3>
                         <div class="debug-info">${JSON.stringify(data, null, 2)}</div>`;

                } catch (error) {
                    document.getElementById('stats-result').innerHTML = 
                        `<p class="error">System test failed: ${error.message}</p>`;
                }
            }
        </script>
    </body>
    </html>
    """


@app.route("/api/captcha/challenge", methods=["POST"])
def api_create_challenge():
    """Создает TSP CAPTCHA challenge."""
    if not captcha_system:
        return (
            jsonify({"success": False, "error": "CAPTCHA system not initialized"}),
            500,
        )

    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No JSON data provided"}), 400

        difficulty = data.get("difficulty", "easy")
        client_id = data.get("client_id", "anonymous")

        challenge = captcha_system.create_challenge(difficulty, client_id)
        return jsonify(challenge)

    except Exception as e:
        logger.error(f"Challenge creation error: {e}")
        return (
            jsonify({"success": False, "error": f"Internal server error: {str(e)}"}),
            500,
        )


@app.route("/api/captcha/verify", methods=["POST"])
def api_verify_challenge():
    """Верифицирует TSP CAPTCHA (без удаления)."""
    if not captcha_system:
        return jsonify({"valid": False, "error": "CAPTCHA system not initialized"}), 500

    try:
        data = request.get_json()
        if not data:
            return jsonify({"valid": False, "error": "No JSON data provided"}), 400

        challenge_id = data.get("challenge_id")

        if not challenge_id:
            return jsonify({"valid": False, "error": "Challenge ID required"}), 400

        verification = captcha_system.verify_challenge(challenge_id, consume=False)
        return jsonify(verification)

    except Exception as e:
        logger.error(f"CAPTCHA verification error: {e}")
        return (
            jsonify({"valid": False, "error": f"Internal server error: {str(e)}"}),
            500,
        )


@app.route("/api/submit", methods=["POST"])
@require_valid_captcha
def api_submit_form():
    """Обрабатывает отправку формы с TSP CAPTCHA."""
    try:
        data = request.get_json()

        required_fields = ["name", "email", "message"]
        for field in required_fields:
            if not data.get(field):
                return (
                    jsonify(
                        {"success": False, "error": f"Missing required field: {field}"}
                    ),
                    400,
                )

        submission_id = hashlib.sha256(
            f"{data['email']}-{time.time()}".encode()
        ).hexdigest()[:12]

        logger.info(f"Form submitted successfully: {submission_id}")
        logger.info(f"Name: {data['name']}, Email: {data['email']}")

        return jsonify(
            {
                "success": True,
                "submission_id": submission_id,
                "message": "Form submitted with TSP CAPTCHA protection",
                "captcha_verification": getattr(request, "captcha", {}),
            }
        )

    except Exception as e:
        logger.error(f"Form submission error: {e}")
        return (
            jsonify({"success": False, "error": f"Internal server error: {str(e)}"}),
            500,
        )


@app.route("/api/captcha/stats")
def api_captcha_stats():
    """Статистика CAPTCHA системы."""
    if not captcha_system:
        return jsonify({"error": "CAPTCHA system not initialized"}), 500

    try:
        # Очищаем просроченные challenges перед показом статистики
        captcha_system.cleanup_expired_challenges()
        stats = captcha_system.get_stats()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Stats error: {e}")
        return jsonify({"error": f"Failed to get stats: {str(e)}"}), 500


@app.route("/health")
def health_check():
    """Проверка здоровья системы."""
    status = {
        "status": "healthy" if captcha_system else "unhealthy",
        "timestamp": datetime.utcnow().isoformat(),
        "system_initialized": captcha_system is not None,
    }

    if captcha_system:
        try:
            stats = captcha_system.get_stats()
            status["stats"] = stats
        except Exception as e:
            status["stats_error"] = str(e)

    return jsonify(status)


if __name__ == "__main__":
    if not captcha_system:
        logger.error("CAPTCHA system failed to initialize - exiting")
        sys.exit(1)

    logger.info("Starting TSP CAPTCHA Demo Server...")
    logger.info("Navigate to http://localhost:5001 for CAPTCHA demo")
    logger.info("Health check: http://localhost:5001/health")

    app.run(debug=True, host="0.0.0.0", port=5001)
