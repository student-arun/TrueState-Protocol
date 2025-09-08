# TSP - True State Protocol
**Copyright © 2025 Vladislav Dunaev**

> **Updated September 2025**: Enhanced with dual-mode architecture - stateful and stateless operation modes for maximum flexibility across different use cases.

A cryptographic protocol for creating mathematically unique, self-verifying digital artifacts with built-in ownership chains and dual-mode verification.

## Overview

TSP (True State Protocol) creates digital artifacts that are mathematically impossible to forge or duplicate. Each artifact contains cryptographic proofs of authenticity, ownership, and rarity that can be verified independently without requiring external databases or network connectivity.

**NEW: Dual-Mode Architecture**
- **Stateful Mode**: Traditional permanent storage with commits.json for licenses, certificates, and NFTs
- **Stateless Mode**: Self-contained tokens with embedded verification data for web authentication and API access
- **Auto-Detection**: Seamless API that automatically handles both modes

### Key Features

- **Mathematical Uniqueness**: Artifacts are backed by cryptographic prime generation with proof-of-work validation
- **Dual-Mode Verification**: Choose between stateful (permanent audit trail) or stateless (zero storage) operation
- **Auto-Detection API**: One interface seamlessly handles both stateful and stateless artifacts
- **Ownership Chains**: Built-in designated ownership with transferable proofs
- **Graduated Rarity**: Configurable complexity levels for different use cases
- **Self-Contained Proofs**: All verification data embedded in the artifact (stateless mode)
- **Offline Capability**: Works without internet connectivity
- **Enterprise Security**: SHA3-256, Argon2, HMAC-based cryptography

## Architecture

TSP consists of 8 core components:

- **Controller**: Configuration management for different artifact types
- **TSPProtocol**: Main protocol implementation with proof-of-work generation
- **TSPProtocolSession**: Verification and restoration of existing artifacts
- **Prime**: Cryptographic prime number generation with validation
- **DeterministicRNG**: Cryptographically secure pseudo-random number generator
- **MerkleTree**: Batch verification and tamper-proof commitment chains
- **TSP**: Main interface for creating and verifying artifacts with dual-mode support
- **TSPHelper**: Utility class for simplified operations

## Installation

```bash
pip install cryptography argon2-cffi portalocker
```

### Dependencies

- `cryptography`: For digital signatures and key management
- `argon2-cffi`: Memory-hard proof-of-work functions
- `portalocker`: Atomic file operations for commit storage (stateful mode only)

## Quick Start

### Generate User Keys

```python
from source.signature import SignatureHandler

# Generate key pair
SignatureHandler.generate_keys(
    private_key_path="private.pem",
    public_key_path="public.pem", 
    password=b"your_secure_password"
)
```

### Create Artifacts (Dual-Mode)

```python
from tsp import TSP

# Initialize TSP for artifact creation
tsp = TSP(
    private_key_path="private.pem",
    public_key_path="public.pem",
    key_password=b"your_secure_password",
    model="WEB_AUTH",  # or NFT, LICENSE, CERTIFICATE
    mode="create"
)

# Stateless Mode: Self-contained tokens (web auth, API tokens)
stateless_result = tsp.create_artifact(persist=False)
print(f"Stateless Token: {stateless_result['mode']}")
print(f"Embedded Data: {len(str(stateless_result['artifact_data']))} bytes")

# Stateful Mode: Permanent storage (licenses, certificates)
stateful_result = tsp.create_artifact(persist=True)
print(f"Artifact ID: {stateful_result['artifact_id']}")
print(f"Merkle Root: {stateful_result['merkle_root']}")
```

### Verify Artifacts (Auto-Detection)

```python
# Initialize TSP for verification
tsp_verify = TSP(
    private_key_path="private.pem",
    public_key_path="public.pem", 
    key_password=b"your_secure_password",
    mode="verify"
)

# Auto-detection: Pass different types for seamless verification
# Stateful verification (artifact ID or config hash)
verification1 = tsp_verify.verify_artifact(stateful_result['artifact_id'])
print(f"Stateful Valid: {verification1['all_valid']} ({verification1['verification_mode']})")

# Stateless verification (embedded artifact data)
verification2 = tsp_verify.verify_artifact(stateless_result['artifact_data'])
print(f"Stateless Valid: {verification2['all_valid']} ({verification2['verification_mode']})")
```

## Examples

### Web Authentication Without Sessions

TSP eliminates server-side session storage entirely with embedded verification:

```python
from flask import Flask, request, jsonify
from tsp import TSP
import base64
import json

app = Flask(__name__)

@app.route("/api/login", methods=["POST"])
def login():
    # Authenticate user credentials
    user = authenticate_user(username, password)
    
    # Create stateless TSP artifact as session token
    tsp = TSP(
        private_key_path="server.pem",
        public_key_path="server_public.pem", 
        key_password=b"server_password",
        model="WEB_AUTH"
    )
    
    # Generate stateless token (persist=False)
    token_result = tsp.create_artifact(persist=False)
    
    # Create session metadata
    session_data = {
        "user_id": user.id,
        "username": user.username,
        "expires_at": int(time.time()) + 3600,  # 1 hour
        "tsp_artifact": token_result["artifact_data"]  # Embedded verification
    }
    
    # Base64 encode for HTTP transport
    token = base64.b64encode(json.dumps(session_data).encode()).decode()
    return jsonify({"token": token})

@app.route("/api/protected")
def protected():
    # Extract token from Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing token"}), 401
    
    token = auth_header[7:]  # Remove "Bearer "
    
    try:
        # Decode session data
        session_data = json.loads(base64.b64decode(token).decode())
        
        # Verify embedded TSP artifact (stateless verification)
        tsp_verify = TSP(
            private_key_path="server.pem",
            public_key_path="server_public.pem",
            key_password=b"server_password",
            mode="verify"
        )
        
        # Auto-detection: Pass artifact_data for stateless verification
        verification = tsp_verify.verify_artifact(session_data["tsp_artifact"])
        
        if verification['all_valid'] and session_data['expires_at'] > int(time.time()):
            return jsonify({
                "data": "secret information",
                "user": session_data['username'],
                "verification_mode": verification['verification_mode']  # "stateless"
            })
        else:
            return jsonify({"error": "invalid token"}), 401
            
    except Exception as e:
        return jsonify({"error": "token verification failed"}), 401
```

**Benefits of Stateless Web Auth:**
- No server-side session storage required
- Unlimited horizontal scaling without sticky sessions
- Microservices can verify tokens independently
- Perfect for containerized and serverless environments

### Ownership Chains

```python
from tsp_helper import TSPHelper

helper = TSPHelper()

# Alice creates artifact for Bob (stateful mode for permanent record)
tsp_alice = helper.create_tsp("alice", designated_owner="bob")
artifact = tsp_alice.create_artifact(persist=True)

# Bob verifies ownership
tsp_bob = helper.create_tsp("bob", mode="verify")
ownership = tsp_bob.verify_my_ownership(artifact['artifact_id'])
print(f"Bob owns artifact: {ownership['ownership_valid']}")

# Bob transfers to Charlie
tsp_bob_create = helper.create_tsp("bob", designated_owner="charlie")
new_artifact = tsp_bob_create.create_artifact(persist=True)
```

### Digital Certificates (Stateful)

Create tamper-proof educational or professional certificates with permanent audit trail:

```python
from tsp_helper import TSPHelper

helper = TSPHelper()

# University creates diploma for graduate (stateful for permanent record)
tsp_university = helper.create_tsp(
    "university", 
    model="CERTIFICATE",  # Higher computational cost
    designated_owner="graduate"
)

print("Creating digital diploma certificate...")
diploma = tsp_university.create_artifact(persist=True)  # Permanent storage

print(f"Certificate issued!")
print(f"Certificate ID: {diploma['artifact_id']}")
print(f"Rarity Level: {diploma['rarity']}")
print(f"Storage Mode: {diploma['mode']}")  # "stateful"

# Graduate verifies ownership
tsp_graduate = helper.create_tsp("graduate", mode="verify")
verification = tsp_graduate.verify_my_ownership(diploma['artifact_id'])

print(f"Certificate authentic: {verification['artifact_valid']}")
print(f"Graduate ownership: {verification['ownership_valid']}")
print(f"Verification mode: {verification['verification_mode']}")  # "stateful"

# Anyone can verify certificate authenticity
tsp_employer = helper.create_tsp("employer", mode="verify")
authenticity = tsp_employer.verify_artifact(diploma['artifact_id'])
print(f"Certificate verified by employer: {authenticity['all_valid']}")
```

### Software Licensing (Dual-Mode)

Create both permanent licenses and temporary access tokens:

```python
from tsp_helper import TSPHelper

helper = TSPHelper()

# Enterprise License (Stateful - permanent audit trail)
tsp_vendor = helper.create_tsp(
    "software_vendor",
    model="LICENSE",
    designated_owner="enterprise_customer"
)

enterprise_license = tsp_vendor.create_artifact(persist=True)
print(f"Enterprise License ID: {enterprise_license['artifact_id']}")
print(f"Storage: {enterprise_license['mode']}")  # "stateful"

# SaaS Access Token (Stateless - no server storage)
tsp_saas = helper.create_tsp(
    "saas_vendor", 
    model="WEB_AUTH",
    designated_owner="saas_customer"
)

access_token = tsp_saas.create_artifact(persist=False)
print(f"SaaS Token Size: {len(str(access_token['artifact_data']))} bytes")
print(f"Storage: {access_token['mode']}")  # "stateless"

# Customer activates software
tsp_customer = helper.create_tsp("enterprise_customer", mode="verify")

# Verify enterprise license (by ID)
license_check = tsp_customer.verify_my_ownership(enterprise_license['artifact_id'])

# Verify SaaS token (by embedded data)
token_check = tsp_customer.verify_my_ownership(access_token['artifact_data'])

print(f"Enterprise license valid: {license_check['ownership_valid']}")
print(f"SaaS token valid: {token_check['ownership_valid']}")
```

### Utility Helper

The `TSPHelper` class simplifies common operations:

```python
from tsp_helper import TSPHelper

helper = TSPHelper()

# Auto-configure TSP instance
tsp = helper.create_tsp("alice", model="CERTIFICATE", designated_owner="bob")

# Get user's public key hash
user_hash = helper.get_user_hash("bob")

# Check key files
helper.check_user_keys("alice")
```

## Artifact Types & Modes

TSP supports multiple artifact types with different computational requirements and storage modes:

| Model | Difficulty | Memory Cost | Primary Mode | Use Case |
|-------|------------|-------------|--------------|----------|
| WEB_AUTH | 2 | 64 MB | Stateless | Authentication tokens, API access |
| LICENSE | 4 | 512 MB | Both | Software licenses, subscriptions |
| CERTIFICATE | 8 | 512 MB | Stateful | Digital certificates, diplomas |
| NFT | 16 | 4096 MB | Stateful | High-value collectibles, art |

### Mode Selection Guide

**Choose Stateful Mode (`persist=True`) for:**
- Permanent credentials (diplomas, certifications)
- High-value assets (NFTs, legal documents)  
- Regulatory compliance (audit trails required)
- Transfer/resale scenarios

**Choose Stateless Mode (`persist=False`) for:**
- Web authentication sessions
- API access tokens
- Microservices communication
- High-throughput scenarios
- Temporary credentials

## Core Concepts

### Mathematical Uniqueness

Each artifact requires generating a cryptographic prime number that satisfies dual proof-of-work constraints:
1. `SHA3-256(prime_bytes) < difficulty_threshold`
2. `SHA3-256(pubkey + seed + pow_hash) < difficulty_threshold`

This makes artifacts computationally expensive to create but instant to verify.

### Dual-Mode Verification

**Stateful Mode:**
- Artifacts stored in `commits.json` with Merkle tree proofs
- Verification by artifact ID or config hash lookup
- Full audit trail and uniqueness guarantees
- Perfect for permanent assets

**Stateless Mode:**
- All verification data embedded in artifact data
- No server-side storage required
- Self-contained cryptographic proofs
- Perfect for scalable web applications

**Auto-Detection:**
```python
# TSP automatically detects mode based on input type
tsp.verify_artifact(123)                    # int -> stateful lookup
tsp.verify_artifact("abc123...")             # str -> stateful lookup  
tsp.verify_artifact({"artifact_data": ...}) # dict -> stateless verification
```

### Ownership Chains

Artifacts can be created for specific owners using designated public key hashes:

```python
# Get target owner's public key hash
owner_hash = TSP.create_pubkey_hash_from_file("bob_public.pem")

# Create artifact for specific owner
tsp = TSP(..., designated_owner_hash=owner_hash)
```

### Rarity System

Built-in rarity mechanics with weighted probability:
- Rarer artifacts require more computational work
- Rarity affects prime number bit length and proof-of-work difficulty
- Deterministically derived from cryptographic seed

## API Reference

### TSP Class

#### Constructor
```python
TSP(private_key_path, public_key_path, key_password, model, mode="create", designated_owner_hash=None)
```

#### Methods
- `create_artifact(persist=True)` - Generate new artifact (stateful/stateless)
- `verify_artifact(identifier)` - Verify artifact integrity (auto-detection)
- `verify_my_ownership(identifier)` - Check ownership rights (auto-detection)
- `restore_artifact(identifier)` - Restore artifact state (stateful only)
- `list_artifacts()` - List all stored artifacts (stateful only)

#### New Parameters
- `persist` (bool): 
  - `True` = Stateful mode (commits.json storage)
  - `False` = Stateless mode (embedded data only)

### TSPHelper Class

#### Methods
- `create_tsp(username, model, mode, designated_owner)` - Simplified TSP creation
- `get_user_hash(username)` - Get user's public key hash
- `check_user_keys(username)` - Verify key files exist

## Storage Formats

### Stateful Storage (commits.json)
```json
{
  "artifact_index": 0,
  "seed": "...",
  "public_key": "...",
  "signature": "...",
  "config_hash": "...",
  "prime": "...",
  "designated_owner": "...",
  "merkle_root": "...",
  "merkle_proof": [...],
  "commit_signature": "..."
}
```

### Stateless Storage (embedded in tokens)
```json
{
  "artifact_data": {
    "seed": "...",
    "public_key": "...", 
    "signature": "...",
    "config_hash": "...",
    "prime": "...",
    "all_verification_data": "..."
  }
}
```

## Use Cases by Mode

### Stateful Mode Use Cases
- **Digital Certificates**: Academic diplomas, professional certifications
- **Software Licensing**: Enterprise perpetual licenses
- **Digital Collectibles**: NFTs, rare digital assets
- **Legal Documents**: Contracts, deeds, official records
- **Supply Chain**: Product authenticity with audit trail

### Stateless Mode Use Cases  
- **Web Authentication**: Session tokens, login credentials
- **API Access**: Service-to-service authentication
- **Microservices**: Inter-service communication tokens
- **Mobile Apps**: Offline-capable authentication
- **Temporary Access**: Short-term permissions, trial access

## Security Features

### Cryptographic Primitives
- **SHA3-256**: Primary hash function
- **Argon2**: Memory-hard proof-of-work
- **HMAC**: Message authentication
- **Ed25519**: Digital signatures

### Attack Resistance
- **Forgery Protection**: Mathematical prime generation requirements
- **Replay Protection**: Unique nonces and timestamps
- **Tampering Detection**: Comprehensive integrity checks
- **Collision Resistance**: Domain-separated hash functions

### Privacy Features
- **Minimal Data**: Only necessary information stored
- **Designated Ownership**: Private artifact creation
- **Offline Verification**: No network exposure required

## Performance

### Creation Times (approximate)
- **WEB_AUTH**: < 1 second (both modes)
- **LICENSE**: 5-30 seconds (both modes)
- **CERTIFICATE**: 30-120 seconds (primarily stateful)
- **NFT**: 2-10 minutes (stateful only)

### Verification Times
- **Stateful**: < 100ms (database lookup + crypto verification)
- **Stateless**: < 50ms (pure crypto verification)
- **Auto-detection**: No performance penalty

### Storage Comparison
- **Stateful**: ~500-800 bytes per artifact (commits.json)
- **Stateless**: ~2-5KB per token (embedded data)
- **Trade-off**: Storage size vs server-side persistence

## Contributing

1. Fork the repository at https://github.com/sonymag/TrueState-Protocol
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/TrueState-Protocol.git`
3. Create feature branch: `git checkout -b feature/amazing-feature`
4. Make your changes and commit: `git commit -m 'Add amazing feature'`
5. Push to your fork: `git push origin feature/amazing-feature`
6. Open a Pull Request from your fork to `sonymag/TrueState-Protocol:main`

### Development Setup

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest

# Test dual-mode examples
python examples/2_ownership_chain.py
python examples/1_software_licensing.py
python examples/3_digital_certificates.py

# Run stateless web server
python examples/4_tsp_flask_auth.py
```

## License

TrueState Protocol (TSP) is dual-licensed to provide flexibility for different use cases:

### Open Source License (AGPL-3.0)
For open source, academic, and non-commercial projects. All derivative works must also be open source.

### Commercial License
For proprietary and commercial applications. Allows closed-source distribution and commercial use.

**Copyright © 2025 Vladislav Dunaev. All rights reserved.**

Choose the license that fits your needs:
- **Open Source Projects**: Use under [AGPL-3.0](https://www.gnu.org/licenses/agpl-3.0.html)
- **Commercial Projects**: Contact dunaevlad@gmail.com for commercial licensing

See [LICENSE](LICENSE) file for complete terms.

**SPDX-License-Identifier:** AGPL-3.0-or-Commercial

## Technical Support

For technical questions or implementation support:
- Open an issue on GitHub
- Review the examples in `/examples` directory
- Check the test suite for usage patterns

## Documentation

- [Architecture & Visual Guide](ARCHITECTURE.md) - Workflow diagrams and system architecture
- [FAQ](FAQ.md) - Frequently asked questions

## Roadmap

- [x] Dual-mode architecture (stateful/stateless)
- [x] Auto-detection API
- [x] Stateless web authentication
- [ ] Time-locked activation
- [ ] Mobile SDK development

---

**TSP Protocol** - Creating mathematical uniqueness in the digital world with flexible deployment options.