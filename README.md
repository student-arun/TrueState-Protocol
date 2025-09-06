# TSP - True State Protocol
**Copyright © 2025 Vladislav Dunaev**

A cryptographic protocol for creating mathematically unique, self-verifying digital artifacts with built-in ownership chains and stateless verification.

## Overview

TSP (True State Protocol) creates digital artifacts that are mathematically impossible to forge or duplicate. 
Each artifact contains cryptographic proofs of authenticity, ownership, and rarity that can be verified independently without requiring external databases or network connectivity.

### Key Features

- **Mathematical Uniqueness**: Artifacts are backed by cryptographic prime generation with proof-of-work validation
- **Stateless Verification**: Complete verification without databases, networks, or central authorities
- **Ownership Chains**: Built-in designated ownership with transferable proofs
- **Graduated Rarity**: Configurable complexity levels for different use cases
- **Self-Contained Proofs**: All verification data embedded in the artifact
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
- **TSP**: Main interface for creating and verifying artifacts
- **TSPHelper**: Utility class for simplified operations

## Installation

```bash
pip install cryptography argon2-cffi portalocker
```

### Dependencies

- `cryptography`: For digital signatures and key management
- `argon2-cffi`: Memory-hard proof-of-work functions
- `portalocker`: Atomic file operations for commit storage

## Quick Start

### Generate User Keys

```python
from source.signature import SignatureHandler

# Generate key pair
signature = SignatureHandler.generate_keys(
    private_key_path="private.pem",
    public_key_path="public.pem", 
    password=b"your_secure_password"
)
```

### Create an Artifact

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

# Create artifact
result = tsp.create_artifact()
print(f"Artifact ID: {result['artifact_id']}")
print(f"Config Hash: {result['config_hash']}")
```

### Verify an Artifact

```python
# Initialize TSP for verification
tsp_verify = TSP(
    private_key_path="private.pem",
    public_key_path="public.pem", 
    key_password=b"your_secure_password",
    mode="verify"
)

# Verify artifact
verification = tsp_verify.verify_artifact(artifact_id)
print(f"Valid: {verification['all_valid']}")
```

## Examples

### Ownership Chains

```python
from tsp_helper import TSPHelper

helper = TSPHelper()

# Alice creates artifact for Bob
tsp_alice = helper.create_tsp("alice", designated_owner="bob")
artifact = tsp_alice.create_artifact()

# Bob verifies ownership
tsp_bob = helper.create_tsp("bob", mode="verify")
ownership = tsp_bob.verify_my_ownership(artifact['artifact_id'])
print(f"Bob owns artifact: {ownership['ownership_valid']}")

# Bob transfers to Charlie
tsp_bob_create = helper.create_tsp("bob", designated_owner="charlie")
new_artifact = tsp_bob_create.create_artifact()
```

### Digital Certificates

Create tamper-proof educational or professional certificates:

```python
from tsp_helper import TSPHelper

helper = TSPHelper()

# University creates diploma for graduate
tsp_university = helper.create_tsp(
    "university", 
    model="CERTIFICATE",  # Higher computational cost
    designated_owner="graduate"
)

print("Creating digital diploma certificate...")
diploma = tsp_university.create_artifact()

print(f"Certificate issued!")
print(f"Certificate ID: {diploma['artifact_id']}")
print(f"Rarity Level: {diploma['rarity']}")
print(f"Computational Proof: {diploma['config_hash'][:16]}...")

# Graduate verifies ownership
tsp_graduate = helper.create_tsp("graduate", mode="verify")
verification = tsp_graduate.verify_my_ownership(diploma['artifact_id'])

print(f"Certificate authentic: {verification['artifact_valid']}")
print(f"Graduate ownership: {verification['ownership_valid']}")
print(f"All proofs valid: {verification['all_checks_valid']}")

# Anyone can verify certificate authenticity
tsp_employer = helper.create_tsp("employer", mode="verify")
authenticity = tsp_employer.verify_artifact(diploma['artifact_id'])
print(f"Certificate verified by employer: {authenticity['all_valid']}")
```

### Software Licensing

Create unforgeable software licenses with built-in ownership:

```python
from tsp_helper import TSPHelper

helper = TSPHelper()

# Software vendor creates license for customer
tsp_vendor = helper.create_tsp(
    "software_vendor",
    model="LICENSE",  # Medium computational cost
    designated_owner="customer"
)

print("Generating software license...")
license_artifact = tsp_vendor.create_artifact()

print(f"License Key Generated!")
print(f"License ID: {license_artifact['artifact_id']}")
print(f"License Hash: {license_artifact['config_hash']}")
print(f"License Rarity: {license_artifact['rarity']}")

# Customer activates software with license
tsp_customer = helper.create_tsp("customer", mode="verify")
license_check = tsp_customer.verify_my_ownership(license_artifact['artifact_id'])

if license_check['ownership_valid']:
    print("✅ Software activated successfully!")
    print(f"Licensed to: {license_check['creator_pubkey'][:16]}...")
    print(f"Valid license: {license_check['all_checks_valid']}")
else:
    print("❌ Invalid or unauthorized license")

# License cannot be pirated - cryptographic proof required
```

### Web Authentication Server

Complete stateless authentication using TSP artifacts as session tokens:

```python
from flask import Flask, request, jsonify
from tsp import TSP

app = Flask(__name__)

@app.route("/api/login", methods=["POST"])
def login():
    # Authenticate user credentials
    user = authenticate_user(username, password)
    
    # Create TSP artifact as session token
    tsp = TSP(keys..., model="WEB_AUTH")
    artifact = tsp.create_artifact()
    
    # Return base64-encoded token
    return jsonify({"token": create_session_token(user, artifact)})

@app.route("/api/protected")
@require_tsp_auth  # Verifies TSP artifact
def protected_endpoint():
    return jsonify({"data": "secret information"})
```

The server includes a modern web interface with:
- Proof-of-work token generation
- Real-time authentication status
- Protected API testing
- Demo accounts (alice/alice123, bob/bob456, etc.)

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

## Artifact Types

TSP supports multiple artifact types with different computational requirements:

| Model | Difficulty | Memory Cost | Use Case |
|-------|------------|-------------|----------|
| WEB_AUTH | 2 | 64 MB | Authentication tokens |
| LICENSE | 4 | 512 MB | Software licenses |
| CERTIFICATE | 8 | 512 MB | Digital certificates |
| NFT | 16 | 4096 MB | High-value collectibles |

## Core Concepts

### Mathematical Uniqueness

Each artifact requires generating a cryptographic prime number that satisfies dual proof-of-work constraints:
1. `SHA3-256(prime_bytes) < difficulty_threshold`
2. `SHA3-256(pubkey + seed + pow_hash) < difficulty_threshold`

This makes artifacts computationally expensive to create but instant to verify.

### Stateless Verification

Artifacts contain all data needed for verification:
- Cryptographic signatures
- Proof-of-work evidence  
- Genesis commitments
- Merkle tree proofs
- Configuration hashes

No external databases or network calls required.

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
- `create_artifact()` - Generate new artifact
- `verify_artifact(identifier)` - Verify artifact integrity
- `verify_my_ownership(identifier)` - Check ownership rights
- `restore_artifact(identifier)` - Restore artifact state
- `list_artifacts()` - List all stored artifacts

### TSPHelper Class

#### Methods
- `create_tsp(username, model, mode, designated_owner)` - Simplified TSP creation
- `get_user_hash(username)` - Get user's public key hash
- `check_user_keys(username)` - Verify key files exist

## Storage Format

Artifacts are stored in `commits.json` with complete verification data:

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

## Use Cases

### Digital Authentication
- Unforgeable login tokens
- Multi-factor authentication artifacts
- Session credentials with built-in expiration

### Supply Chain Verification
- Product authenticity certificates
- Chain of custody tracking
- Quality assurance proofs

### Software Licensing
- Tamper-proof license keys
- Usage tracking artifacts
- Subscription management

### Digital Collectibles
- Provably rare digital assets
- Ownership transfer mechanisms
- Authenticity guarantees

### Certificate Management
- Educational diplomas
- Professional certifications
- Government-issued documents

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
- WEB_AUTH: < 1 second
- LICENSE: 5-30 seconds  
- CERTIFICATE: 30-120 seconds
- NFT: 2-10 minutes

### Verification Times
- Single artifact: < 100ms
- Batch verification: Linear scaling
- Merkle proof: Logarithmic complexity

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

### Development Setup

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest

# Generate test keys
python examples/generate_keys.py
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

- [ ] Multi-signature artifacts
- [ ] Time-locked activation
- [ ] Cross-protocol bridges
- [ ] Hardware security module integration
- [ ] Mobile SDK development
- [ ] Enterprise API gateway

---

**TSP Protocol** - Creating mathematical uniqueness in the digital world.