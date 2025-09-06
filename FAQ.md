# TSP Protocol - Frequently Asked Questions

## General Questions

### What is TSP (True State Protocol)?

TSP is a cryptographic protocol that creates mathematically unique, self-verifying digital artifacts. Each artifact contains cryptographic proofs that make it impossible to forge or duplicate, with complete verification possible offline without any central authority.

### How is TSP different from blockchain?

| Feature | TSP | Blockchain |
|---------|-----|------------|
| **Verification** | Instant, offline | Requires network consensus |
| **Storage** | Self-contained artifacts | Distributed ledger |
| **Scalability** | No network overhead | Limited by block size/time |
| **Energy** | One-time proof-of-work | Continuous mining |
| **Dependencies** | None (stateless) | Full network nodes |

### What makes TSP artifacts unforgeable?

TSP artifacts require:
1. **Cryptographic prime generation** with specific bit lengths
2. **Dual proof-of-work validation** using SHA3-256
3. **Digital signatures** from the creator's private key
4. **Merkle tree commitments** for batch integrity
5. **Domain separation** preventing cross-context attacks

Forging an artifact would require breaking SHA3-256 or stealing private keys.

## Technical Questions

### What are the different artifact models?

| Model | Difficulty | Mining Time | Memory Cost | Use Case |
|-------|------------|-------------|-------------|----------|
| **WEB_AUTH** | 2 | < 1 second | 64 MB | Authentication tokens |
| **LICENSE** | 4 | 5-30 seconds | 512 MB | Software licenses |
| **CERTIFICATE** | 8 | 30-120 seconds | 512 MB | Digital certificates |
| **NFT** | 16 | 2-10 minutes | 4096 MB | High-value collectibles |

### How does ownership verification work?

TSP supports **designated ownership** where artifacts are created for specific public key holders:

```python
# Create artifact for specific owner
owner_hash = TSP.create_pubkey_hash_from_file("owner_public.pem")
tsp = TSP(..., designated_owner_hash=owner_hash)
artifact = tsp.create_artifact()

# Only the designated owner can verify ownership
tsp_owner = TSP(..., mode="verify")
result = tsp_owner.verify_my_ownership(artifact['artifact_id'])
# result['ownership_valid'] = True only for the correct owner
```

### Can artifacts be transferred between owners?

Yes! Ownership chains are supported:
1. Alice creates artifact for Bob
2. Bob verifies ownership
3. Bob creates new artifact for Artur (proving the transfer)
4. Artur can trace the ownership history

Each transfer creates a new artifact with cryptographic proof of the previous ownership.

### Do I need internet connectivity?

**No!** TSP artifacts are completely self-contained:
- **Creation**: No network required (only local computation)
- **Verification**: All data embedded in artifact
- **Storage**: Simple JSON files
- **Transfer**: Copy artifact data

This makes TSP ideal for offline environments, air-gapped systems, and edge computing.

## Implementation Questions

### How do I get started with TSP?

1. **Install dependencies:**
   ```bash
   pip install cryptography argon2-cffi portalocker
   ```

2. **Generate keys:**
   ```python
   from source.signature import SignatureHandler
   SignatureHandler.generate_keys("private.pem", "public.pem", b"password")
   ```

3. **Create first artifact:**
   ```python
   from tsp import TSP
   tsp = TSP("private.pem", "public.pem", b"password", "WEB_AUTH")
   artifact = tsp.create_artifact()
   ```

### How do I verify an artifact?

```python
# Verify artifact integrity
tsp_verify = TSP(..., mode="verify")
result = tsp_verify.verify_artifact(artifact_id)

# Check specific ownership
ownership = tsp_verify.verify_my_ownership(artifact_id)
print(f"Valid: {ownership['all_checks_valid']}")
```

### Can I customize the computational requirements?

Yes, through the Controller configuration. You can:
- Adjust base proof-of-work difficulty
- Modify memory costs for Argon2
- Change rarity probability weights
- Set custom prime number bit lengths

### How do I integrate TSP into my application?

**Web Applications:**
```python
# Use as session tokens
@app.route("/login")
def login():
    artifact = create_tsp_session(user_id)
    return {"token": base64_encode(artifact)}

@app.route("/protected")
@require_tsp_auth
def protected():
    return {"data": "secret"}
```

**License Management:**
```python
# Generate software license
license = vendor_tsp.create_artifact(designated_owner=customer_key)

# Customer activates software
if customer_tsp.verify_my_ownership(license_id):
    activate_software()
```

## Security Questions

### How secure are TSP artifacts?

TSP security relies on:
- **SHA3-256 cryptographic hash function** (NIST standard)
- **Ed25519 digital signatures** (state-of-the-art elliptic curve)
- **Argon2 memory-hard functions** (password hashing competition winner)
- **Prime number generation** with cryptographic validation

Breaking TSP would require breaking one of these well-established primitives.

### What happens if someone steals my private key?

If your private key is compromised:
- **Existing artifacts remain valid** (they're already signed)
- **New artifacts can be created** by the attacker with your identity
- **Solution:** Generate new keys and migrate to new identity

This is similar to any PKI system - private key security is critical.

### Can quantum computers break TSP?

Current TSP implementation uses classical cryptography vulnerable to quantum attacks:
- **SHA3-256:** Reduced security but still strong
- **Ed25519:** Vulnerable to Shor's algorithm

**Future-proofing:** TSP architecture supports post-quantum cryptography upgrades.

### How do I audit TSP artifacts?

TSP provides comprehensive auditability:

```python
# Get complete artifact information
info = tsp.get_artifact_info(artifact_id)

# Verify all cryptographic proofs
verification = tsp.verify_artifact(artifact_id, debug_config_hash=True)

# Check Merkle tree inclusion
TSP.list_artifacts()  # See all artifacts in system
```

## Performance Questions

### How fast is TSP verification?

- **Artifact verification:** < 100ms
- **Ownership checking:** < 50ms  
- **Merkle proof validation:** < 10ms

Verification is nearly instant regardless of artifact complexity.

### What are the computational costs?

**Creation costs** (one-time):
- WEB_AUTH: Minimal (< 1 second)
- LICENSE: Moderate (5-30 seconds)
- CERTIFICATE: High (30-120 seconds)
- NFT: Very high (2-10 minutes)

**Verification costs** (every time):
- All models: < 100ms consistently

### Can TSP scale to millions of artifacts?

Yes! TSP scales because:
- **No network consensus** required
- **Parallel creation** possible
- **Logarithmic verification** with Merkle trees
- **Stateless servers** can handle unlimited load

### How much storage do artifacts require?

- **Artifact data:** ~2-5 KB each
- **Commits.json:** Linear growth (~5 KB per artifact)
- **Keys:** ~1 KB per identity
- **No databases** or external storage needed

## Business Questions

### What industries can use TSP?

**High-potential industries:**
1. **Software licensing** - Unforgeable license keys
2. **Digital certificates** - Academic, professional credentials
3. **Supply chain** - Product authenticity tracking
4. **Government services** - Digital ID, permits, licenses
5. **Financial services** - Digital bonds, certificates
6. **Gaming** - Provably rare digital assets

### How does TSP reduce costs?

- **No blockchain fees** or gas costs
- **No central servers** to maintain
- **No database licensing** required
- **Instant verification** reduces support costs
- **Offline capability** reduces infrastructure needs

### Can TSP replace existing PKI?

TSP complements rather than replaces PKI:
- **TSP:** Creates unforgeable digital assets
- **PKI:** Manages identity and trust relationships

TSP can use PKI certificates as the underlying identity layer.

### How do I commercialize TSP?

**Business models:**
- **SaaS verification API** - Charge per verification
- **Enterprise licensing** - License the protocol
- **Integration services** - Custom implementations
- **White-label solutions** - Industry-specific versions

## Troubleshooting

### "Import error: Cannot find TSP modules"

```bash
# Ensure correct directory structure
project/
  ├── tsp.py
  ├── core/
  ├── examples/
  └── source/

# Run from project root
python examples/ownership_chain.py
```

### "Keys missing for user"

```python
# Generate missing keys
from examples.tsp_helper import TSPHelper
helper = TSPHelper()
helper.check_user_keys("username")  # Shows which keys are missing

# Or generate manually
from source.signature import SignatureHandler
SignatureHandler.generate_keys("private.pem", "public.pem", b"password")
```

### "Artifact verification failed"

Common causes:
1. **Wrong model** - Ensure using same model as creation
2. **Corrupted data** - Check commits.json integrity
3. **Key mismatch** - Verify using correct public key
4. **Timestamp issues** - Check system clock

Debug with:
```python
result = tsp.verify_artifact(artifact_id, debug_config_hash=True)
print(result)  # Shows detailed error information
```

### "Mining takes too long"

**Solutions:**
- Use lower complexity model (WEB_AUTH vs NFT)
- Reduce rarity requirements in Controller
- Use faster hardware (more CPU cores/RAM)
- Consider batch creation for multiple artifacts

### "PoW verification failed"

This usually indicates:
- **System clock issues** - Ensure accurate time
- **Corrupted seed data** - Check stored artifact data
- **Memory pressure** - Ensure sufficient RAM for Argon2

## Integration Examples

### Web Authentication

```python
# Login endpoint
@app.route("/api/login", methods=["POST"])
def login():
    user = authenticate_user(username, password)
    tsp = TSP(..., model="WEB_AUTH")
    artifact = tsp.create_artifact()
    return {"token": encode_artifact(artifact)}

# Protected endpoint
@app.route("/api/data")
@require_tsp_token
def protected_data():
    return {"secret": "data"}
```

### Software Licensing

```python
# Vendor creates license
vendor_tsp = TSP(..., designated_owner=customer_pubkey_hash)
license = vendor_tsp.create_artifact()

# Customer validates license
customer_tsp = TSP(..., mode="verify")
if customer_tsp.verify_my_ownership(license_id):
    enable_software_features()
```

### Certificate Issuance

```python
# University issues diploma
university_tsp = TSP(..., model="CERTIFICATE", designated_owner=graduate)
diploma = university_tsp.create_artifact()

# Employer verifies diploma
employer_tsp = TSP(..., mode="verify")
verification = employer_tsp.verify_artifact(diploma_id)
if verification['all_valid']:
    approve_employment()
```

---

**Need more help?**
- Check the examples in `/examples` directory
- Review the comprehensive README
- Test with demo accounts: alice/alice123, bob/bob456
- Run the included demo scripts for hands-on learning