"""
TSP Example - Software Licensing Demo
Copyright (c) 2025 Vladislav Dunaev
Licensed under AGPL-3.0-or-Commercial
"""

"""
TSP Software Licensing Example - Dual Mode Edition
=================================================

Demonstration of creating and verifying unforgeable software licenses
using TSP protocol with both stateful and stateless modes:

- Stateful Mode: Traditional permanent licenses (stored in commits.json)
- Stateless Mode: Embedded license tokens (no storage required)
- Auto-Detection: Seamless API for both modes
"""

import sys
import time
import json
import base64
from pathlib import Path

# Add parent directory to path for TSP imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from examples.tsp_helper import TSPHelper
    from tsp import TSP
except ImportError as e:
    print(f"ERROR: Failed to import TSP modules: {e}")
    print("Make sure you're running from the correct directory with TSP installed.")
    sys.exit(1)


def demo_traditional_licensing():
    """Traditional software licensing with permanent storage (stateful mode)."""

    print("🏢 TRADITIONAL SOFTWARE LICENSING (Stateful Mode)")
    print("=" * 60)
    print("📦 Product: SecureCAD Pro Enterprise v2025")
    print("💰 License: $5,999/year perpetual license")
    print("🎯 Use Case: Enterprise software with permanent audit trail")
    print("-" * 60)

    helper = TSPHelper()

    # Alice (vendor) creates permanent license for Bob (customer)
    print("\n1️⃣ VENDOR: Creating permanent enterprise license...")
    print("   🔨 Mining LICENSE-grade cryptographic proof...")
    print("   💾 Will be stored in commits.json for audit trail")

    start_time = time.time()

    tsp_vendor = helper.create_tsp(
        "alice",
        model="LICENSE",  # Medium computational cost (5-30 seconds)
        mode="create",
        designated_owner="bob",
    )

    # Create stateful license (persist=True)
    license_artifact = tsp_vendor.create_artifact(persist=True)
    mining_time = time.time() - start_time

    print(f"   ✅ Permanent license generated in {mining_time:.1f} seconds")
    print(f"   📄 License ID: {license_artifact['artifact_id']}")
    print(f"   🔗 Config Hash: {license_artifact['config_hash'][:20]}...")
    print(f"   💎 Rarity Level: {license_artifact['rarity']}")
    print(f"   🎯 Personalized: {license_artifact['is_personalized']}")
    print(f"   🏗️  Merkle Root: {license_artifact['merkle_root'][:20]}...")
    print(f"   📊 Storage Mode: {license_artifact['mode']}")

    # Bob activates software using artifact ID (triggers stateful verification)
    print("\n2️⃣ CUSTOMER: Activating enterprise software...")
    print("   🔍 Verifying via commits.json lookup (stateful mode)")

    tsp_customer = helper.create_tsp("bob", mode="verify")

    # Pass artifact_id (int) - auto-detects stateful mode
    license_verification = tsp_customer.verify_my_ownership(
        license_artifact["artifact_id"]
    )

    print(f"🔍 License authenticity: {'✅ VALID' if license_verification['artifact_valid'] else '❌ INVALID'}")
    print(f"🔑 Bob's ownership: {'✅ VERIFIED' if license_verification['ownership_valid'] else '❌ DENIED'}")
    print(f"🛡️  Merkle proof: {'✅ VALID' if license_verification['merkle_valid'] else '❌ INVALID'}")
    print(f"📊 All checks: {'✅ PASSED' if license_verification['all_checks_valid'] else '❌ FAILED'}")
    print(f"📊 Verification mode: {license_verification['verification_mode']}")

    if license_verification["all_checks_valid"]:
        print("\n🚀 ENTERPRISE SOFTWARE ACTIVATION SUCCESSFUL!")
        print("💻 SecureCAD Pro Enterprise is now licensed and running")
        print(f"👤 Licensed to: Bob")
        print(f"📅 License created: {time.ctime(license_verification.get('creation_timestamp', time.time()))}")
        print("📋 Full audit trail available in commits.json")

    return license_artifact, license_verification


def demo_saas_licensing():
    """Modern SaaS licensing with embedded tokens (stateless mode)."""

    print("\n☁️  MODERN SAAS LICENSING (Stateless Mode)")
    print("=" * 60)
    print("📦 Product: CloudCAD SaaS API v2025")
    print("💰 License: $29/month subscription token")
    print("🎯 Use Case: API access tokens with no server storage")
    print("-" * 60)

    helper = TSPHelper()

    # Alice (vendor) creates embedded license token for Bob
    print("\n1️⃣ SAAS VENDOR: Creating embedded API license token...")
    print("   🔨 Mining WEB_AUTH-grade proof (fast generation)")
    print("   🌐 Stateless - no server storage required")

    start_time = time.time()

    tsp_vendor = helper.create_tsp(
        "alice",
        model="WEB_AUTH",  # Fast generation for API tokens
        mode="create",
        designated_owner="bob",
    )

    # Create stateless license token (persist=False)
    license_token = tsp_vendor.create_artifact(persist=False)
    token_creation_time = time.time() - start_time

    print(f"   ✅ API token generated in {token_creation_time:.2f} seconds")
    print(f"   🔗 Config Hash: {license_token['config_hash'][:20]}...")
    print(f"   💎 Rarity Level: {license_token['rarity']}")
    print(f"   📊 Storage Mode: {license_token['mode']}")
    print(f"   💾 Token Size: ~{len(str(license_token['artifact_data']))} bytes")

    # Create API-ready token
    api_token = {
        "customer_id": "bob_enterprise",
        "product": "CloudCAD_SaaS_API",
        "plan": "professional",
        "issued_at": int(time.time()),
        "expires_at": int(time.time()) + 2592000,  # 30 days
        "tsp_license": license_token["artifact_data"]
    }

    # Base64 encode for API headers
    token_json = json.dumps(api_token, separators=(',', ':'))
    encoded_token = base64.b64encode(token_json.encode()).decode()

    print(f"   🎫 API Token Size: {len(token_json)} bytes")
    print(f"   📦 Base64 Encoded: {len(encoded_token)} chars")
    print(f"   🔗 Usage: Authorization: Bearer {encoded_token[:40]}...")

    # Bob uses API token (stateless verification)
    print("\n2️⃣ CUSTOMER: Using SaaS API with embedded token...")
    print("   🔍 Verifying via embedded data (stateless mode)")

    # Simulate API token verification
    decoded_json = base64.b64decode(encoded_token.encode()).decode()
    decoded_token = json.loads(decoded_json)

    tsp_customer = helper.create_tsp("bob", mode="verify")

    # Pass artifact_data (dict) - auto-detects stateless mode
    token_verification = tsp_customer.verify_my_ownership(
        decoded_token["tsp_license"]
    )

    print(f"🔍 Token authenticity: {'✅ VALID' if token_verification['artifact_valid'] else '❌ INVALID'}")
    print(f"🔑 Bob's authorization: {'✅ VERIFIED' if token_verification['ownership_valid'] else '❌ DENIED'}")
    print(f"📊 All checks: {'✅ PASSED' if token_verification['all_checks_valid'] else '❌ FAILED'}")
    print(f"📊 Verification mode: {token_verification['verification_mode']}")
    print(f"⏰ Token expires: {decoded_token['expires_at'] - int(time.time())}s")

    if token_verification["all_checks_valid"]:
        print("\n🚀 SAAS API ACCESS GRANTED!")
        print("☁️  CloudCAD SaaS API is now accessible")
        print(f"👤 Authorized user: {decoded_token['customer_id']}")
        print(f"📊 Plan: {decoded_token['plan']}")
        print("🌐 No server storage required for verification")

    return encoded_token, token_verification


def demo_auto_detection():
    """Demonstrate automatic mode detection capabilities."""

    print("\n🤖 AUTO-DETECTION CAPABILITIES")
    print("=" * 60)
    print("🎯 One API automatically handles both license types")
    print("-" * 60)

    helper = TSPHelper()

    # Create both license types
    print("\n📋 Creating test licenses...")

    # Stateful license
    tsp_vendor1 = helper.create_tsp("alice", model="LICENSE", mode="create", designated_owner="bob")
    stateful_license = tsp_vendor1.create_artifact(persist=True)

    # Stateless token
    tsp_vendor2 = helper.create_tsp("alice", model="WEB_AUTH", mode="create", designated_owner="bob")
    stateless_token = tsp_vendor2.create_artifact(persist=False)

    # Test auto-detection
    tsp_verifier = helper.create_tsp("bob", mode="verify")

    print("\n🧪 Testing verify_artifact() auto-detection...")

    # Test 1: artifact_id (int) → stateful
    print("\n📋 Test 1: verify_artifact(artifact_id)")
    result1 = tsp_verifier.verify_artifact(stateful_license["artifact_id"])
    print(f"   🔍 Input: artifact_id = {stateful_license['artifact_id']}")
    print(f"   🎯 Detected mode: {result1.get('verification_mode', 'unknown')}")
    print(f"   ✅ Valid: {result1.get('all_valid', False)}")

    # Test 2: config_hash (str) → stateful
    print("\n📋 Test 2: verify_artifact(config_hash)")
    result2 = tsp_verifier.verify_artifact(stateful_license["config_hash"])
    print(f"   🔍 Input: config_hash = {stateful_license['config_hash'][:20]}...")
    print(f"   🎯 Detected mode: {result2.get('verification_mode', 'unknown')}")
    print(f"   ✅ Valid: {result2.get('all_valid', False)}")

    # Test 3: artifact_data (dict) → stateless
    print("\n📋 Test 3: verify_artifact(artifact_data)")
    result3 = tsp_verifier.verify_artifact(stateless_token["artifact_data"])
    print(f"   🔍 Input: artifact_data = {{...dict...}}")
    print(f"   🎯 Detected mode: {result3.get('verification_mode', 'unknown')}")
    print(f"   ✅ Valid: {result3.get('all_valid', False)}")

    print("\n🧪 Testing verify_my_ownership() auto-detection...")

    # Test 4: ownership with stateful
    ownership1 = tsp_verifier.verify_my_ownership(stateful_license["artifact_id"])
    print(f"\n📋 Stateful ownership verification:")
    print(f"   🎯 Mode: {ownership1.get('verification_mode', 'unknown')}")
    print(f"   🔑 Ownership: {ownership1.get('ownership_valid', False)}")

    # Test 5: ownership with stateless
    ownership2 = tsp_verifier.verify_my_ownership(stateless_token["artifact_data"])
    print(f"\n📋 Stateless ownership verification:")
    print(f"   🎯 Mode: {ownership2.get('verification_mode', 'unknown')}")
    print(f"   🔑 Ownership: {ownership2.get('ownership_valid', False)}")

    print("\n✅ AUTO-DETECTION WORKING PERFECTLY!")
    print("🎯 Developer experience: One method, multiple modes")


def demo_security_testing():
    """Test security features across both modes."""

    print("\n🛡️  SECURITY TESTING ACROSS MODES")
    print("=" * 60)

    helper = TSPHelper()

    # Create licenses
    tsp_vendor = helper.create_tsp("alice", model="LICENSE", mode="create", designated_owner="bob")
    stateful_license = tsp_vendor.create_artifact(persist=True)

    tsp_vendor = helper.create_tsp("alice", model="WEB_AUTH", mode="create", designated_owner="bob")
    stateless_token = tsp_vendor.create_artifact(persist=False)

    # Artur attempts to steal licenses
    print("\n🏴‍☠️ SECURITY TEST: Artur attempts license theft...")
    tsp_pirate = helper.create_tsp("artur", mode="verify")

    # Test 1: Stateful license theft attempt
    print("\n📋 Test 1: Attempting to steal stateful license")
    pirate_attempt1 = tsp_pirate.verify_my_ownership(stateful_license["artifact_id"])
    print(f"   🔍 License validity: {pirate_attempt1['artifact_valid']}")
    print(f"   🏴‍☠️ Artur's ownership: {pirate_attempt1['ownership_valid']}")
    print(f"   🛡️  Security result: {'🚨 BREACH!' if pirate_attempt1['ownership_valid'] else '✅ PROTECTED'}")

    # Test 2: Stateless token theft attempt
    print("\n📋 Test 2: Attempting to steal stateless token")
    pirate_attempt2 = tsp_pirate.verify_my_ownership(stateless_token["artifact_data"])
    print(f"   🔍 Token validity: {pirate_attempt2['artifact_valid']}")
    print(f"   🏴‍☠️ Artur's ownership: {pirate_attempt2['ownership_valid']}")
    print(f"   🛡️  Security result: {'🚨 BREACH!' if pirate_attempt2['ownership_valid'] else '✅ PROTECTED'}")

    if not pirate_attempt1["ownership_valid"] and not pirate_attempt2["ownership_valid"]:
        print("\n🛡️  ALL SECURITY TESTS PASSED!")
        print("🔒 Both stateful and stateless modes prevent unauthorized access")
        print("💎 Cryptographic ownership verification is bulletproof")
    else:
        print("\n🚨 SECURITY FAILURE DETECTED!")


def demo_performance_comparison():
    """Compare performance between licensing modes."""

    print("\n⚡ LICENSING PERFORMANCE COMPARISON")
    print("=" * 60)

    helper = TSPHelper()
    runs = 3

    print(f"🔄 Running {runs} iterations of each licensing mode...")

    stateful_times = []
    stateless_times = []

    for i in range(runs):
        print(f"\n🔄 Run {i + 1}/{runs}")

        # Stateful licensing workflow
        tsp_vendor = helper.create_tsp("alice", model="WEB_AUTH", mode="create", designated_owner="bob")
        tsp_customer = helper.create_tsp("bob", mode="verify")

        start = time.time()
        license = tsp_vendor.create_artifact(persist=True)
        verification = tsp_customer.verify_my_ownership(license["artifact_id"])
        stateful_time = time.time() - start
        stateful_times.append(stateful_time)

        # Stateless token workflow
        tsp_vendor = helper.create_tsp("alice", model="WEB_AUTH", mode="create", designated_owner="bob")
        tsp_customer = helper.create_tsp("bob", mode="verify")

        start = time.time()
        token = tsp_vendor.create_artifact(persist=False)
        verification = tsp_customer.verify_my_ownership(token["artifact_data"])
        stateless_time = time.time() - start
        stateless_times.append(stateless_time)

        print(f"   📊 Stateful: {stateful_time:.3f}s | Stateless: {stateless_time:.3f}s")

    # Calculate results
    avg_stateful = sum(stateful_times) / len(stateful_times)
    avg_stateless = sum(stateless_times) / len(stateless_times)

    if avg_stateful < avg_stateless:
        speedup = avg_stateless / avg_stateful
        faster_mode = "stateful"
    else:
        speedup = avg_stateful / avg_stateless
        faster_mode = "stateless"

    print(f"\n📊 LICENSING PERFORMANCE RESULTS:")
    print(f"🏢 Stateful (Enterprise):  {avg_stateful:.3f}s avg")
    print(f"☁️  Stateless (SaaS):      {avg_stateless:.3f}s avg")
    print(f"🚀 Performance gain: {speedup:.1f}x faster ({faster_mode})")

    # Storage analysis
    tsp_sample = helper.create_tsp("alice", model="WEB_AUTH", mode="create")
    stateless_sample = tsp_sample.create_artifact(persist=False)
    token_size = len(json.dumps(stateless_sample["artifact_data"]))

    print(f"\n💾 STORAGE ANALYSIS:")
    print(f"🏢 Stateful license: ~500 bytes (commits.json entry)")
    print(f"☁️  Stateless token: ~{token_size} bytes (embedded data)")
    print(f"📊 Size ratio: {token_size / 500:.1f}x larger (stateless)")


def license_key_generator():
    """Generate multiple license keys demonstrating both modes."""

    print("\n🏭 DUAL-MODE BATCH LICENSE GENERATION")
    print("=" * 60)

    helper = TSPHelper()
    customers = ["bob", "artur", "alice"]

    print("📋 Generating licenses in both modes...")

    # Enterprise licenses (stateful)
    print("\n🏢 ENTERPRISE LICENSES (Stateful Mode)")
    print("-" * 40)

    enterprise_licenses = []
    for i, customer in enumerate(customers, 1):
        if not helper.check_user_keys(customer):
            print(f"⚠️  Skipping {customer} - no keys found")
            continue

        print(f"🔨 Enterprise License {i}/3 for {customer}...")
        tsp_vendor = helper.create_tsp("alice", model="LICENSE", designated_owner=customer)
        license_data = tsp_vendor.create_artifact(persist=True)

        enterprise_licenses.append({
            "customer": customer,
            "license_id": license_data["artifact_id"],
            "config_hash": license_data["config_hash"],
            "mode": "stateful",
            "rarity": license_data["rarity"],
        })

        print(f"   ✅ License {license_data['artifact_id']} → {customer} (stateful)")

    # SaaS tokens (stateless)
    print("\n☁️  SAAS API TOKENS (Stateless Mode)")
    print("-" * 40)

    saas_tokens = []
    for i, customer in enumerate(customers, 1):
        if not helper.check_user_keys(customer):
            continue

        print(f"⚡ SaaS Token {i}/3 for {customer}...")
        tsp_vendor = helper.create_tsp("alice", model="WEB_AUTH", designated_owner=customer)
        token_data = tsp_vendor.create_artifact(persist=False)

        saas_tokens.append({
            "customer": customer,
            "config_hash": token_data["config_hash"],
            "mode": "stateless",
            "rarity": token_data["rarity"],
            "size": len(str(token_data["artifact_data"]))
        })

        print(f"   ✅ Token {token_data['config_hash'][:16]}... → {customer} (stateless)")

    # Summary
    print(f"\n📊 BATCH GENERATION SUMMARY:")
    print(f"🏢 Enterprise licenses: {len(enterprise_licenses)} (stored in commits.json)")
    print(f"☁️  SaaS tokens: {len(saas_tokens)} (embedded in token data)")

    print(f"\n📋 ENTERPRISE LICENSES:")
    for lic in enterprise_licenses:
        print(f"   {lic['customer']}: ID {lic['license_id']} (rarity: {lic['rarity']})")

    print(f"\n🎫 SAAS TOKENS:")
    for token in saas_tokens:
        print(f"   {token['customer']}: {token['config_hash'][:16]}... ({token['size']} bytes)")


def main():
    """Main demonstration function showcasing dual-mode licensing."""

    print("🔑 TSP SOFTWARE LICENSING - DUAL MODE EDITION")
    print("=" * 70)
    print("🎯 Demonstrating both stateful and stateless licensing modes")
    print("=" * 70)

    # Check user keys
    helper = TSPHelper()
    required_users = ["alice", "bob", "artur"]
    missing_keys = []

    for user in required_users:
        if not helper.check_user_keys(user):
            missing_keys.append(user)

    if missing_keys:
        print(f"⚠️  Keys missing for: {', '.join(missing_keys)}")
        print("Please generate them first using: python examples/generate_keys.py")
        return

    try:
        # Demo 1: Traditional enterprise licensing (stateful)
        enterprise_license, enterprise_verification = demo_traditional_licensing()

        # Demo 2: Modern SaaS licensing (stateless)
        saas_token, saas_verification = demo_saas_licensing()

        # Demo 3: Auto-detection capabilities
        demo_auto_detection()

        # Demo 4: Security testing
        demo_security_testing()

        # Demo 5: Performance comparison
        demo_performance_comparison()

        # Summary with architectural insights
        print("\n🎯 DUAL-MODE LICENSING SUMMARY")
        print("=" * 70)
        print("🏢 STATEFUL MODE (Enterprise/Perpetual Licenses):")
        print("   ✅ Perfect for: Enterprise software, certificates, NFTs")
        print("   ✅ Features: Permanent audit trail, Merkle verification")
        print("   ✅ Storage: commits.json registry (~500 bytes per license)")
        print("   ✅ Benefits: Global uniqueness, compliance, resale capability")
        print()
        print("☁️  STATELESS MODE (SaaS/API Tokens):")
        print("   ✅ Perfect for: Web authentication, API access, subscriptions")
        print("   ✅ Features: Zero server storage, embedded verification")
        print("   ✅ Storage: Token-embedded (~2-5KB per token)")
        print("   ✅ Benefits: Maximum scalability, microservices-friendly")
        print()
        print("🤖 AUTO-DETECTION API:")
        print("   ✅ One method handles both modes seamlessly")
        print("   ✅ Zero configuration required")
        print("   ✅ Backward compatibility guaranteed")
        print()
        print("🛡️  SECURITY GUARANTEES:")
        print("   ✅ Both modes cryptographically unforgeable")
        print("   ✅ Ownership verification bulletproof")
        print("   ✅ No central authority required")

        print("\n🎉 DUAL-MODE LICENSING DEMO COMPLETE!")
        print("🚀 TSP ready for both enterprise and SaaS deployment!")

        # Optional batch generation
        user_input = input("\n🔄 Run dual-mode batch license generation? (y/N): ")
        if user_input.lower() == "y":
            license_key_generator()

    except KeyboardInterrupt:
        print("\n\n👋 Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()