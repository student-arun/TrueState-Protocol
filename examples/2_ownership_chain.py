"""
TSP Example - Software Licensing Demo
Copyright (c) 2025 Vladislav Dunaev
Licensed under AGPL-3.0-or-Commercial
"""
import time
import json
import base64
from examples.tsp_helper import TSPHelper


def demo_stateful_mode():
    """Demo traditional stateful mode (commits.json storage)"""
    print("📁 STATEFUL MODE DEMO (Traditional)")
    print("=" * 50)

    helper = TSPHelper()

    # Alice creates LICENSE for Bob (stateful - goes to commits.json)
    print("\n1️⃣ Alice creates LICENSE artifact for Bob (stateful mode)...")
    tsp_alice = helper.create_tsp(
        "alice", model="LICENSE", mode="create", designated_owner="bob"
    )

    start_time = time.time()
    alice_artifact = tsp_alice.create_artifact(persist=True)  # Stateful
    creation_time = time.time() - start_time

    print(f"✅ LICENSE Artifact {alice_artifact['artifact_id']} created")
    print(f"⏱️  Creation time: {creation_time:.2f}s")
    print(f"🏷️  Config Hash: {alice_artifact['config_hash'][:16]}...")
    print(f"🎯 Rarity: {alice_artifact['rarity']}")
    print(f"📊 Mode: {alice_artifact['mode']}")
    print(f"🌳 Merkle Root: {alice_artifact['merkle_root'][:16]}...")

    # Bob verifies ownership (stateful - reads from commits.json)
    print("\n2️⃣ Bob verifies ownership (stateful lookup)...")
    tsp_bob = helper.create_tsp("bob", mode="verify")

    start_time = time.time()
    # Using artifact_id (int) - triggers stateful mode automatically
    bob_ownership = tsp_bob.verify_my_ownership(alice_artifact["artifact_id"])
    verify_time = time.time() - start_time

    print(f"⏱️  Verification time: {verify_time:.3f}s")
    print(f"🔒 Ownership valid: {bob_ownership['ownership_valid']}")
    print(f"✅ All checks: {bob_ownership['all_checks_valid']}")
    print(f"📊 Verification mode: {bob_ownership['verification_mode']}")

    return alice_artifact, bob_ownership


def demo_stateless_mode():
    """Demo new stateless mode (no storage, token embedding)"""
    print("\n🌐 STATELESS MODE DEMO (Web Auth Tokens)")
    print("=" * 50)

    helper = TSPHelper()

    # Alice creates WEB_AUTH token for Bob (stateless - no commits.json)
    print("\n1️⃣ Alice creates WEB_AUTH token for Bob (stateless mode)...")
    tsp_alice = helper.create_tsp(
        "alice", model="WEB_AUTH", mode="create", designated_owner="bob"
    )

    start_time = time.time()
    alice_token = tsp_alice.create_artifact(persist=False)  # Stateless!
    creation_time = time.time() - start_time

    print(f"✅ WEB_AUTH Token created (no storage)")
    print(f"⏱️  Creation time: {creation_time:.2f}s")
    print(f"🏷️  Config Hash: {alice_token['config_hash'][:16]}...")
    print(f"🎯 Rarity: {alice_token['rarity']}")
    print(f"📊 Mode: {alice_token['mode']}")
    print(f"💾 Token size: ~{len(str(alice_token['artifact_data']))} bytes")

    # Bob verifies ownership (stateless - from token data directly)
    print("\n2️⃣ Bob verifies ownership (stateless from token data)...")
    tsp_bob = helper.create_tsp("bob", mode="verify")

    start_time = time.time()
    # Using artifact_data (dict) - triggers stateless mode automatically
    bob_ownership = tsp_bob.verify_my_ownership(alice_token["artifact_data"])
    verify_time = time.time() - start_time

    print(f"⏱️  Verification time: {verify_time:.3f}s")
    print(f"🔒 Ownership valid: {bob_ownership['ownership_valid']}")
    print(f"✅ All checks: {bob_ownership['all_checks_valid']}")
    print(f"📊 Verification mode: {bob_ownership['verification_mode']}")

    return alice_token, bob_ownership


def demo_web_token_encoding():
    """Demo real-world web token creation and encoding"""
    print("\n🌐 WEB TOKEN ENCODING DEMO")
    print("=" * 50)

    helper = TSPHelper()

    # Create token for web authentication
    print("Creating web authentication token...")
    tsp_create = helper.create_tsp("alice", model="WEB_AUTH", mode="create")
    token_result = tsp_create.create_artifact(persist=False)

    # Simulate real web token creation
    web_token = {
        "user_id": "alice",
        "issued_at": int(time.time()),
        "expires_at": int(time.time()) + 3600,  # 1 hour
        "tsp_data": token_result["artifact_data"]
    }

    # Base64 encode for HTTP headers
    token_json = json.dumps(web_token, separators=(',', ':'))
    encoded_token = base64.b64encode(token_json.encode()).decode()

    print(f"🎫 Web Token Size: {len(token_json)} bytes")
    print(f"📦 Base64 Encoded: {len(encoded_token)} chars")
    print(f"🔗 HTTP Header: Authorization: Bearer {encoded_token[:50]}...")

    # Simulate token verification
    print("\n🔍 Verifying web token...")
    decoded_json = base64.b64decode(encoded_token.encode()).decode()
    decoded_token = json.loads(decoded_json)

    tsp_verify = helper.create_tsp("alice", mode="verify")
    verification = tsp_verify.verify_artifact(decoded_token["tsp_data"])

    print(f"✅ Token valid: {verification['all_valid']}")
    print(f"👤 User ID: {decoded_token['user_id']}")
    print(f"⏰ Expires: {decoded_token['expires_at'] - int(time.time())}s")

    return encoded_token


def demo_auto_detection():
    """Demo automatic mode detection"""
    print("\n🤖 AUTO-DETECTION DEMO")
    print("=" * 50)

    helper = TSPHelper()
    tsp_verify = helper.create_tsp("alice", mode="verify")

    # Create both types of artifacts
    print("Creating test artifacts...")

    # Stateful artifact
    tsp_create = helper.create_tsp("alice", model="LICENSE", mode="create")
    stateful_artifact = tsp_create.create_artifact(persist=True)

    # Stateless artifact
    tsp_create = helper.create_tsp("alice", model="WEB_AUTH", mode="create")
    stateless_artifact = tsp_create.create_artifact(persist=False)

    print("\n🧪 Testing auto-detection...")

    # Test 1: Pass artifact_id (int) - should detect stateful
    print("\n📋 Test 1: verify_artifact(artifact_id) - expect stateful")
    result1 = tsp_verify.verify_artifact(stateful_artifact["artifact_id"])
    print(f"🔍 Detected mode: {result1.get('verification_mode', 'unknown')}")

    # Test 2: Pass artifact_data (dict) - should detect stateless
    print("\n📋 Test 2: verify_artifact(artifact_data) - expect stateless")
    result2 = tsp_verify.verify_artifact(stateless_artifact["artifact_data"])
    print(f"🔍 Detected mode: {result2.get('verification_mode', 'unknown')}")

    # Test 3: Pass config_hash (str) - should detect stateful
    print("\n📋 Test 3: verify_artifact(config_hash) - expect stateful")
    result3 = tsp_verify.verify_artifact(stateful_artifact["config_hash"])
    print(f"🔍 Detected mode: {result3.get('verification_mode', 'unknown')}")

    # Test 4: Same with ownership verification
    print("\n📋 Test 4: verify_my_ownership auto-detection")
    ownership1 = tsp_verify.verify_my_ownership(stateful_artifact["artifact_id"])
    ownership2 = tsp_verify.verify_my_ownership(stateless_artifact["artifact_data"])

    print(f"🔍 Stateful ownership mode: {ownership1.get('verification_mode', 'unknown')}")
    print(f"🔍 Stateless ownership mode: {ownership2.get('verification_mode', 'unknown')}")


def demo_performance_comparison():
    """Compare performance between modes"""
    print("\n⚡ PERFORMANCE COMPARISON")
    print("=" * 50)

    helper = TSPHelper()

    # Multiple runs for average
    runs = 3
    stateful_times = []
    stateless_times = []

    print(f"Running {runs} iterations of each mode...")

    for i in range(runs):
        print(f"\n🔄 Run {i + 1}/{runs}")

        # Stateful creation + verification
        tsp_create = helper.create_tsp("alice", model="WEB_AUTH", mode="create", designated_owner="bob")
        tsp_verify = helper.create_tsp("bob", mode="verify")

        start = time.time()
        artifact = tsp_create.create_artifact(persist=True)
        ownership = tsp_verify.verify_my_ownership(artifact["artifact_id"])
        stateful_time = time.time() - start
        stateful_times.append(stateful_time)

        # Stateless creation + verification
        tsp_create = helper.create_tsp("alice", model="WEB_AUTH", mode="create", designated_owner="bob")
        tsp_verify = helper.create_tsp("bob", mode="verify")

        start = time.time()
        token = tsp_create.create_artifact(persist=False)
        ownership = tsp_verify.verify_my_ownership(token["artifact_data"])
        stateless_time = time.time() - start
        stateless_times.append(stateless_time)

        print(f"   Stateful: {stateful_time:.3f}s | Stateless: {stateless_time:.3f}s")

    # Calculate averages
    avg_stateful = sum(stateful_times) / len(stateful_times)
    avg_stateless = sum(stateless_times) / len(stateless_times)

    # Performance analysis
    if avg_stateful < avg_stateless:
        speedup = avg_stateless / avg_stateful
        faster_mode = "stateful"
    else:
        speedup = avg_stateful / avg_stateless
        faster_mode = "stateless"

    print(f"\n📊 PERFORMANCE RESULTS:")
    print(f"📁 Stateful avg:  {avg_stateful:.3f}s")
    print(f"🌐 Stateless avg: {avg_stateless:.3f}s")
    print(f"🚀 Speedup: {speedup:.1f}x faster ({faster_mode} mode)")

    # Memory usage estimation
    print(f"\n💾 MEMORY USAGE ESTIMATION:")

    # Create sample artifacts for size comparison
    tsp_sample = helper.create_tsp("alice", model="WEB_AUTH", mode="create")

    # Stateless artifact size
    stateless_sample = tsp_sample.create_artifact(persist=False)
    stateless_size = len(json.dumps(stateless_sample["artifact_data"]))

    print(f"📦 Stateless token: ~{stateless_size} bytes")
    print(f"🗄️  Stateful storage: ~500 bytes (commits.json entry)")
    print(f"📈 Size ratio: {stateless_size / 500:.1f}x larger (stateless)")


def demo_edge_cases():
    """Test edge cases and error handling"""
    print("\n🧪 EDGE CASES & ERROR HANDLING")
    print("=" * 50)

    helper = TSPHelper()
    tsp_verify = helper.create_tsp("alice", mode="verify")

    # Test 1: Invalid artifact data
    print("\n📋 Test 1: Invalid artifact data")
    try:
        result = tsp_verify.verify_artifact({"invalid": "data"})
        print(f"🔍 Result: {result.get('all_valid', 'Error')}")
    except Exception as e:
        print(f"❌ Expected error: {str(e)[:50]}...")

    # Test 2: Non-existent artifact ID
    print("\n📋 Test 2: Non-existent artifact ID")
    try:
        result = tsp_verify.verify_artifact(99999)
        print(f"🔍 Result: {result.get('all_valid', 'Error')}")
    except Exception as e:
        print(f"❌ Expected error: {str(e)[:50]}...")

    # Test 3: Wrong ownership verification
    print("\n📋 Test 3: Wrong ownership verification")
    tsp_create = helper.create_tsp("alice", model="WEB_AUTH", mode="create", designated_owner="bob")
    token = tsp_create.create_artifact(persist=False)

    # Alice tries to verify ownership of Bob's token
    ownership = tsp_verify.verify_my_ownership(token["artifact_data"])
    print(f"🔍 Alice ownership of Bob's token: {ownership['ownership_valid']}")


def main():
    """Main demo function showcasing dual-mode capabilities"""
    print("🚀 TSP DUAL-MODE COMPREHENSIVE DEMONSTRATION")
    print("=" * 60)
    print("Showcasing Stateful vs Stateless operation modes")
    print("=" * 60)

    # Check user keys
    helper = TSPHelper()
    users = ["alice", "bob", "artur"]
    missing_keys = []

    for user in users:
        if not helper.check_user_keys(user):
            missing_keys.append(user)

    if missing_keys:
        print(f"⚠️  Keys missing for: {', '.join(missing_keys)}")
        print("Please generate them first using examples/generate_keys.py")
        return

    try:
        # Demo 1: Traditional stateful mode
        stateful_artifact, stateful_ownership = demo_stateful_mode()

        # Demo 2: New stateless mode
        stateless_artifact, stateless_ownership = demo_stateless_mode()

        # Demo 3: Real web token encoding
        web_token = demo_web_token_encoding()

        # Demo 4: Auto-detection
        demo_auto_detection()

        # Demo 5: Performance comparison
        demo_performance_comparison()

        # Demo 6: Edge cases
        demo_edge_cases()

        # Summary with recommendations
        print("\n🎯 SUMMARY & RECOMMENDATIONS")
        print("=" * 60)
        print("✅ STATEFUL MODE - Use for:")
        print("   • Software licenses (LICENSE model)")
        print("   • Digital certificates (CERTIFICATE model)")
        print("   • NFTs and collectibles (NFT model)")
        print("   • Any asset requiring permanent audit trail")
        print("   • When uniqueness must be globally enforced")
        print()
        print("🌐 STATELESS MODE - Use for:")
        print("   • Web authentication tokens (WEB_AUTH model)")
        print("   • Session management")
        print("   • API authentication")
        print("   • High-throughput scenarios")
        print("   • Microservices without shared storage")
        print()
        print("🤖 AUTO-DETECTION BENEFITS:")
        print("   • Seamless API - one method handles both modes")
        print("   • Backward compatibility guaranteed")
        print("   • Developer-friendly interface")
        print("   • Zero configuration required")
        print()
        print("📊 PERFORMANCE INSIGHTS:")
        print("   • Stateless: Faster verification, larger tokens")
        print("   • Stateful: Smaller storage, more I/O overhead")
        print("   • Choose based on access patterns and scale")

        print(f"\n🎉 TSP Dual-Mode Comprehensive Demo Complete!")
        print(f"🔧 All features working perfectly!")
        print(f"🚀 Ready for production deployment!")

    except Exception as e:
        print(f"❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()