"""
TSP Example - Software Licensing Demo
Copyright (c) 2025 Vladislav Dunaev
Licensed under AGPL-3.0-or-Commercial
"""

from examples.tsp_helper import TSPHelper


def main():
    print("🚀 TSP Ownership Chain Example")
    print("=" * 50)

    # Initialize helper
    helper = TSPHelper()

    # Check user keys
    users = ["alice", "bob", "artur"]
    for user in users:
        if not helper.check_user_keys(user):
            print(f"⚠️  Keys missing for {user}. Please generate them first.")
            return

    print("\n📝 Creating ownership chain: Alice → Bob → Artur")
    print("-" * 50)

    # Alice creates artifact for Bob
    print("\n1️⃣ Alice creates artifact for Bob...")
    tsp_alice = helper.create_tsp(
        "alice", model="WEB_AUTH", mode="create", designated_owner="bob"
    )
    alice_artifact_result = tsp_alice.create_artifact()
    print(f"✅ Artifact {alice_artifact_result['artifact_id']} created for Bob")
    print(f"Config Hash: {alice_artifact_result['config_hash'][:16]}...")
    print(f"Rarity: {alice_artifact_result['rarity']}")

    # Bob verifies ownership
    print("\n2️⃣ Bob verifies ownership...")
    tsp_bob_verify = helper.create_tsp("bob", mode="verify")
    bob_ownership_results = tsp_bob_verify.verify_my_ownership(
        alice_artifact_result["artifact_id"]
    )

    print(f"Artifact valid: {bob_ownership_results['artifact_valid']}")
    print(f"Ownership valid: {bob_ownership_results['ownership_valid']}")
    print(f"All checks: {bob_ownership_results['all_checks_valid']}")

    if not bob_ownership_results["ownership_valid"]:
        print("❌ Bob ownership verification failed!")
        return

    # Bob creates artifact for Artur
    print("\n3️⃣ Bob creates artifact for Artur...")
    tsp_bob_create = helper.create_tsp(
        "bob", model="WEB_AUTH", mode="create", designated_owner="artur"
    )
    bob_artifact_result = tsp_bob_create.create_artifact()
    print(f"✅ Artifact {bob_artifact_result['artifact_id']} created for Artur")
    print(f"Config Hash: {bob_artifact_result['config_hash'][:16]}...")
    print(f"Rarity: {bob_artifact_result['rarity']}")

    # Artur verifies ownership
    print("\n4️⃣ Artur verifies ownership...")
    tsp_artur_verify = helper.create_tsp("artur", mode="verify")
    artur_ownership_results = tsp_artur_verify.verify_my_ownership(
        bob_artifact_result["artifact_id"]
    )

    print(f"Artifact valid: {artur_ownership_results['artifact_valid']}")
    print(f"Ownership valid: {artur_ownership_results['ownership_valid']}")
    print(f"All checks: {artur_ownership_results['all_checks_valid']}")

    # Final report
    print("\n📊 Final Report:")
    print("-" * 30)
    print(
        f"✅ Alice → Bob: {'SUCCESS' if bob_ownership_results['all_checks_valid'] else 'FAILED'}"
    )
    print(
        f"✅ Bob → Artur: {'SUCCESS' if artur_ownership_results['all_checks_valid'] else 'FAILED'}"
    )

    # Additional cross-checks
    print("\n🔍 Cross-verification tests:")

    # Artur tries to verify Bob's artifact (should fail)
    print("Testing Artur with Bob's artifact (should fail)...")
    artur_wrong_ownership = tsp_artur_verify.verify_my_ownership(
        alice_artifact_result["artifact_id"]
    )
    print(
        f"❌ Artur vs Alice→Bob artifact: {'FAILED' if not artur_wrong_ownership['ownership_valid'] else 'UNEXPECTED SUCCESS'}"
    )

    # Alice tries to verify Artur's artifact (should fail)
    print("Testing Alice with Artur's artifact (should fail)...")
    tsp_alice_verify = helper.create_tsp("alice", mode="verify")
    alice_wrong_ownership = tsp_alice_verify.verify_my_ownership(
        bob_artifact_result["artifact_id"]
    )
    print(
        f"❌ Alice vs Bob→Artur artifact: {'FAILED' if not alice_wrong_ownership['ownership_valid'] else 'UNEXPECTED SUCCESS'}"
    )

    print("\n🎉 TSP Ownership Chain Demo Complete!")


if __name__ == "__main__":
    main()
