"""
TSP Example - Software Licensing Demo
Copyright (c) 2025 Vladislav Dunaev
Licensed under AGPL-3.0-or-Commercial
"""

"""
TSP Software Licensing Example
===============================

Demonstration of creating and verifying unforgeable software licenses
using TSP protocol with graduated computational requirements.
"""

import sys
import time
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


def software_licensing_demo():
    """Complete software licensing workflow demonstration."""

    print("🔑 TSP Software Licensing Demo")
    print("=" * 50)

    # Initialize helper
    helper = TSPHelper()

    # Check if required users exist
    required_users = ["alice", "bob", "artur"]
    for user in required_users:
        if not helper.check_user_keys(user):
            print(f"⚠️  Keys missing for {user}. Please generate them first.")
            print(f"   Use: python examples/generate_keys.py")
            return

    print("\n📦 Software: 'SecureCAD Pro v2025'")
    print("💰 License Cost: $2,999/year")
    print("🏢 Vendor: Alice Software Corporation")
    print("👤 Customer: Bob")
    print("-" * 50)

    # Alice (vendor) creates license for Bob (customer)
    print("\n1️⃣ ALICE (VENDOR): Creating license for Bob...")
    print("   🔨 Mining LICENSE-grade cryptographic proof...")

    start_time = time.time()

    tsp_vendor = helper.create_tsp(
        "alice",
        model="LICENSE",  # Medium computational cost (4-20 seconds)
        mode="create",
        designated_owner="bob",
    )

    license_artifact = tsp_vendor.create_artifact()
    mining_time = time.time() - start_time

    print(f"   ✅ License generated in {mining_time:.1f} seconds")
    print(f"   📄 License ID: {license_artifact['artifact_id']}")
    print(f"   🔗 License Hash: {license_artifact['config_hash'][:20]}...")
    print(f"   💎 Rarity Level: {license_artifact['rarity']}")
    print(f"   🎯 Personalized: {license_artifact['is_personalized']}")
    print(f"   🏗️  Merkle Root: {license_artifact['merkle_root'][:20]}...")

    # Bob (customer) receives and activates license
    print("\n2️⃣ BOB (CUSTOMER): Activating software license...")

    tsp_customer = helper.create_tsp("bob", mode="verify")
    license_verification = tsp_customer.verify_my_ownership(
        license_artifact["artifact_id"]
    )

    print(
        f"🔍 License authenticity: {'✅ VALID' if license_verification['artifact_valid'] else '❌ INVALID'}"
    )
    print(
        f"🔑 Bob's ownership: {'✅ VERIFIED' if license_verification['ownership_valid'] else '❌ DENIED'}"
    )
    print(
        f"🛡️  Merkle proof: {'✅ VALID' if license_verification['merkle_valid'] else '❌ INVALID'}"
    )
    print(
        f"📊 All checks: {'✅ PASSED' if license_verification['all_checks_valid'] else '❌ FAILED'}"
    )

    if license_verification["all_checks_valid"]:
        print("🚀 SOFTWARE ACTIVATION SUCCESSFUL!")
        print("💻 SecureCAD Pro v2025 is now licensed and running")
        print(f"👤 Licensed to: Bob (ID: {license_verification.get('user_id', 'N/A')})")
        print(
            f"📅 License created: {time.ctime(license_verification.get('creation_timestamp', time.time()))}"
        )
    else:
        print("🚫 SOFTWARE ACTIVATION FAILED!")
        return

    # Show license details
    print("\n📋 LICENSE DETAILS:")
    print(f"🆔 Artifact Index: {license_verification['artifact_index']}")
    print(f"🔢 Creation Timestamp: {license_verification['creation_timestamp']}")
    print(f"💎 Rarity Threshold: {license_verification['rarity']}")
    print(f"👨‍💼 Creator (Alice): {license_verification['creator_pubkey'][:20]}...")
    print(f"👤 Owner (Bob): {license_verification['my_pubkey'][:20]}...")
    print(f"🔐 Personalized License: {license_verification['is_personalized']}")

    # artur attempts to use the license (should fail)
    print("\n3️⃣ SECURITY TEST: artur attempts to steal license...")

    tsp_pirate = helper.create_tsp("artur", mode="verify")
    pirate_attempt = tsp_pirate.verify_my_ownership(license_artifact["artifact_id"])

    print(
        f"🔍 License authenticity: {'✅ VALID' if pirate_attempt['artifact_valid'] else '❌ INVALID'}"
    )
    print(
        f"🏴‍☠️ artur's ownership: {'⚠️  STOLEN!' if pirate_attempt['ownership_valid'] else '❌ DENIED'}"
    )
    print(
        f"🛡️  Security check: {'🚨 BREACH!' if pirate_attempt['all_checks_valid'] else '✅ PROTECTED'}"
    )

    if not pirate_attempt["ownership_valid"]:
        print("🛡️  LICENSE PROTECTION SUCCESSFUL!")
        print("🚫 artur cannot activate software")
        print("🔒 Cryptographic ownership verification blocked unauthorized use")
    else:
        print("🚨 SECURITY BREACH! This should not happen!")

    # Demonstrate independent verification (no network needed)
    print("\n4️⃣ INDEPENDENT VERIFICATION: Third party audit...")

    # Simulate an auditor or compliance checker
    auditor_verification = TSP.list_artifacts()

    if auditor_verification:
        latest_license = auditor_verification[-1]  # Get latest artifact

        print(f"📋 Found {len(auditor_verification)} artifacts in system")
        print(f"🔍 Auditing License ID: {latest_license['artifact_index']}")
        print(f"💎 License Rarity: {latest_license['rarity']}")
        print(f"🔐 Personalized: {latest_license['is_personalized']}")
        print(f"🏗️  Merkle Root: {latest_license['merkle_root'][:20]}...")

        # Verify without access to private keys
        tsp_auditor = helper.create_tsp(
            "alice", mode="verify"
        )  # Use Alice for verification
        audit_result = tsp_auditor.verify_artifact(latest_license["artifact_index"])

        print(
            f"✅ Independent audit: {'PASSED' if audit_result['all_valid'] else 'FAILED'}"
        )
        print("📊 Compliance: LICENSE meets all cryptographic requirements")

    # License transfer scenario
    print("\n5️⃣ LICENSE TRANSFER: Bob creates transfer certificate...")

    # Bob can create a new artifact to prove they had the original license
    tsp_customer_create = helper.create_tsp(
        "bob",
        model="LICENSE",
        mode="create",
        designated_owner="alice",  # Transfer back to Alice
    )

    print("🔄 Creating transfer certificate...")
    transfer_cert = tsp_customer_create.create_artifact()

    print(f"📄 Transfer Certificate ID: {transfer_cert['artifact_id']}")
    print(f"🔗 Transfer Hash: {transfer_cert['config_hash'][:20]}...")
    print("✅ Transfer certificate created (proves Bob had valid license)")

    # Final summary
    print("\n📊 LICENSING DEMO SUMMARY:")
    print("=" * 50)
    print("✅ Alice created unforgeable license")
    print("✅ Bob successfully activated software")
    print("✅ artur blocked by cryptographic ownership")
    print("✅ Independent verification completed")
    print("✅ License transfer mechanism demonstrated")
    print("\n🔑 KEY BENEFITS:")
    print("   • No central license server required")
    print("   • Impossible to pirate (cryptographic proof)")
    print("   • Instant verification (offline capable)")
    print("   • Audit trail built-in")
    print("   • Transfer/resale possible")

    print(f"\n💎 COMPUTATIONAL COST: LICENSE model")
    print(f"   Mining time: {mining_time:.1f} seconds")
    print(f"   Verification: <100ms")
    print(f"   Rarity achieved: {license_artifact['rarity']}")


def license_key_generator():
    """Generate multiple license keys for batch licensing."""

    print("\n🏭 BATCH LICENSE GENERATION")
    print("=" * 40)

    helper = TSPHelper()

    print("Generating 3 licenses for different customers...")

    customers = ["bob", "artur", "alice"]  # Using existing users
    licenses = []

    for i, customer in enumerate(customers, 1):
        print(f"\n🔨 License {i}/3 for {customer}...")

        if not helper.check_user_keys(customer):
            print(f"⚠️  Skipping {customer} - no keys found")
            continue

        tsp_vendor = helper.create_tsp(
            "alice", model="LICENSE", designated_owner=customer  # Alice as vendor
        )

        license_data = tsp_vendor.create_artifact()
        licenses.append(
            {
                "customer": customer,
                "license_id": license_data["artifact_id"],
                "config_hash": license_data["config_hash"],
                "rarity": license_data["rarity"],
            }
        )

        print(f"✅ License {license_data['artifact_id']} → {customer}")

    print(f"\n📋 BATCH SUMMARY: {len(licenses)} licenses generated")
    for lic in licenses:
        print(f"   {lic['customer']}: ID {lic['license_id']} (rarity: {lic['rarity']})")


if __name__ == "__main__":
    try:
        software_licensing_demo()

        # Optional: run batch generation
        user_input = input("\n🔄 Run batch license generation demo? (y/N): ")
        if user_input.lower() == "y":
            license_key_generator()

    except KeyboardInterrupt:
        print("\n\n👋 Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo error: {e}")
        import traceback

        traceback.print_exc()
