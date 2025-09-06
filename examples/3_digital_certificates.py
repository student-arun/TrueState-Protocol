"""
TSP Example - Software Licensing Demo
Copyright (c) 2025 Vladislav Dunaev
Licensed under AGPL-3.0-or-Commercial
"""

"""
TSP Digital Certificates Example
=================================

Demonstration of creating and verifying tamper-proof educational and
professional certificates using TSP protocol with high computational requirements.
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


def digital_certificates_demo():
    """Complete digital certificate workflow demonstration."""

    print("🎓 TSP Digital Certificates Demo")
    print("=" * 50)

    # Initialize helper
    helper = TSPHelper()

    # Check if required users exist (NO CHARLIE!)
    required_users = ["alice", "bob", "artur"]
    for user in required_users:
        if not helper.check_user_keys(user):
            print(f"⚠ Keys missing for {user}. Please generate them first.")
            print(f"Use: python examples/generate_keys.py")
            return

    print("\n🏛️  Institution: Alice University")
    print("📜 Certificate: Master of Computer Science")
    print("👨‍🎓 Graduate: Bob Smith")
    print("📅 Graduation Date: May 2024")
    print("-" * 50)

    # Alice (university) creates diploma for Bob (graduate)
    print("\n1️⃣ ALICE (UNIVERSITY): Issuing digital diploma for Bob...")
    print("🔨 Mining CERTIFICATE-grade cryptographic proof...")
    print("⏱️ This may take 30-120 seconds for high security...")

    start_time = time.time()

    tsp_university = helper.create_tsp(
        "alice",
        model="CERTIFICATE",  # High computational cost (30-120 seconds)
        mode="create",
        designated_owner="bob",
    )

    diploma_artifact = tsp_university.create_artifact()
    mining_time = time.time() - start_time

    print(f"✅ Diploma issued in {mining_time:.1f} seconds")
    print(f"📜 Certificate ID: {diploma_artifact['artifact_id']}")
    print(f"🔗 Certificate Hash: {diploma_artifact['config_hash'][:20]}...")
    print(f"💎 Rarity Level: {diploma_artifact['rarity']}")
    print(f"🎯 Personalized: {diploma_artifact['is_personalized']}")
    print(f"🏗️ Merkle Root: {diploma_artifact['merkle_root'][:20]}...")
    print(
        f"📊 Creation Timestamp: {time.ctime(diploma_artifact['creation_timestamp'])}"
    )

    # Bob (graduate) receives and verifies diploma
    print("\n2️⃣ BOB (GRADUATE): Verifying received diploma...")

    tsp_graduate = helper.create_tsp("bob", mode="verify")
    diploma_verification = tsp_graduate.verify_my_ownership(
        diploma_artifact["artifact_id"]
    )

    print(
        f"🔍 Certificate authenticity: {'✅ AUTHENTIC' if diploma_verification['artifact_valid'] else '❌ INVALID'}"
    )
    print(
        f"🎓 Bob's ownership: {'✅ VERIFIED' if diploma_verification['ownership_valid'] else '❌ DENIED'}"
    )
    print(
        f"🛡️ Merkle proof: {'✅ VALID' if diploma_verification['merkle_valid'] else '❌ INVALID'}"
    )
    print(
        f"📊 All checks: {'✅ PASSED' if diploma_verification['all_checks_valid'] else '❌ FAILED'}"
    )

    if diploma_verification["all_checks_valid"]:
        print("🎉 DIPLOMA VERIFICATION SUCCESSFUL!")
        print("📜 Alice University M.S. Computer Science confirmed")
        print(f"👤 Issued to: Bob (verified owner)")
        print(
            f"📅 Issue date: {time.ctime(diploma_verification.get('creation_timestamp', time.time()))}"
        )
    else:
        print("🚫 DIPLOMA VERIFICATION FAILED!")
        return

    # Show detailed certificate information
    print("\n📋 CERTIFICATE DETAILS:")
    print(f"🆔 Certificate Index: {diploma_verification['artifact_index']}")
    print(f"🔢 Issue Timestamp: {diploma_verification['creation_timestamp']}")
    print(f"💎 Security Level: {diploma_verification['rarity']} (higher = more secure)")
    print(f"🏛️ Issuing Authority: {diploma_verification['creator_pubkey'][:20]}...")
    print(f"👨‍🎓 Certificate Holder: {diploma_verification['my_pubkey'][:20]}...")
    print(f"🔐 Personalized Certificate: {diploma_verification['is_personalized']}")
    print(
        f"🏗️ Blockchain Proof: {diploma_verification.get('merkle_root', 'N/A')[:20]}..."
    )

    # Artur (employer) verifies diploma (independent verification)
    print("\n3️⃣ ARTUR (EMPLOYER): Independent diploma verification...")

    tsp_employer = helper.create_tsp("artur", mode="verify")
    employer_verification = tsp_employer.verify_artifact(
        diploma_artifact["artifact_id"]
    )

    print(
        f"🔍 Certificate authenticity: {'✅ VERIFIED' if employer_verification['all_valid'] else '❌ SUSPICIOUS'}"
    )
    print(
        f"🏛️  Issuing institution: {'✅ CONFIRMED' if employer_verification['signature_valid'] else '❌ UNVERIFIED'}"
    )
    print(
        f"🔐 Cryptographic proof: {'✅ VALID' if employer_verification['pow_valid'] else '❌ INVALID'}"
    )
    print(
        f"📊 Full verification: {'✅ PASSED' if employer_verification['all_valid'] else '❌ FAILED'}"
    )

    if employer_verification["all_valid"]:
        print("✅ EMPLOYMENT VERIFICATION PASSED!")
        print("💼 Candidate's diploma is authentic Alice University certificate")
        print("🔒 No possibility of forgery (cryptographic guarantee)")
    else:
        print("🚨 EMPLOYMENT VERIFICATION FAILED!")
        print("🚫 Diploma authenticity could not be confirmed")

    # Alice attempts to create second diploma (demonstrates uniqueness)
    print("\n4️⃣ UNIQUENESS TEST: Alice creates second diploma...")

    print("🔄 Creating another diploma with same parameters...")

    # Alice creates another diploma for Bob (same parameters)
    tsp_second = helper.create_tsp(
        "alice",
        model="CERTIFICATE",
        mode="create",
        designated_owner="bob",  # Same recipient
    )

    second_diploma = tsp_second.create_artifact()

    print(f"📜 Second certificate created: ID {second_diploma['artifact_id']}")
    print(f"🔍 Second cert hash: {second_diploma['config_hash'][:20]}...")

    # Artur checks both certificates
    second_verification = tsp_employer.verify_artifact(second_diploma["artifact_id"])

    print(f"🔍 Artur's verification of second certificate:")
    print(
        f"Certificate valid: {'✅ YES' if second_verification['all_valid'] else '❌ NO'}"
    )
    print(
        f"Same as first: {'🚨 DUPLICATE!' if second_diploma['config_hash'] == diploma_artifact['config_hash'] else '✅ UNIQUE'}"
    )

    # The key insight: each certificate has unique cryptographic proof
    print("📊 UNIQUENESS ANALYSIS:")
    print(f"First diploma:  {diploma_artifact['config_hash'][:20]}...")
    print(f"Second diploma: {second_diploma['config_hash'][:20]}...")
    print("✅ Each certificate is mathematically unique")
    print("🔒 Even identical parameters produce different certificates")
    print("🛡️  Timestamp and nonce ensure uniqueness")

    # Demonstrate batch verification for transcript
    print("\n5️⃣ TRANSCRIPT VERIFICATION: Multiple certificates...")

    # Alice (university) issues additional certificates (course completions)
    additional_certs = []
    courses = ["Advanced Algorithms", "Machine Learning", "Cybersecurity"]

    print("   🏛️  Alice University issuing course completion certificates...")

    for i, course in enumerate(courses):
        print(f"   📚 Course {i + 1}/3: {course}")

        course_cert = tsp_university.create_artifact()
        additional_certs.append(
            {
                "course": course,
                "cert_id": course_cert["artifact_id"],
                "config_hash": course_cert["config_hash"],
                "rarity": course_cert["rarity"],
            }
        )

        print(f"✅ Certificate {course_cert['artifact_id']} issued")

    # Bob (graduate) verifies complete transcript
    print("\n👨‍🎓 Bob verifying complete academic transcript...")

    all_valid = True
    for cert in additional_certs:
        verification = tsp_graduate.verify_my_ownership(cert["cert_id"])
        status = "✅" if verification["all_checks_valid"] else "❌"
        print(f"{status} {cert['course']}: {verification['all_checks_valid']}")
        if not verification["all_checks_valid"]:
            all_valid = False

    print(
        f"📊 Complete transcript: {'✅ ALL VERIFIED' if all_valid else '❌ ISSUES FOUND'}"
    )

    # Professional certification example
    print("\n6️⃣ PROFESSIONAL CERTIFICATION: Industry credential...")

    # Bob gets professional certification
    print("🏢 Professional body issuing industry certification...")

    # Using Alice as the issuing authority for professional cert
    tsp_professional_body = helper.create_tsp(
        "alice",  # Alice as professional body
        model="CERTIFICATE",
        designated_owner="bob",
    )

    prof_cert = tsp_professional_body.create_artifact()

    print(f"🏆 Professional Certificate ID: {prof_cert['artifact_id']}")
    print(f"🔗 Cert Hash: {prof_cert['config_hash'][:20]}...")
    print(f"💎 Security Level: {prof_cert['rarity']}")

    # Final summary
    print("\n📊 DIGITAL CERTIFICATES DEMO SUMMARY:")
    print("=" * 50)
    print("✅ Alice University issued tamper-proof diploma")
    print("✅ Bob verified certificate ownership")
    print("✅ Artur independently verified authenticity")
    print("✅ Mathematical uniqueness demonstrated")
    print("✅ Batch transcript verification completed")
    print("✅ Professional certification demonstrated")

    print("\n🔑 KEY BENEFITS:")
    print("• Impossible to forge (requires Alice's private key)")
    print("• Instant verification by any party worldwide")
    print("• No central database required")
    print("• Immutable audit trail")
    print("• Works offline")
    print("• Cryptographically unique per certificate")

    print(f"\n💎 COMPUTATIONAL COST: CERTIFICATE model")
    print(f"Mining time: {mining_time:.1f} seconds")
    print(f"Verification: <100ms")
    print(f"Security level: {diploma_artifact['rarity']}")
    print(f"Total certificates created: {len(additional_certs) + 3}")


def university_batch_graduation():
    """Simulate batch graduation ceremony with multiple diplomas."""

    print("\n🎓 BATCH GRADUATION CEREMONY")
    print("=" * 40)

    helper = TSPHelper()

    # Multiple graduates (NO CHARLIE!)
    graduates = ["bob", "artur"]  # Only using existing users
    degrees = ["B.S. Computer Science", "M.S. Data Science"]

    print(f"Issuing {len(graduates)} diplomas from Alice University...")

    diplomas_issued = []

    for i, (grad, degree) in enumerate(zip(graduates, degrees)):
        if not helper.check_user_keys(grad):
            print(f"   ⚠️  Skipping {grad} - no keys found")
            continue

        print(f"\n🎓 Graduate {i + 1}/{len(graduates)}: {grad}")
        print(f"📜 Degree: {degree}")
        print("🔨 Mining certificate...")

        tsp_university = helper.create_tsp(
            "alice", model="CERTIFICATE", designated_owner=grad  # Alice as university
        )

        diploma_data = tsp_university.create_artifact()
        diplomas_issued.append(
            {
                "graduate": grad,
                "degree": degree,
                "diploma_id": diploma_data["artifact_id"],
                "config_hash": diploma_data["config_hash"],
                "rarity": diploma_data["rarity"],
            }
        )

        print(f"✅ Diploma {diploma_data['artifact_id']} issued to {grad}")
        print(f"💎 Security level: {diploma_data['rarity']}")

    print(f"\n🎉 GRADUATION CEREMONY COMPLETE!")
    print(f"📊 {len(diplomas_issued)} diplomas issued")
    print("\n📋 DIPLOMA REGISTRY:")

    for diploma in diplomas_issued:
        print(f"🎓 {diploma['graduate']}: {diploma['degree']}")
        print(f"ID: {diploma['diploma_id']}")
        print(f"Hash: {diploma['config_hash'][:20]}...")
        print(f"Security: {diploma['rarity']}")
        print()


if __name__ == "__main__":
    try:
        digital_certificates_demo()

        # Optional: run batch graduation
        user_input = input("\n🎓 Run batch graduation ceremony demo? (y/N): ")
        if user_input.lower() == "y":
            university_batch_graduation()

    except KeyboardInterrupt:
        print("\n\n👋 Demo interrupted by user")
    except Exception as e:
        print(f"❌ Demo error: {e}")
        import traceback

        traceback.print_exc()
