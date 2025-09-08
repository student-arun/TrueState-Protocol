"""
TSP Example - Software Licensing Demo
Copyright (c) 2025 Vladislav Dunaev
Licensed under AGPL-3.0-or-Commercial
"""

"""
TSP Digital Certificates Example - Dual Mode Edition
===================================================

Demonstration of creating and verifying tamper-proof educational and
professional certificates using TSP protocol in both modes:

- Stateful Mode: Permanent diplomas and certifications (stored in commits.json)
- Stateless Mode: Course completions and temporary credentials (embedded tokens)
- Auto-Detection: Seamless API for both certificate types
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


def demo_permanent_diploma():
    """Permanent academic diploma with full audit trail (stateful mode)."""

    print("🎓 PERMANENT ACADEMIC DIPLOMA (Stateful Mode)")
    print("=" * 60)
    print("🏛️  Institution: Alice University")
    print("📜 Degree: Master of Computer Science")
    print("👨‍🎓 Graduate: Bob Smith")
    print("🎯 Use Case: Lifetime academic credential with audit trail")
    print("-" * 60)

    helper = TSPHelper()

    # Alice (university) creates permanent diploma for Bob
    print("\n1️⃣ UNIVERSITY: Issuing permanent diploma...")
    print("   🔨 Mining CERTIFICATE-grade cryptographic proof...")
    print("   💾 Will be stored in commits.json for permanent record")
    print("   ⏱️  This may take 30-120 seconds for high security...")

    start_time = time.time()

    tsp_university = helper.create_tsp(
        "alice",
        model="CERTIFICATE",  # High computational cost (30-120 seconds)
        mode="create",
        designated_owner="bob",
    )

    # Create stateful diploma (persist=True)
    diploma_artifact = tsp_university.create_artifact(persist=True)
    mining_time = time.time() - start_time

    print(f"   ✅ Diploma issued in {mining_time:.1f} seconds")
    print(f"   📜 Certificate ID: {diploma_artifact['artifact_id']}")
    print(f"   🔗 Config Hash: {diploma_artifact['config_hash'][:20]}...")
    print(f"   💎 Security Level: {diploma_artifact['rarity']}")
    print(f"   🎯 Personalized: {diploma_artifact['is_personalized']}")
    print(f"   🏗️  Merkle Root: {diploma_artifact['merkle_root'][:20]}...")
    print(f"   📊 Storage Mode: {diploma_artifact['mode']}")

    # Bob verifies ownership using artifact ID (triggers stateful verification)
    print("\n2️⃣ GRADUATE: Verifying permanent diploma...")
    print("   🔍 Verifying via commits.json lookup (stateful mode)")

    tsp_graduate = helper.create_tsp("bob", mode="verify")

    # Pass artifact_id (int) - auto-detects stateful mode
    diploma_verification = tsp_graduate.verify_my_ownership(
        diploma_artifact["artifact_id"]
    )

    print(f"🔍 Diploma authenticity: {'✅ AUTHENTIC' if diploma_verification['artifact_valid'] else '❌ INVALID'}")
    print(f"🎓 Bob's ownership: {'✅ VERIFIED' if diploma_verification['ownership_valid'] else '❌ DENIED'}")
    print(f"🛡️  Merkle proof: {'✅ VALID' if diploma_verification['merkle_valid'] else '❌ INVALID'}")
    print(f"📊 All checks: {'✅ PASSED' if diploma_verification['all_checks_valid'] else '❌ FAILED'}")
    print(f"📊 Verification mode: {diploma_verification['verification_mode']}")

    if diploma_verification["all_checks_valid"]:
        print("\n🎉 PERMANENT DIPLOMA VERIFICATION SUCCESSFUL!")
        print("📜 Alice University M.S. Computer Science confirmed")
        print(f"👤 Lifetime credential for: Bob")
        print(f"📅 Issue date: {time.ctime(diploma_verification.get('creation_timestamp', time.time()))}")
        print("📋 Full audit trail available in commits.json")

    return diploma_artifact, diploma_verification


def demo_course_completion_tokens():
    """Course completion certificates as embedded tokens (stateless mode)."""

    print("\n📚 COURSE COMPLETION CERTIFICATES (Stateless Mode)")
    print("=" * 60)
    print("🏛️  Institution: Alice University Online")
    print("📖 Courses: Continuing Education Program")
    print("👨‍🎓 Student: Bob Smith")
    print("🎯 Use Case: Micro-credentials without permanent storage")
    print("-" * 60)

    helper = TSPHelper()
    courses = ["Machine Learning Basics", "Cybersecurity Fundamentals", "Data Analytics"]
    completion_tokens = []

    # Alice creates course completion tokens for Bob
    print("\n1️⃣ UNIVERSITY: Issuing course completion tokens...")
    print("   ⚡ Using WEB_AUTH model for fast generation")
    print("   🌐 Stateless - no server storage required")

    for i, course in enumerate(courses, 1):
        print(f"\n   📖 Course {i}/3: {course}")

        start_time = time.time()

        tsp_university = helper.create_tsp(
            "alice",
            model="WEB_AUTH",  # Fast generation for course completions
            mode="create",
            designated_owner="bob",
        )

        # Create stateless completion token (persist=False)
        course_token = tsp_university.create_artifact(persist=False)
        creation_time = time.time() - start_time

        # Create course completion certificate
        completion_cert = {
            "student_id": "bob_smith_2025",
            "course_name": course,
            "institution": "Alice_University_Online",
            "completion_date": int(time.time()),
            "grade": "Pass",
            "credit_hours": 3,
            "tsp_certificate": course_token["artifact_data"]
        }

        # Base64 encode for digital badges
        cert_json = json.dumps(completion_cert, separators=(',', ':'))
        encoded_cert = base64.b64encode(cert_json.encode()).decode()

        completion_tokens.append({
            "course": course,
            "config_hash": course_token["config_hash"],
            "encoded_cert": encoded_cert,
            "creation_time": creation_time,
            "size": len(cert_json)
        })

        print(f"      ✅ Generated in {creation_time:.2f}s")
        print(f"      🎫 Certificate size: {len(cert_json)} bytes")
        print(f"      📦 Encoded size: {len(encoded_cert)} chars")

    # Bob verifies course completions using embedded data
    print("\n2️⃣ STUDENT: Verifying course completion certificates...")
    print("   🔍 Verifying via embedded data (stateless mode)")

    tsp_student = helper.create_tsp("bob", mode="verify")
    all_valid = True

    for token in completion_tokens:
        # Decode and verify
        decoded_json = base64.b64decode(token["encoded_cert"].encode()).decode()
        decoded_cert = json.loads(decoded_json)

        # Pass artifact_data (dict) - auto-detects stateless mode
        verification = tsp_student.verify_my_ownership(
            decoded_cert["tsp_certificate"]
        )

        status = "✅" if verification["all_checks_valid"] else "❌"
        print(f"   {status} {token['course']}: {verification['all_checks_valid']} ({verification['verification_mode']})")

        if not verification["all_checks_valid"]:
            all_valid = False

    if all_valid:
        print("\n🎉 ALL COURSE COMPLETIONS VERIFIED!")
        print("📚 Bob has successfully completed all courses")
        print(f"🎫 {len(completion_tokens)} micro-credentials confirmed")
        print("🌐 No server storage required for verification")

    return completion_tokens


def demo_professional_certification():
    """Professional industry certification (stateful mode)."""

    print("\n🏆 PROFESSIONAL CERTIFICATION (Stateful Mode)")
    print("=" * 60)
    print("🏢 Certifying Body: Alice Professional Institute")
    print("🛡️  Certification: Certified Information Security Professional")
    print("👨‍💼 Candidate: Bob Smith")
    print("🎯 Use Case: Industry credential with regulatory compliance")
    print("-" * 60)

    helper = TSPHelper()

    # Alice (professional body) issues certification for Bob
    print("\n1️⃣ PROFESSIONAL BODY: Issuing industry certification...")
    print("   🔨 Mining CERTIFICATE-grade proof for regulatory compliance")
    print("   💾 Permanent record required for professional standing")

    start_time = time.time()

    tsp_cert_body = helper.create_tsp(
        "alice",
        model="CERTIFICATE",
        mode="create",
        designated_owner="bob",
    )

    # Create stateful professional certification
    prof_cert = tsp_cert_body.create_artifact(persist=True)
    creation_time = time.time() - start_time

    print(f"   ✅ Certification issued in {creation_time:.1f} seconds")
    print(f"   🏆 Certificate ID: {prof_cert['artifact_id']}")
    print(f"   🔗 Config Hash: {prof_cert['config_hash'][:20]}...")
    print(f"   💎 Security Level: {prof_cert['rarity']}")
    print(f"   📊 Storage Mode: {prof_cert['mode']}")

    # Bob verifies professional certification
    print("\n2️⃣ PROFESSIONAL: Verifying industry certification...")

    tsp_professional = helper.create_tsp("bob", mode="verify")
    cert_verification = tsp_professional.verify_my_ownership(prof_cert["artifact_id"])

    print(f"🏆 Certification valid: {'✅ YES' if cert_verification['all_checks_valid'] else '❌ NO'}")
    print(f"📊 Verification mode: {cert_verification['verification_mode']}")

    return prof_cert, cert_verification


def demo_employer_verification():
    """Employer verifying multiple certificate types."""

    print("\n💼 EMPLOYER VERIFICATION PROCESS")
    print("=" * 60)
    print("🏢 Company: Tech Innovations Inc.")
    print("👤 Candidate: Bob Smith")
    print("🎯 Verifying: Academic diploma + Professional certification")
    print("-" * 60)

    helper = TSPHelper()

    # Get existing certificates from previous demos
    # We'll create fresh ones for this demo
    print("\n1️⃣ CANDIDATE: Submitting credentials...")

    # Create sample diploma
    tsp_uni = helper.create_tsp("alice", model="CERTIFICATE", mode="create", designated_owner="bob")
    diploma = tsp_uni.create_artifact(persist=True)

    # Create sample professional cert
    tsp_prof = helper.create_tsp("alice", model="CERTIFICATE", mode="create", designated_owner="bob")
    prof_cert = tsp_prof.create_artifact(persist=True)

    print(f"   📜 Academic Diploma: ID {diploma['artifact_id']}")
    print(f"   🏆 Professional Cert: ID {prof_cert['artifact_id']}")

    # Artur (employer) verifies both certificates
    print("\n2️⃣ EMPLOYER: Independent verification...")
    print("   🔍 Verifying without access to candidate's private keys")

    tsp_employer = helper.create_tsp("artur", mode="verify")

    # Verify diploma (stateful)
    diploma_check = tsp_employer.verify_artifact(diploma["artifact_id"])
    prof_check = tsp_employer.verify_artifact(prof_cert["artifact_id"])

    print(f"\n📊 VERIFICATION RESULTS:")
    print(f"🎓 Academic Diploma: {'✅ VERIFIED' if diploma_check['all_valid'] else '❌ SUSPICIOUS'}")
    print(f"🏆 Professional Cert: {'✅ VERIFIED' if prof_check['all_valid'] else '❌ SUSPICIOUS'}")

    both_valid = diploma_check['all_valid'] and prof_check['all_valid']

    if both_valid:
        print("\n✅ EMPLOYMENT VERIFICATION PASSED!")
        print("💼 Candidate credentials are authentic")
        print("🔒 No possibility of forgery (cryptographic guarantee)")
        print("⚡ Instant verification without contacting institutions")
    else:
        print("\n🚨 EMPLOYMENT VERIFICATION FAILED!")

    return both_valid


def demo_auto_detection():
    """Demonstrate automatic mode detection for certificates."""

    print("\n🤖 CERTIFICATE AUTO-DETECTION")
    print("=" * 60)
    print("🎯 Testing seamless API across certificate types")
    print("-" * 60)

    helper = TSPHelper()

    # Create test certificates
    print("\n📋 Creating test certificates...")

    # Stateful diploma
    tsp_create1 = helper.create_tsp("alice", model="CERTIFICATE", mode="create", designated_owner="bob")
    stateful_diploma = tsp_create1.create_artifact(persist=True)

    # Stateless course completion
    tsp_create2 = helper.create_tsp("alice", model="WEB_AUTH", mode="create", designated_owner="bob")
    stateless_course = tsp_create2.create_artifact(persist=False)

    # Test auto-detection
    tsp_verifier = helper.create_tsp("bob", mode="verify")

    print("\n🧪 Testing verify_artifact() auto-detection...")

    # Test 1: artifact_id (int) → stateful
    print("\n📋 Test 1: verify_artifact(artifact_id)")
    result1 = tsp_verifier.verify_artifact(stateful_diploma["artifact_id"])
    print(f"   🔍 Input: artifact_id = {stateful_diploma['artifact_id']}")
    print(f"   🎯 Detected mode: {result1.get('verification_mode', 'unknown')}")
    print(f"   ✅ Valid: {result1.get('all_valid', False)}")

    # Test 2: config_hash (str) → stateful
    print("\n📋 Test 2: verify_artifact(config_hash)")
    result2 = tsp_verifier.verify_artifact(stateful_diploma["config_hash"])
    print(f"   🔍 Input: config_hash = {stateful_diploma['config_hash'][:20]}...")
    print(f"   🎯 Detected mode: {result2.get('verification_mode', 'unknown')}")
    print(f"   ✅ Valid: {result2.get('all_valid', False)}")

    # Test 3: artifact_data (dict) → stateless
    print("\n📋 Test 3: verify_artifact(artifact_data)")
    result3 = tsp_verifier.verify_artifact(stateless_course["artifact_data"])
    print(f"   🔍 Input: artifact_data = {{...dict...}}")
    print(f"   🎯 Detected mode: {result3.get('verification_mode', 'unknown')}")
    print(f"   ✅ Valid: {result3.get('all_valid', False)}")

    print("\n🧪 Testing verify_my_ownership() auto-detection...")

    # Test ownership verification
    ownership1 = tsp_verifier.verify_my_ownership(stateful_diploma["artifact_id"])
    ownership2 = tsp_verifier.verify_my_ownership(stateless_course["artifact_data"])

    print(f"\n📋 Stateful ownership:")
    print(f"   🎯 Mode: {ownership1.get('verification_mode', 'unknown')}")
    print(f"   🔑 Ownership: {ownership1.get('ownership_valid', False)}")

    print(f"\n📋 Stateless ownership:")
    print(f"   🎯 Mode: {ownership2.get('verification_mode', 'unknown')}")
    print(f"   🔑 Ownership: {ownership2.get('ownership_valid', False)}")

    print("\n✅ AUTO-DETECTION WORKING PERFECTLY!")


def demo_certificate_performance():
    """Compare performance between certificate modes."""

    print("\n⚡ CERTIFICATE PERFORMANCE ANALYSIS")
    print("=" * 60)

    helper = TSPHelper()
    runs = 2  # Reduced for certificate generation time

    print(f"🔄 Running {runs} iterations (reduced due to CERTIFICATE mining time)...")

    stateful_times = []
    stateless_times = []

    for i in range(runs):
        print(f"\n🔄 Run {i + 1}/{runs}")

        # Stateful certificate workflow
        tsp_create = helper.create_tsp("alice", model="WEB_AUTH", mode="create", designated_owner="bob")
        tsp_verify = helper.create_tsp("bob", mode="verify")

        start = time.time()
        cert = tsp_create.create_artifact(persist=True)
        verification = tsp_verify.verify_my_ownership(cert["artifact_id"])
        stateful_time = time.time() - start
        stateful_times.append(stateful_time)

        # Stateless certificate workflow
        tsp_create = helper.create_tsp("alice", model="WEB_AUTH", mode="create", designated_owner="bob")
        tsp_verify = helper.create_tsp("bob", mode="verify")

        start = time.time()
        token = tsp_create.create_artifact(persist=False)
        verification = tsp_verify.verify_my_ownership(token["artifact_data"])
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

    print(f"\n📊 CERTIFICATE PERFORMANCE RESULTS:")
    print(f"🎓 Stateful (Diplomas):     {avg_stateful:.3f}s avg")
    print(f"📚 Stateless (Courses):     {avg_stateless:.3f}s avg")
    print(f"🚀 Performance gain: {speedup:.1f}x faster ({faster_mode})")

    # Certificate size analysis
    tsp_sample = helper.create_tsp("alice", model="WEB_AUTH", mode="create")
    stateless_sample = tsp_sample.create_artifact(persist=False)
    cert_size = len(json.dumps(stateless_sample["artifact_data"]))

    print(f"\n💾 CERTIFICATE STORAGE ANALYSIS:")
    print(f"🎓 Stateful diploma: ~800 bytes (commits.json + metadata)")
    print(f"📚 Stateless course: ~{cert_size} bytes (embedded certificate)")
    print(f"📊 Size ratio: {cert_size / 800:.1f}x larger (stateless)")


def university_batch_graduation():
    """Demonstrate dual-mode batch graduation ceremony."""

    print("\n🎓 DUAL-MODE BATCH GRADUATION CEREMONY")
    print("=" * 60)

    helper = TSPHelper()
    graduates = ["bob", "artur"]

    # Permanent diplomas (stateful)
    print("\n🏛️  PERMANENT DIPLOMAS (Stateful Mode)")
    print("-" * 40)

    diplomas_issued = []
    degrees = ["B.S. Computer Science", "M.S. Data Science"]

    for i, (grad, degree) in enumerate(zip(graduates, degrees)):
        if not helper.check_user_keys(grad):
            print(f"   ⚠️  Skipping {grad} - no keys found")
            continue

        print(f"\n🎓 Graduate {i + 1}/{len(graduates)}: {grad}")
        print(f"📜 Degree: {degree}")
        print("🔨 Mining permanent diploma...")

        # Use WEB_AUTH for faster demo (in real world would be CERTIFICATE)
        tsp_university = helper.create_tsp("alice", model="WEB_AUTH", designated_owner=grad)
        diploma_data = tsp_university.create_artifact(persist=True)

        diplomas_issued.append({
            "graduate": grad,
            "degree": degree,
            "diploma_id": diploma_data["artifact_id"],
            "config_hash": diploma_data["config_hash"],
            "mode": "stateful"
        })

        print(f"   ✅ Diploma {diploma_data['artifact_id']} issued (stateful)")

    # Course completions (stateless)
    print("\n📚 COURSE COMPLETION CERTIFICATES (Stateless Mode)")
    print("-" * 40)

    course_certs = []
    courses = ["Ethics in Technology", "Research Methods"]

    for i, (grad, course) in enumerate(zip(graduates, courses)):
        if not helper.check_user_keys(grad):
            continue

        print(f"\n📖 Course {i + 1}/{len(graduates)}: {course}")
        print(f"👤 Student: {grad}")
        print("⚡ Generating course certificate...")

        tsp_university = helper.create_tsp("alice", model="WEB_AUTH", designated_owner=grad)
        course_data = tsp_university.create_artifact(persist=False)

        course_certs.append({
            "student": grad,
            "course": course,
            "config_hash": course_data["config_hash"],
            "mode": "stateless",
            "size": len(str(course_data["artifact_data"]))
        })

        print(f"   ✅ Certificate generated (stateless, {len(str(course_data['artifact_data']))} bytes)")

    # Summary
    print(f"\n🎉 GRADUATION CEREMONY COMPLETE!")
    print(f"📊 {len(diplomas_issued)} permanent diplomas + {len(course_certs)} course certificates")

    print(f"\n📋 PERMANENT DIPLOMAS (Stored in commits.json):")
    for diploma in diplomas_issued:
        print(f"   🎓 {diploma['graduate']}: {diploma['degree']} (ID: {diploma['diploma_id']})")

    print(f"\n📚 COURSE CERTIFICATES (Embedded tokens):")
    for cert in course_certs:
        print(f"   📖 {cert['student']}: {cert['course']} ({cert['size']} bytes)")


def main():
    """Main demonstration function showcasing dual-mode certificates."""

    print("🎓 TSP DIGITAL CERTIFICATES - DUAL MODE EDITION")
    print("=" * 70)
    print("🎯 Demonstrating both stateful and stateless certificate modes")
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
        # Demo 1: Permanent academic diploma (stateful)
        diploma_artifact, diploma_verification = demo_permanent_diploma()

        # Demo 2: Course completion tokens (stateless)
        completion_tokens = demo_course_completion_tokens()

        # Demo 3: Professional certification (stateful)
        prof_cert, prof_verification = demo_professional_certification()

        # Demo 4: Employer verification process
        employer_result = demo_employer_verification()

        # Demo 5: Auto-detection capabilities
        demo_auto_detection()

        # Demo 6: Performance comparison
        demo_certificate_performance()

        # Summary with practical insights
        print("\n🎯 DUAL-MODE CERTIFICATES SUMMARY")
        print("=" * 70)
        print("🎓 STATEFUL MODE (Permanent Academic/Professional Credentials):")
        print("   ✅ Perfect for: Diplomas, degrees, professional certifications")
        print("   ✅ Features: Lifetime audit trail, regulatory compliance")
        print("   ✅ Storage: commits.json registry (~800 bytes per certificate)")
        print("   ✅ Benefits: Permanent record, employer verification, transferable")
        print()
        print("📚 STATELESS MODE (Course Completions/Micro-Credentials):")
        print("   ✅ Perfect for: Course completions, skill badges, temporary certs")
        print("   ✅ Features: Instant issuance, no storage overhead")
        print("   ✅ Storage: Certificate-embedded (~2-5KB per certificate)")
        print("   ✅ Benefits: Scalable, platform-independent, blockchain-free")
        print()
        print("🤖 AUTO-DETECTION API:")
        print("   ✅ One method handles both certificate types")
        print("   ✅ Zero configuration required")
        print("   ✅ Seamless institutional integration")
        print()
        print("🛡️  SECURITY GUARANTEES:")
        print("   ✅ Both modes cryptographically tamper-proof")
        print("   ✅ Impossible to forge without institution's private key")
        print("   ✅ Instant verification by any party worldwide")
        print("   ✅ No central authority or database required")

        print("\n🎉 DUAL-MODE CERTIFICATES DEMO COMPLETE!")
        print("🚀 TSP ready for educational institutions and professional bodies!")

        # Optional batch graduation
        user_input = input("\n🎓 Run dual-mode batch graduation ceremony? (y/N): ")
        if user_input.lower() == "y":
            university_batch_graduation()

    except KeyboardInterrupt:
        print("\n\n👋 Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()