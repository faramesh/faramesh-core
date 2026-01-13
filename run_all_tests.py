#!/usr/bin/env python3
"""Comprehensive test runner for FaraCore DX features.

This script runs all tests and verifies end-to-end functionality.
"""

import subprocess
import sys
from pathlib import Path

def run_tests():
    """Run all tests and report results."""
    project_root = Path(__file__).parent
    tests_dir = project_root / "tests"
    
    print("=" * 80)
    print("FaraCore DX Features - Comprehensive Test Suite")
    print("=" * 80)
    print()
    
    # Test categories
    test_files = [
        ("API Tests", "test_api.py"),
        ("CLI Tests", "test_cli.py"),
        ("CLI DX Tests", "test_cli_dx.py"),
        ("SDK Tests", "test_sdk.py"),
        ("Policy Tests", "test_policy_validation.py"),
        ("Events Tests", "test_events.py"),
        ("Risk Scoring Tests", "test_risk_scoring.py"),
    ]
    
    results = {}
    total_passed = 0
    total_failed = 0
    
    for category, test_file in test_files:
        test_path = tests_dir / test_file
        if not test_path.exists():
            print(f"⚠️  {category}: {test_file} not found, skipping...")
            continue
        
        print(f"\n{'=' * 80}")
        print(f"Running {category}: {test_file}")
        print('=' * 80)
        
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pytest", str(test_path), "-v", "--tb=short"],
                cwd=project_root,
                capture_output=True,
                text=True,
                timeout=300,
            )
            
            if result.returncode == 0:
                print(f"✅ {category}: PASSED")
                # Count passed tests
                passed = result.stdout.count("PASSED")
                total_passed += passed
                results[category] = ("PASSED", passed, 0)
            else:
                print(f"❌ {category}: FAILED")
                print(result.stdout)
                print(result.stderr)
                # Count failed tests
                failed = result.stdout.count("FAILED")
                total_failed += failed
                results[category] = ("FAILED", 0, failed)
                
        except subprocess.TimeoutExpired:
            print(f"⏱️  {category}: TIMEOUT (>5 minutes)")
            results[category] = ("TIMEOUT", 0, 0)
        except Exception as e:
            print(f"💥 {category}: ERROR - {e}")
            results[category] = ("ERROR", 0, 0)
    
    # Summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    
    for category, (status, passed, failed) in results.items():
        status_icon = {
            "PASSED": "✅",
            "FAILED": "❌",
            "TIMEOUT": "⏱️",
            "ERROR": "💥",
        }.get(status, "❓")
        
        print(f"{status_icon} {category}: {status}")
        if passed > 0:
            print(f"   Passed: {passed}")
        if failed > 0:
            print(f"   Failed: {failed}")
    
    print("\n" + "=" * 80)
    print(f"Total: {total_passed} passed, {total_failed} failed")
    print("=" * 80)
    
    if total_failed == 0:
        print("\n🎉 All tests passed!")
        return 0
    else:
        print(f"\n⚠️  {total_failed} test(s) failed. Please review above.")
        return 1


if __name__ == "__main__":
    sys.exit(run_tests())
