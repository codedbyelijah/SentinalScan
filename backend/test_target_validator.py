"""Test script to verify target validator works correctly."""

import sys
from pathlib import Path

# Add the app directory to the path
sys.path.insert(0, str(Path(__file__).parent))

from app.services.target_validator import TargetValidator, ValidationError

# Test cases
test_cases = [
    # Valid URLs
    ("https://example.com", "url"),
    ("http://example.com", "url"),
    ("https://example.com:8080", "url"),
    
    # Valid domains
    ("example.com", "domain"),
    ("sub.example.com", "domain"),
    ("test.example.co.uk", "domain"),
    
    # Valid IPv4
    ("192.168.1.1", "ipv4"),
    ("10.0.0.1", "ipv4"),
    ("8.8.8.8", "ipv4"),
    
    # Valid IPv6
    ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", "ipv6"),
    ("::1", "ipv6"),
    ("fe80::1", "ipv6"),
    
    # Invalid cases
    ("", "error"),
    ("   ", "error"),
    ("not-a-valid-target", "error"),
    ("ftp://example.com", "error"),  # unsupported protocol
    ("999.999.999.999", "error"),  # invalid IPv4
]

print("Testing TargetValidator...\n")

passed = 0
failed = 0

for target_input, expected_type in test_cases:
    try:
        result = TargetValidator.validate(target_input)
        
        if expected_type == "error":
            print(f"❌ FAIL: Expected error for '{target_input}', but got: {result.target_type}")
            failed += 1
        elif result.target_type.value == expected_type:
            print(f"✅ PASS: '{target_input}' -> {result.target_type.value}")
            print(f"   Normalized: {result.normalized_target}")
            passed += 1
        else:
            print(f"❌ FAIL: '{target_input}' expected {expected_type}, got {result.target_type.value}")
            failed += 1
    except ValidationError as e:
        if expected_type == "error":
            print(f"✅ PASS: '{target_input}' correctly raised error: {e.message}")
            passed += 1
        else:
            print(f"❌ FAIL: '{target_input}' raised unexpected error: {e.message}")
            failed += 1
    except Exception as e:
        print(f"❌ FAIL: '{target_input}' raised unexpected exception: {e}")
        failed += 1

print(f"\n{'='*50}")
print(f"Results: {passed} passed, {failed} failed")
print(f"{'='*50}")

if failed > 0:
    sys.exit(1)
else:
    print("\n✅ All tests passed!")
