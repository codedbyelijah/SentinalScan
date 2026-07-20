"""Test script to verify ScanModule interface works correctly."""

import sys
from pathlib import Path

# Add the app directory to the path
sys.path.insert(0, str(Path(__file__).parent))

from app.models.target import Target
from app.models.scan_result import ScanResult
from app.scanners.scan_module import ScanModule

# Test 1: Verify interface imports
print("Test 1: Verify ScanModule imports...")
try:
    from app.scanners.scan_module import ScanModule
    print("✅ ScanModule imported successfully")
except Exception as e:
    print(f"❌ Failed to import ScanModule: {e}")
    sys.exit(1)

# Test 2: Verify abstract method enforcement
print("\nTest 2: Verify abstract method enforcement...")
try:
    class IncompleteModule(ScanModule):
        pass
    
    # This should fail because scan() is not implemented
    module = IncompleteModule()
    print("❌ Abstract method enforcement failed - should not be able to instantiate")
    sys.exit(1)
except TypeError as e:
    print(f"✅ Abstract method enforcement works: {e}")

# Test 3: Verify concrete implementation works
print("\nTest 3: Verify concrete implementation works...")
try:
    class ConcreteModule(ScanModule):
        async def scan(self, target: Target) -> ScanResult:
            return ScanResult(
                module_name="test_module",
                status="completed",
                execution_time=0.0,
                findings=[]
            )
    
    module = ConcreteModule()
    print("✅ Concrete module instantiated successfully")
except Exception as e:
    print(f"❌ Failed to create concrete module: {e}")
    sys.exit(1)

print("\n" + "="*60)
print("✅ All tests passed!")
print("="*60)
