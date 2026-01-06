import subprocess
import os

print("Testing WSL Nikto detection...")

# Test 1: Wake up Ubuntu
print("\n1. Starting Ubuntu WSL...")
try:
    result = subprocess.run(
        ["wsl", "-d", "Ubuntu", "echo", "starting"],
        capture_output=True,
        timeout=10
    )
    print(f"   Result: {result.returncode}")
except Exception as e:
    print(f"   Error: {e}")

# Test 2: Check nikto
print("\n2. Checking for nikto...")
try:
    result = subprocess.run(
        ["wsl", "-d", "Ubuntu", "which", "nikto"],
        capture_output=True,
        text=True,
        timeout=15
    )
    print(f"   Return code: {result.returncode}")
    print(f"   Output: {result.stdout.strip()}")
    print(f"   Stderr: {result.stderr.strip()}")
except Exception as e:
    print(f"   Error: {e}")

# Test 3: Run nikto version
print("\n3. Running nikto -Version...")
try:
    result = subprocess.run(
        ["wsl", "-d", "Ubuntu", "nikto", "-Version"],
        capture_output=True,
        text=True,
        timeout=15
    )
    print(f"   Return code: {result.returncode}")
    print(f"   First 200 chars: {result.stdout[:200]}")
except Exception as e:
    print(f"   Error: {e}")

print("\nDone!")
