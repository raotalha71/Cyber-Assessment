import os
import subprocess
import time
import shutil
import platform
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Reports directory - auto-detect based on current file location
CURRENT_DIR = Path(__file__).parent
REPORTS_DIR = Path(os.getenv("REPORTS_DIR", str(CURRENT_DIR / "reports"))).resolve()
REPORTS_DIR.mkdir(parents=True, exist_ok=True)  # Make sure folder exists


def _run_mock_scan(target: str, timeout: int):
    """
    Generate mock scan results for testing purposes.
    """
    # Simulate scan time
    time.sleep(2)
    
    # Output file (timestamped)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_file = REPORTS_DIR / f"nikto_{ts}.txt"
    
    # Generate mock findings
    alerts = [
        {
            "name": "+ MOCK: Server leaks inodes via ETags, header found with file /, fields: 0x29cd 0x5c8a3c9d06380",
            "risk": "Low",
            "confidence": "High",
            "uri": target,
        },
        {
            "name": "+ MOCK: The anti-clickjacking X-Frame-Options header is not present.",
            "risk": "Medium",
            "confidence": "High",
            "uri": target,
        },
        {
            "name": "+ MOCK: No CGI Directories found (use '-C all' to force check all possible dirs)",
            "risk": "Low",
            "confidence": "High",
            "uri": target,
        },
        {
            "name": "+ MOCK: Allowed HTTP Methods: GET, POST, OPTIONS, HEAD",
            "risk": "Medium",
            "confidence": "High",
            "uri": target,
        },
        {
            "name": "+ MOCK: /admin/: Admin login page/section found.",
            "risk": "High",
            "confidence": "High",
            "uri": target,
        },
    ]
    
    # Write mock output
    mock_output = f"""- Nikto v2.5.0 (MOCK MODE)
---------------------------------------------------------------------------
+ Target IP:          {target}
+ Target Hostname:    {target}
+ Target Port:        80
+ Start Time:         {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} (GMT0)
---------------------------------------------------------------------------
+ Server: nginx/1.18.0
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-Content-Type-Options header is not set.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server leaks inodes via ETags, header found with file /, fields: 0x29cd 0x5c8a3c9d06380
+ Allowed HTTP Methods: GET, POST, OPTIONS, HEAD
+ /admin/: Admin login page/section found.
+ 7891 requests: 0 error(s) and 5 item(s) reported on remote host
+ End Time:           {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} (GMT0) (2 seconds)
---------------------------------------------------------------------------
"""
    
    try:
        out_file.write_text(mock_output, encoding="utf-8")
    except Exception:
        pass
    
    return {
        "ok": True,
        "partial": False,
        "error": None,
        "alerts": alerts,
        "out_path": str(out_file),
    }

def run_nikto_scan(target: str, timeout: int | None = None):
    """
    Run Nikto scan and return parsed alerts.
    Supports Windows (WSL/Docker), Linux, and mock mode.
    - Reads output line by line while Nikto runs.
    - If timeout is reached, kills Nikto but RETURNS partial results.
    
    Returns dict:
    {
      ok: bool,
      partial: bool,
      error: str | None,
      alerts: [ {name, risk, confidence, uri}, ... ],
      out_path: str | None
    }
    """
    # Timeout setting (default: 180 seconds)
    if timeout is None:
        try:
            timeout = int(os.getenv("NIKTO_TIMEOUT", "180"))
        except ValueError:
            timeout = 180  # default 3 minutes

    # Detect platform and find Nikto
    is_windows = platform.system() == "Windows"
    
    # Check if user wants to use mock mode (for testing without Nikto)
    use_mock = os.getenv("NIKTO_MOCK_MODE", "false").lower() == "true"
    
    if use_mock:
        return _run_mock_scan(target, timeout)
    
    nikto_path = None
    nikto_cmd = []
    
    if is_windows:
        # Force WSL first (set FORCE_WSL_NIKTO=true to skip Docker)
        force_wsl = os.getenv("FORCE_WSL_NIKTO", "true").lower() == "true"
        
        # Try WSL first
        wsl_nikto = shutil.which("wsl")
        if wsl_nikto:
            # Check if nikto exists in WSL Ubuntu (specify distribution)
            try:
                # Check for nikto directly (no wake-up needed)
                result = subprocess.run(
                    ["wsl", "-d", "Ubuntu", "which", "nikto"],
                    capture_output=True,
                    text=True,
                    timeout=20
                )
                if result.returncode == 0 and result.stdout.strip():
                    nikto_path = "wsl"
                    nikto_cmd = ["wsl", "-d", "Ubuntu", "nikto"]
                    print(f"[INFO] Using WSL Ubuntu Nikto: {result.stdout.strip()}")
                else:
                    print(f"[WARN] Nikto not found in Ubuntu WSL")
            except subprocess.TimeoutExpired:
                print(f"[WARN] WSL Ubuntu check timed out - trying default WSL")
                # Try default WSL if Ubuntu times out
                try:
                    result = subprocess.run(
                        ["wsl", "which", "nikto"],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    if result.returncode == 0 and result.stdout.strip():
                        nikto_path = "wsl"
                        nikto_cmd = ["wsl", "nikto"]
                        print(f"[INFO] Using default WSL Nikto: {result.stdout.strip()}")
                except Exception as e2:
                    print(f"[WARN] Default WSL check also failed: {e2}")
            except Exception as e:
                print(f"[WARN] WSL Ubuntu check failed: {e}")
        
        # Try Docker only if WSL didn't work and not forced
        if not nikto_path and not force_wsl:
            docker_path = shutil.which("docker")
            if docker_path:
                try:
                    # Check if Docker is running
                    result = subprocess.run(
                        ["docker", "ps"],
                        capture_output=True,
                        timeout=5
                    )
                    if result.returncode == 0:
                        nikto_path = "docker"
                        nikto_cmd = ["docker", "run", "--rm", "sullo/nikto"]
                        print("[INFO] Using Docker Nikto")
                except Exception as e:
                    print(f"[WARN] Docker check failed: {e}")
    else:
        # Linux/Mac
        nikto_path = shutil.which("nikto") or "/usr/bin/nikto"
        if os.path.isfile(nikto_path):
            nikto_cmd = [nikto_path]
    
    if not nikto_cmd:
        error_msg = """Nikto not found. Please choose one of these options:

Option 1 - Install WSL and Nikto (Recommended for Windows):
  1. Install WSL: wsl --install
  2. In WSL terminal: sudo apt update && sudo apt install nikto

Option 2 - Use Docker:
  1. Install Docker Desktop
  2. Pull Nikto: docker pull sullo/nikto

Option 3 - Use Mock Mode (for testing):
  Set environment variable: NIKTO_MOCK_MODE=true
"""
        return {
            "ok": False,
            "partial": False,
            "error": error_msg,
            "alerts": [],
            "out_path": None,
        }

    # Output file (timestamped)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_file = REPORTS_DIR / f"nikto_{ts}.txt"

    # Build optimized Nikto command
    cmd = nikto_cmd + ["-h", target]
    
    # Add fast mode optimizations
    fast_mode = os.getenv("NIKTO_FAST_MODE", "true").lower() == "true"
    if fast_mode:
        # Tuning options: skip slow tests
        # 1=Interesting files, 2=Misconfiguration, 3=Info disclosure, 4=Injection, 6=XSS
        cmd.extend(["-Tuning", "123"])  # Focus on common vulnerabilities
        cmd.append("-no404")  # Skip 404 testing (saves time)
        cmd.extend(["-maxtime", str(timeout)])  # Set max execution time
    
    print(f"[INFO] Running Nikto: {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,  # capture output
            stderr=subprocess.STDOUT,   # merge errors into stdout
            text=True,
            bufsize=1,
        )
    except Exception as e:
        return {
            "ok": False,
            "partial": False,
            "error": f"Failed to start Nikto: {e}",
            "alerts": [],
            "out_path": None,
        }

    # Read output line by line
    lines: list[str] = []
    alerts: list[dict] = []
    start = time.time()
    timed_out = False

    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            lines.append(line)

            stripped = line.strip()
            if not stripped:
                continue

            # Only treat real findings (lines starting with "+")
            if not stripped.startswith("+"):
                continue

            # Skip header/metadata lines (Target IP, Target Hostname, Start Time, Server, etc.)
            # These are informational and not vulnerabilities
            skip_patterns = [
                "+ target ip:", "+ target hostname:", "+ target port:",
                "+ start time:", "+ end time:", "+ server:",
                "requests:", "item(s) reported"
            ]
            low = stripped.lower()
            
            if any(pattern in low for pattern in skip_patterns):
                continue
            
            risk = "Medium"

            # Simple keyword-based risk classification
            if any(w in low for w in ["critical", "vulnerable", "exploit",
                                      "admin", "sql", "xss", "shell", "execute"]):
                risk = "High"
            elif any(w in low for w in ["info only", "informational"]):
                risk = "Low"

            # Store each finding in a dictionary
            alerts.append({
                "name": stripped[:200],   # first 200 chars
                "risk": risk,
                "confidence": "High",  # all Nikto alerts are high confidence
                "uri": target,
            })

            # Check timeout
            if time.time() - start > timeout:
                timed_out = True
                break
    finally:
        # Ensure process is stopped
        if proc.poll() is None:
            try:
                proc.kill()
            except Exception:
                pass
        try:
            proc.wait(timeout=5)
        except Exception:
            pass

    # Write raw Nikto output to report file (for record)
    try:
        out_file.write_text("".join(lines), encoding="utf-8", errors="ignore")
    except Exception:
        # Not fatal
        pass

    # If no alerts parsed at all
    if not alerts:
        if timed_out:
            return {
                "ok": False,
                "partial": False,
                "error": f"Nikto timed out after {timeout} seconds and no findings were parsed.",
                "alerts": [],
                "out_path": str(out_file),
            }
        else:
            # Completed but nothing interesting found
            alerts = [{
                "name": "Scan completed – no parsable Nikto findings.",
                "risk": "Low",
                "confidence": "High",
                "uri": target,
            }]

    # If we hit timeout but have some alerts → treat as PARTIAL SUCCESS
    if timed_out:
        return {
            "ok": True,
            "partial": True,
            "error": f"Nikto timed out after {timeout} seconds – partial results returned.",
            "alerts": alerts,
            "out_path": str(out_file),
        }

    # Normal successful finish
    return {
        "ok": True,
        "partial": False,
        "error": None,
        "alerts": alerts,
        "out_path": str(out_file),
    }
