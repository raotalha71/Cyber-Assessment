# Mock scan function for testing without Nikto
import time
from pathlib import Path
from datetime import datetime

def _run_mock_scan(target: str, timeout: int):
    """
    Generate mock scan results for testing purposes.
    """
    from nikto_runner import REPORTS_DIR
    
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
