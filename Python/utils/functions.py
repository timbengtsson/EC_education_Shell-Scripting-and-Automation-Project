import subprocess
import argparse 
from datetime import datetime

from typing import Any 


def runCommand(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )

 
def parseArgs() -> argparse.Namespace:
    now = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")

    p = argparse.ArgumentParser(description="Local Docker security scanner (Trivy + Python orchestrator)")

    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--image", help="Image ref to scan, e.g. myapp:dev")
    g.add_argument("--running", action="store_true", help="Scan images used by running containers")

    p.add_argument("--out", default=now, help="Output directory")
    # p.add_argument("--pull", action="store_true", help="Pull image if missing (only for --image)")

    p.add_argument("--fail-on", default="HIGH", choices=["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    p.add_argument("--require-fix", action="store_true", help="Fail only if a fix is available")
    return p.parse_args()
 
 
def _safe_str(value: Any) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    return s if s else None


def _safe_list_str(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    return [str(value).strip()]
