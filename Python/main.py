#!/usr/bin/env python3
"""
==========================================================

Purpose
-------

TL;DR
Identify known vulnerabilities in Docker images

Scan all running images:
python3 main.py --running --fail-on HIGH

Description
-----------

A Python script working as an orchestrator that uses Trivy (https://trivy.dev/) as a scan engine
to identify known vulnerabilities in Docker images. It collects results,
normalizes them, applies a configurable policy, and generates a report.

What it scans
-------------
- Images. Even when using --running, the script scans the images
  used by currently running containers, not the container runtime state.

What is needed
-------------
- Docker and Docker daemon running (docker info must work)
- Trivy installed and available in PATH
- First Trivy run may download/update its vulnerability database

How to use it
-------------
Scan a specific local image:
  python3 main.py --image <repository:tag> [options]

Scan images used by currently running containers:
  python3 main.py --running [options]

Examples
--------
1) Scan one image and fail on HIGH+ only if a fix exists:
  python3 main.py --image nginx:1.27-alpine --fail-on HIGH --require-fix

2) Scan one image, fail only on CRITICAL, require fix:
  python3 main.py --image nginx:1.27-alpine --fail-on CRITICAL --require-fix

3) Scan running containers' images and fail on HIGH+ (fix not required):
  python3 main.py --running --fail-on HIGH

4) Pull image if missing, save output under reports/test1:
  python3 main.py --image ubuntu:22.04 --pull --out test1

Notes
-----
- "Policy varning" is not a crash. It means the scan found vulnerabilities that
  violate the configured policy. Reports are still generated, but the script
  exits with code 2 for automation/CI usage.
- Vulnerability counts can be high for base images. Focus first on CRITICAL/HIGH
  and findings where a fixed version is available.

==========================================================
"""

from __future__ import annotations

import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from scanner.models import Policy, Severity, ScanTarget, ScanResult, VulnerabilityFinding, ScanSummary
from utils.functions import runCommand, parseArgs

from utils.docker_helper import getRunningImageRefs, ensureImageAvailable
from scanner.normalizers.trivy_normalizer import normalizeTrivy
from scanner.trivy_engine import scanImageWithTrivy
import logging   

"""
logger.debug("Detaljerad info för felsökning")
logger.info("Normal information")
logger.warning("Något oväntat men ej kritiskt")
logger.error("Något gick fel")
logger.critical("Allvarligt fel") 
"""
def setupLogging(outDir: Path) -> None:
    outDir.mkdir(parents=True, exist_ok=True)
    logPath = outDir / "scanner.log"

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter("%(message)s"))

    fileh = logging.FileHandler(logPath, encoding="utf-8")
    fileh.setLevel(logging.DEBUG)
    fileh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s - %(message)s"))

    root.handlers.clear()
    root.addHandler(console)
    root.addHandler(fileh)
 

  
def safeFilename(name: str) -> str:
    # gör om "repo/app:tag" till "repo_app_tag"
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in name)
 
def saveRawTrivyJson(outDir: Path, imageRef: str, raw: dict[str, Any]) -> Path:
    path = outDir / f"trivy_raw_{safeFilename(imageRef)}.json"
    with path.open("w", encoding="utf-8") as f:
        json.dump(raw, f, ensure_ascii=False, indent=2)
    return path
 
# -----------------------------
# Reporting
# -----------------------------
def writeOutputs(outDir: Path, scanResults: list[ScanResult]) -> tuple[Path, Path]:
    outDir.mkdir(parents=True, exist_ok=True)

    # maskinläsbart
    jsonPath = outDir / "scan_all.json"
    with jsonPath.open("w", encoding="utf-8") as f:
        json.dump([r.to_dict() for r in scanResults], f, ensure_ascii=False, indent=2)

    # mänsklig rapport
    mdPath = outDir / "report.md"
    lines: list[str] = []
    lines.append("# Docker vulnerability report")
    lines.append("")
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append("")

    # total-summering
    total = ScanSummary()
    for r in scanResults:
        total.total += r.summary.total
        total.critical += r.summary.critical
        total.high += r.summary.high
        total.medium += r.summary.medium
        total.low += r.summary.low
        total.unknown += r.summary.unknown

    lines.append("## Overall summary")
    lines.append(f"- Images scanned: {len(scanResults)}")
    lines.append(f"- Total vulns: {total.total}")
    lines.append(f"- CRITICAL: {total.critical} | HIGH: {total.high} | MEDIUM: {total.medium} | LOW: {total.low} | UNKNOWN: {total.unknown}")
    lines.append("")

    # per image + top findings
    for r in scanResults:
        s = r.summary
        lines.append(f"## {r.target.image_ref}")
        lines.append(f"- Source: `{r.target.source}`")
        if r.target.digest:
            lines.append(f"- Digest/ImageID: `{r.target.digest}`")
        lines.append(f"- Tool: {r.tool_name} {r.tool_version or ''}".strip())
        lines.append(f"- Total: {s.total} | CRITICAL: {s.critical} | HIGH: {s.high} | MEDIUM: {s.medium} | LOW: {s.low}")
        lines.append("")

        # topp 15
        top = sorted(
            r.findings,
            key=lambda f: (f.severity.rank(), 1 if f.has_fix() else 0),
            reverse=True,
        )[:15]

        if not top:
            lines.append("No vulnerabilities found 🎉")
            lines.append("")
            continue

        lines.append("Top findings (max 15):")
        for fnd in top:
            fix = fnd.fixed_version if fnd.fixed_version else "-"
            lines.append(f"- **{fnd.severity.value}** {fnd.vulnerability_id} | `{fnd.pkg_name}` {fnd.installed_version or '-'} → {fix}")
            if fnd.primary_url:
                lines.append(f"  - {fnd.primary_url}")
        lines.append("")

    with mdPath.open("w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return jsonPath, mdPath

 
# -----------------------------
# Validation / Pree-flight
# Make sure we got the tools and structures we need
# - Docker -> Container engine
# - Trivvy -> Scan engine
# -----------------------------
def ensureToolExists(name: str) -> None:
    if shutil.which(name) is None:
        print(f"ERROR: '{name}' is not installed or not in PATH.", file=sys.stderr)
        sys.exit(1)


def validateEnvironment(outDir: Path) -> None:
    # tools
    ensureToolExists("docker")
    ensureToolExists("trivy")

    # docker daemon
    proc = runCommand(["docker", "info"])
    if proc.returncode != 0:
        print("ERROR: Docker daemon is not running (docker info failed).", file=sys.stderr)
        if proc.stderr.strip():
            print(proc.stderr.strip(), file=sys.stderr)
        sys.exit(1)

    # output folder
    outDir.mkdir(parents=True, exist_ok=True)


def main() -> None:  
    # Setup logging tidigt
    outDir = Path("reports")
    setupLogging(outDir)

    logger = logging.getLogger(__name__)
   
    # Get possible arguments or defaults
    try:
        args = parseArgs()
    except SystemExit as e:
        logger.error("Felaktig argument. Använd 'python3 main.py --help' för att se vad du kan använda.")
        raise 

    logger.info(f"=========== Startar ny scanning: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} ===========") 

    # Output folder 
    outDir = Path(args.out)
      
    reports_root = Path("reports").resolve()
    outDir = (reports_root / args.out).resolve()

    # Making sure we avoide dir traversal attacks (reports needs to be inside /reports dir)
    if reports_root not in outDir.parents and outDir != reports_root: 
        logger.error("--out måste vara i mappen reports/")
        print("ERROR: --out must be inside the reports/ directory.", file=sys.stderr)
        sys.exit(1)

    # Make sure we got the output folder
    outDir.mkdir(parents=True, exist_ok=True)

    # Check we got all the tools and services we need (docker trivy etc.)
    validateEnvironment(outDir)

    # Policy
    policy = Policy(
        fail_on=Severity.from_str(args.fail_on),
        require_fix=bool(args.require_fix),
    )
 
    # target = Docker images to be scanned 
    targets: list[ScanTarget] = []
    if args.image:
        ensureImageAvailable(args.image, False) # (Dont pull for now) pullIfMissing=bool(args.pull))
        targets = [ScanTarget(image_ref=args.image, source="image")]
    else:
        refs = getRunningImageRefs()
        if not refs:
            logger.warning("Hittade inga aktiva docker bilder att scanna.") 
            sys.exit(0)
        targets = [ScanTarget(image_ref=r, source="running") for r in refs]

    # Scan + normalize
    scanResults: list[ScanResult] = []
    # shouldFail = False
    policyViolated = False

    # Loop all images and scan
    for t in targets: 
        logger.info(f"Scannar: {t.image_ref}") 
        raw = scanImageWithTrivy(t.image_ref)
        saveRawTrivyJson(outDir, t.image_ref, raw)

        res = normalizeTrivy(raw, t)
        scanResults.append(res)

        if policy.should_fail(res.findings):
            policyViolated = True

    jsonPath, mdPath = writeOutputs(outDir, scanResults)
      
    if policyViolated: 
        logger.warning(
            "Policy varning för: %s (fail_on=%s, require_fix=%s)",
            t.image_ref, policy.fail_on.value, policy.require_fix
        ) 
 
        logger.info(f"Du hittar full rapport i:\n{mdPath}\n")
        sys.exit(2)

    logger.info("Godkänd policy för alla images\n")
 
    sys.exit(0) 

if __name__ == "__main__":
    main()