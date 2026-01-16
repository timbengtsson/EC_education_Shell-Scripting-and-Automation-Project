# Docker Security Scanner

## Purpose 
A Python script working as an orchestrator that uses Trivy as a scan engine <br>
to identify known vulnerabilities in Docker images. It collects results,<br>
normalizes them, applies a configurable policy, and generates a report.<br>

## What it scans 
- Docker Images. the script scans the images
  used by currently running containers.

## What is needed 
- Docker and Docker daemon running (docker info must work)
- Trivy installed and available in PATH
- First Trivy run may download/update its vulnerability database

## How to use it 
Scan a specific local image: 
```bash
python3 main.py --image <repository:tag> [options]
```

Scan images used by currently running containers: 
```bash
python3 main.py --running [options]
```

Help:
  python3 main.py --help

## Targets (choose one!) 
`--image <imageRef>` <br>
  Scan one specific image reference.<br>
  Examples: myapp:dev, nginx:1.27-alpine, ubuntu:22.04

`--running`<br>
  Scan all unique image references used by running containers.<br>
  The script collects image refs via `docker ps` and deduplicates them.<br>

## Output options 
`--out <name>`<br>
  Output directory name under reports/.<br>
  Example: --out test-run  -> reports/test-run<br>
  Default: a timestamp or "latest" depending on your implementation.<br>
 

## Policy options 
--fail-on <level><br>
  Minimum severity that triggers a policy violation.<br>
  Allowed: UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL<br>
  Default: HIGH

--require-fix<br>
  If set: only trigger a policy violation when a fix is available<br>
  (i.e., Trivy reports a fixed version for the vulnerability).<br>
  If not set: any vulnerability meeting --fail-on triggers violation,<br>
  regardless of whether a fix exists.

## Exit codes 
0  Policy passed (no violations according to configured policy)<br>
2  Policy failed (violations found)<br>
1  Technical error (Docker/Trivy missing, daemon not running, scan/parse error)<br>

## Generated files 
Inside reports/<out>/ (or default -> reports/YYYY-MM-DD_HH:MM:SS/):
- report.md            Human-readable summary + top findings
- scan_all.json        Normalized scan results (machine-readable)
- trivy_raw_*.json     Raw Trivy JSON output per scanned image
- scanner.log          Runtime logs for troubleshooting

Trying our best to avoide directory traversal attacks.

## Examples 
1) Scan one image and fail on HIGH+ only if a fix exists:
```
python3 main.py --image nginx:1.27-alpine --fail-on HIGH --require-fix
```
2) Scan one image, fail only on CRITICAL, require fix:
```
python3 main.py --image nginx:1.27-alpine --fail-on CRITICAL --require-fix
```
3) Scan running containers' images and fail on HIGH+ (fix not required):
```
python3 main.py --running --fail-on HIGH
```
4) Pull image if missing, save output under reports/test1:
```
python3 main.py --image ubuntu:22.04 --pull --out test1
```

 