from typing import Any 
from scanner.models import ScanTarget, ScanResult, VulnerabilityFinding, Severity
from utils.functions import _safe_str, _safe_list_str
import logging

logger = logging.getLogger(__name__)

"""
This function takes raw output from Trivy and converts it / Normalize it to a ScanResult object.
Where each finding is a VulnerabilityFinding object, and the ScanResult object has a list of findings
"""
def normalizeTrivy(raw: dict[str, Any], scan_target: ScanTarget) -> ScanResult:
    tool_version = raw.get("TrivyVersion") or raw.get("Version")

    result = ScanResult(
        target=scan_target,
        tool_name="trivy",
        tool_version=_safe_str(tool_version),
    )

    results = raw.get("Results") or []
    for r in results:
        target_name = r.get("Target")
        component_type = r.get("Type")
        vulns = r.get("Vulnerabilities") or []
        for v in vulns:
            finding = VulnerabilityFinding(
                vulnerability_id=str(v.get("VulnerabilityID") or "").strip(),
                pkg_name=str(v.get("PkgName") or "").strip(),
                installed_version=_safe_str(v.get("InstalledVersion")),
                fixed_version=_safe_str(v.get("FixedVersion")),
                severity=Severity.from_str(v.get("Severity")),
                title=_safe_str(v.get("Title")),
                description=_safe_str(v.get("Description")),
                primary_url=_safe_str(v.get("PrimaryURL")),
                references=_safe_list_str(v.get("References")),
                target=_safe_str(target_name),
                component_type=_safe_str(component_type),
            )

            # skip broken entries
            if finding.vulnerability_id and finding.pkg_name:
                result.findings.append(finding)

    result.finalize()
    return result

