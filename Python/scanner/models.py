
from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import Any 
from datetime import datetime, timezone



class Severity(str, Enum):
    UNKNOWN = "UNKNOWN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @staticmethod
    def from_str(value: str | None) -> "Severity":
        if not value:
            return Severity.UNKNOWN
        v = value.strip().upper()
        return Severity(v) if v in Severity._value2member_map_ else Severity.UNKNOWN

    def rank(self) -> int:
        order = {
            Severity.UNKNOWN: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return order[self]


@dataclass(frozen=True)
class ScanTarget:
    image_ref: str
    source: str = "image"     # image|running
    digest: str | None = None # optional (ImageID)


@dataclass(frozen=True)
class VulnerabilityFinding:
    vulnerability_id: str
    pkg_name: str
    installed_version: str | None
    fixed_version: str | None
    severity: Severity
    title: str | None = None
    description: str | None = None
    primary_url: str | None = None
    references: list[str] = field(default_factory=list)

    target: str | None = None          # Trivy Results.Target
    component_type: str | None = None  # Trivy Results.Type

    def has_fix(self) -> bool:
        return bool(self.fixed_version and self.fixed_version.strip())


@dataclass
class ScanSummary:
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unknown: int = 0

    def add(self, sev: Severity) -> None:
        self.total += 1
        if sev == Severity.CRITICAL:
            self.critical += 1
        elif sev == Severity.HIGH:
            self.high += 1
        elif sev == Severity.MEDIUM:
            self.medium += 1
        elif sev == Severity.LOW:
            self.low += 1
        else:
            self.unknown += 1


@dataclass
class ScanResult:
    target: ScanTarget
    tool_name: str
    tool_version: str | None
    scanned_at_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    findings: list[VulnerabilityFinding] = field(default_factory=list)
    summary: ScanSummary = field(default_factory=ScanSummary)

    def finalize(self) -> None:
        self.summary = ScanSummary()
        for f in self.findings:
            self.summary.add(f.severity)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # Enum -> string
        for f in d["findings"]:
            f["severity"] = f["severity"]
        return d


@dataclass(frozen=True)
class Policy:
    fail_on: Severity = Severity.HIGH
    require_fix: bool = True

    def should_fail(self, findings: list[VulnerabilityFinding]) -> bool:
        for f in findings:
            if f.severity.rank() >= self.fail_on.rank():
                if not self.require_fix or f.has_fix():
                    return True
        return False