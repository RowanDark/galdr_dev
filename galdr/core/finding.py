from dataclasses import dataclass
from typing import Optional

@dataclass
class SecurityFinding:
    """
    A dataclass to hold the details of a security finding.
    This is used by both passive and active scanners.
    """
    severity: str  # 'Critical', 'High', 'Medium', 'Low', 'Info'
    confidence: str  # 'Certain', 'Firm', 'Tentative'
    title: str
    description: str
    evidence: str
    remediation: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
