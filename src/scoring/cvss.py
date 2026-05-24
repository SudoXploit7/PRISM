"""
PRISM -- CVSS v3.1 Base Score Calculator
Implements the FIRST CVSS v3.1 specification for per-finding severity scoring.
"""

import math
from typing import Any

# -- CVSS v3.1 Metric Values (Table 15-19, FIRST spec) --------------------

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_SCOPE_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_SCOPE_CHANGED   = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_S  = {"U": False, "C": True}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

# -- Pre-computed CVSS vectors for common finding types --------------------

VECTOR_DB: dict[str, dict[str, str]] = {
    # Shadow admin / full admin access
    "SHADOW_ADMIN":               {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"},
    "EXPLICIT_ADMIN":             {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"},
    # Privilege escalation
    "PRIVESC_PATH":               {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"},
    "PRIVESC_ADMIN_EXPLICIT":     {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"},
    # Network exposure
    "OPEN_SECURITY_GROUP":        {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "H"},
    "ALL_PORTS_OPEN":             {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
    "PUBLIC_S3_BUCKET":           {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "L", "A": "N"},
    "DEFAULT_SG_OPEN":            {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"},
    # CloudTrail evasion
    "CLOUDTRAIL_EVASION":         {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "C", "C": "N", "I": "H", "A": "H"},
    "NO_CLOUDTRAIL":              {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "N", "I": "H", "A": "H"},
    "TRAIL_NOT_LOGGING":          {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "N", "I": "H", "A": "N"},
    "SINGLE_REGION_TRAIL":        {"AV": "N", "AC": "H", "PR": "N", "UI": "N", "S": "U", "C": "N", "I": "L", "A": "N"},
    "NO_LOG_VALIDATION":          {"AV": "N", "AC": "H", "PR": "L", "UI": "N", "S": "U", "C": "N", "I": "L", "A": "N"},
    # Lambda
    "LAMBDA_ADMIN_ROLE":          {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"},
    "LAMBDA_HARDCODED_SECRET":    {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"},
    "LAMBDA_CODE_INJECTION":      {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "N"},
    # Secrets
    "SECRETS_EXFIL":              {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"},
    "SSM_EXFIL":                  {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"},
    "CREDENTIAL_HARVESTER":       {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "N"},
    # Cross-account
    "CROSS_ACCOUNT_ROOT_TRUST":   {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "N"},
    "WILDCARD_TRUST":             {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"},
    "CROSS_ACCOUNT_TRUST":        {"AV": "N", "AC": "H", "PR": "L", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "N"},
    # Credentials
    "CRITICAL_KEY_AGE":           {"AV": "N", "AC": "H", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
    "OLD_ACCESS_KEY":             {"AV": "N", "AC": "H", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"},
    "NO_MFA":                     {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
    # Ghost identity
    "GHOST_IDENTITY":             {"AV": "N", "AC": "H", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
    # Policy fingerprints (severity mapped from risk_score in fingerprinter)
    "POLICY_FINGERPRINT_CRITICAL":{"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"},
    "POLICY_FINGERPRINT_HIGH":    {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
    "POLICY_FINGERPRINT_MEDIUM":  {"AV": "N", "AC": "H", "PR": "L", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "N"},
    # Insufficient permissions (warning)
    "INSUFFICIENT_PERMISSIONS":   {"AV": "N", "AC": "H", "PR": "H", "UI": "N", "S": "U", "C": "N", "I": "N", "A": "N"},
}


def calculate(
    av: str = "N", ac: str = "L", pr: str = "N", ui: str = "N",
    s: str = "U", c: str = "N", i: str = "N", a: str = "N",
) -> float:
    """Calculate CVSS v3.1 base score from individual metrics.

    Returns:
        Float score 0.0-10.0 rounded to one decimal.
    """
    scope_changed = _S.get(s, False)
    pr_table = _PR_SCOPE_CHANGED if scope_changed else _PR_SCOPE_UNCHANGED

    iss = 1.0 - (
        (1.0 - _CIA.get(c, 0.0))
        * (1.0 - _CIA.get(i, 0.0))
        * (1.0 - _CIA.get(a, 0.0))
    )

    if iss <= 0:
        return 0.0

    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    exploitability = (
        8.22
        * _AV.get(av, 0.85)
        * _AC.get(ac, 0.77)
        * pr_table.get(pr, 0.85)
        * _UI.get(ui, 0.85)
    )

    if impact <= 0:
        return 0.0

    if scope_changed:
        raw = min(1.08 * (impact + exploitability), 10.0)
    else:
        raw = min(impact + exploitability, 10.0)

    return math.ceil(raw * 10) / 10


def score_for_finding(finding_type: str) -> float:
    """Look up pre-computed CVSS score for a finding type.

    Args:
        finding_type: The finding type string (e.g. 'SHADOW_ADMIN').

    Returns:
        CVSS v3.1 base score (0.0-10.0).
    """
    vec = VECTOR_DB.get(finding_type)
    if not vec:
        return 0.0
    return calculate(**{k.lower(): v for k, v in vec.items()})


def vector_string(finding_type: str) -> str:
    """Return the CVSS v3.1 vector string for a finding type.

    Args:
        finding_type: The finding type string.

    Returns:
        CVSS vector string e.g. 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'
    """
    vec = VECTOR_DB.get(finding_type)
    if not vec:
        return ""
    return (
        f"CVSS:3.1/AV:{vec['AV']}/AC:{vec['AC']}/PR:{vec['PR']}/"
        f"UI:{vec['UI']}/S:{vec['S']}/C:{vec['C']}/I:{vec['I']}/A:{vec['A']}"
    )


def severity_from_score(score: float) -> str:
    """Map CVSS score to severity label per FIRST specification.

    Args:
        score: CVSS v3.1 base score.

    Returns:
        One of 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', or 'NONE'.
    """
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 0.1:
        return "LOW"
    return "NONE"
