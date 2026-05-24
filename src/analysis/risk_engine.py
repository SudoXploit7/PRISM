"""
PRISM -- Risk Engine (NIST CSF 2.0 Aligned)
Computes overall account risk from CVSS-scored findings mapped to NIST functions.
"""

from typing import Any

from loguru import logger


# -- NIST CSF 2.0 Function Weights ----------------------------------------
NIST_FUNCTION_WEIGHTS: dict[str, float] = {
    "IDENTIFY":  0.15,
    "PROTECT":   0.30,
    "DETECT":    0.20,
    "RESPOND":   0.15,
    "RECOVER":   0.10,
    "GOVERN":    0.10,
}

# -- Finding Type -> NIST Function Mapping ---------------------------------
NIST_FUNCTION_MAP: dict[str, str] = {
    "SHADOW_ADMIN":             "PROTECT",
    "EXPLICIT_ADMIN":           "PROTECT",
    "PRIVESC_PATH":             "PROTECT",
    "PRIVESC_ADMIN_EXPLICIT":   "PROTECT",
    "OPEN_SECURITY_GROUP":      "PROTECT",
    "ALL_PORTS_OPEN":           "PROTECT",
    "PUBLIC_S3_BUCKET":         "PROTECT",
    "DEFAULT_SG_OPEN":          "PROTECT",
    "CLOUDTRAIL_EVASION":       "DETECT",
    "NO_CLOUDTRAIL":            "DETECT",
    "TRAIL_NOT_LOGGING":        "DETECT",
    "SINGLE_REGION_TRAIL":      "DETECT",
    "NO_LOG_VALIDATION":        "DETECT",
    "LAMBDA_ADMIN_ROLE":        "PROTECT",
    "LAMBDA_HARDCODED_SECRET":  "PROTECT",
    "LAMBDA_CODE_INJECTION":    "PROTECT",
    "SECRETS_EXFIL":            "PROTECT",
    "SSM_EXFIL":                "PROTECT",
    "CREDENTIAL_HARVESTER":     "PROTECT",
    "CROSS_ACCOUNT_ROOT_TRUST": "IDENTIFY",
    "WILDCARD_TRUST":           "IDENTIFY",
    "CROSS_ACCOUNT_TRUST":      "IDENTIFY",
    "CRITICAL_KEY_AGE":         "GOVERN",
    "OLD_ACCESS_KEY":           "GOVERN",
    "NO_MFA":                   "PROTECT",
    "GHOST_IDENTITY":           "IDENTIFY",
    "INSUFFICIENT_PERMISSIONS": "GOVERN",
}

# -- CIS AWS Foundations Benchmark Control Mapping -------------------------
CIS_CONTROL_MAP: dict[str, str] = {
    "SHADOW_ADMIN":             "CIS 1.16",
    "EXPLICIT_ADMIN":           "CIS 1.16",
    "PRIVESC_PATH":             "CIS 1.16",
    "NO_MFA":                   "CIS 1.10",
    "CRITICAL_KEY_AGE":         "CIS 1.14",
    "OLD_ACCESS_KEY":           "CIS 1.14",
    "NO_CLOUDTRAIL":            "CIS 3.1",
    "TRAIL_NOT_LOGGING":        "CIS 3.1",
    "SINGLE_REGION_TRAIL":      "CIS 3.2",
    "NO_LOG_VALIDATION":        "CIS 3.3",
    "OPEN_SECURITY_GROUP":      "CIS 5.2",
    "ALL_PORTS_OPEN":           "CIS 5.3",
    "PUBLIC_S3_BUCKET":         "CIS 2.1.2",
    "WILDCARD_TRUST":           "CIS 1.16",
    "CROSS_ACCOUNT_ROOT_TRUST": "CIS 1.16",
}


class RiskEngine:
    """Computes overall account risk score using NIST CSF 2.0 alignment."""

    def compute(self, findings: list[dict]) -> dict[str, Any]:
        """Compute overall risk score from all findings.

        Args:
            findings: List of finding dicts, each with 'type', 'severity',
                      and optionally 'cvss_score'.

        Returns:
            Risk summary dict with overall_score, rating, severity_counts,
            nist_breakdown, and cis_controls.
        """
        severity_counts: dict[str, int] = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0,
        }

        # Group CVSS scores by NIST function
        nist_scores: dict[str, list[float]] = {fn: [] for fn in NIST_FUNCTION_WEIGHTS}

        for f in findings:
            sev = f.get("severity", "MEDIUM").upper()
            if sev in severity_counts:
                severity_counts[sev] += 1

            finding_type = f.get("type", "")
            cvss = f.get("cvss_score", 0.0)
            if cvss == 0.0:
                # Fallback: derive from severity
                cvss = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}.get(sev, 5.0)

            nist_fn = NIST_FUNCTION_MAP.get(finding_type, "PROTECT")
            nist_scores[nist_fn].append(cvss)

        # Compute weighted average across NIST functions
        weighted_sum = 0.0
        nist_breakdown: dict[str, dict[str, Any]] = {}

        for fn, weight in NIST_FUNCTION_WEIGHTS.items():
            scores = nist_scores.get(fn, [])
            if scores:
                fn_avg = sum(scores) / len(scores)
                fn_score = min(fn_avg * 10, 100.0)  # Scale 0-10 CVSS to 0-100
            else:
                fn_score = 0.0

            nist_breakdown[fn] = {
                "score": round(fn_score, 1),
                "finding_count": len(scores),
                "weight": weight,
            }
            weighted_sum += fn_score * weight

        overall_score = round(min(weighted_sum, 100.0))

        # Rating
        if overall_score >= 80:
            rating = "CRITICAL"
        elif overall_score >= 60:
            rating = "HIGH"
        elif overall_score >= 40:
            rating = "ELEVATED"
        elif overall_score >= 20:
            rating = "MODERATE"
        else:
            rating = "LOW"

        total = sum(severity_counts.values())

        # Collect CIS controls
        cis_controls: list[str] = []
        seen_cis: set[str] = set()
        for f in findings:
            cis = CIS_CONTROL_MAP.get(f.get("type", ""))
            if cis and cis not in seen_cis:
                seen_cis.add(cis)
                cis_controls.append(cis)

        result = {
            "overall_score": overall_score,
            "rating": rating,
            "total_findings": total,
            "severity_counts": severity_counts,
            "nist_breakdown": nist_breakdown,
            "cis_controls_triggered": sorted(cis_controls),
        }

        logger.info(f"Risk score computed: {overall_score}/100 ({rating})")
        return result
