"""
PRISM -- Cross-Account Trust Analyzer
Detects risky cross-account role trust relationships.
"""

import re
from typing import Any

from loguru import logger

from src.scoring.cvss import score_for_finding, vector_string


def _mask_account_id(text: str) -> str:
    """Mask 12-digit AWS account IDs in user-facing strings."""
    return re.sub(r"\b(\d{3})\d{6}(\d{3})\b", r"\1******\2", text)


class CrossAccountAnalyzer:
    """Analyzes cross-account trust relationships for security risks."""

    def __init__(self, own_account_id: str = "") -> None:
        self.own_account_id = own_account_id
        self.findings: list[dict] = []

    def analyze(
        self,
        trusts: list[tuple[str, str, str]],
        roles: list[str],
    ) -> list[dict]:
        """Analyze trust relationships for cross-account risks.

        Args:
            trusts: List of (source, target_role, relationship_type) tuples.
            roles: List of role names in the account.

        Returns:
            List of cross-account trust findings.
        """
        for src, dst, rel in trusts:
            if rel != "AssumeRole":
                continue

            # Extract account ID from ARN
            if src.startswith("arn:aws:iam::") and ":root" in src:
                foreign_account = src.split(":")[4]
                if foreign_account and foreign_account != self.own_account_id:
                    masked = _mask_account_id(foreign_account)
                    cvss = score_for_finding("CROSS_ACCOUNT_ROOT_TRUST")
                    self.findings.append({
                        "type": "CROSS_ACCOUNT_ROOT_TRUST",
                        "severity": "HIGH",
                        "identity": dst,
                        "resource": _mask_account_id(src),
                        "mitre": "T1078.004",
                        "description": (
                            f"Role '{dst}' trusts the ROOT of external account {masked}. "
                            f"Any identity in that account can assume this role. "
                            f"If the external account is compromised, this account is also at risk."
                        ),
                        "remediation": (
                            f"Restrict the trust policy of '{dst}' to specific roles/users "
                            f"in the external account instead of root. Add ExternalId condition."
                        ),
                        "cvss_score": cvss,
                        "cvss_vector": vector_string("CROSS_ACCOUNT_ROOT_TRUST"),
                    })

            # Check for wildcard principal (anyone can assume)
            if src == "*":
                cvss = score_for_finding("WILDCARD_TRUST")
                self.findings.append({
                    "type": "WILDCARD_TRUST",
                    "severity": "CRITICAL",
                    "identity": dst,
                    "resource": "*",
                    "mitre": "T1078.004",
                    "description": (
                        f"Role '{dst}' has a wildcard (*) trust policy -- ANY identity "
                        f"in ANY account can assume this role. Critical misconfiguration."
                    ),
                    "remediation": (
                        f"Immediately update the trust policy of '{dst}' to specify exact "
                        f"principal ARNs: aws iam update-assume-role-policy "
                        f"--role-name {dst} --policy-document '<restricted_policy>'"
                    ),
                    "cvss_score": cvss,
                    "cvss_vector": vector_string("WILDCARD_TRUST"),
                })

            # External account (not root, but still cross-account)
            if src.startswith("arn:aws:iam::"):
                foreign_account = src.split(":")[4]
                if foreign_account and foreign_account != self.own_account_id and ":root" not in src:
                    masked = _mask_account_id(foreign_account)
                    cvss = score_for_finding("CROSS_ACCOUNT_TRUST")
                    self.findings.append({
                        "type": "CROSS_ACCOUNT_TRUST",
                        "severity": "MEDIUM",
                        "identity": dst,
                        "resource": _mask_account_id(src),
                        "mitre": "T1078.004",
                        "description": (
                            f"Role '{dst}' can be assumed by an identity from external account "
                            f"{masked}. Verify this trust is intentional and the "
                            f"external identity is properly secured."
                        ),
                        "remediation": (
                            f"Review trust relationship for '{dst}'. Consider adding "
                            f"sts:ExternalId condition to prevent confused deputy attacks."
                        ),
                        "cvss_score": cvss,
                        "cvss_vector": vector_string("CROSS_ACCOUNT_TRUST"),
                    })

        logger.info(f"Cross-account analysis complete: {len(self.findings)} findings")
        return self.findings
