"""
PRISM -- IAM Shadow Admin Detector
Identifies identities with indirect admin access through privilege escalation vectors.
"""

from typing import Any

from loguru import logger

from src.scoring.cvss import score_for_finding, vector_string

# -- Escalation vectors that grant effective admin access ------------------
ESCALATION_VECTORS: dict[str, dict[str, str]] = {
    "iam:CreatePolicyVersion": {
        "description": "Can create a new policy version granting full admin, then set it as default",
        "attack_command": "aws iam create-policy-version --policy-arn <POLICY_ARN> --policy-document '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}' --set-as-default",
        "mitre": "T1098",
    },
    "iam:SetDefaultPolicyVersion": {
        "description": "Can activate a dormant policy version that already grants admin",
        "attack_command": "aws iam set-default-policy-version --policy-arn <POLICY_ARN> --version-id v<N>",
        "mitre": "T1098",
    },
    "iam:AttachUserPolicy": {
        "description": "Can attach AdministratorAccess to any user including self",
        "attack_command": "aws iam attach-user-policy --user-name <SELF> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
        "mitre": "T1098",
    },
    "iam:AttachRolePolicy": {
        "description": "Can attach AdministratorAccess to any role then assume it",
        "attack_command": "aws iam attach-role-policy --role-name <ROLE> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
        "mitre": "T1098",
    },
    "iam:PutUserPolicy": {
        "description": "Can inject an inline admin policy into any user",
        "attack_command": "aws iam put-user-policy --user-name <SELF> --policy-name backdoor --policy-document '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}'",
        "mitre": "T1098",
    },
    "iam:PutRolePolicy": {
        "description": "Can inject an inline admin policy into any role",
        "attack_command": "aws iam put-role-policy --role-name <ROLE> --policy-name backdoor --policy-document '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}'",
        "mitre": "T1098",
    },
    "iam:UpdateAssumeRolePolicy": {
        "description": "Can modify any role's trust policy to allow self-assumption",
        "attack_command": "aws iam update-assume-role-policy --role-name <ADMIN_ROLE> --policy-document '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"<SELF_ARN>\"},\"Action\":\"sts:AssumeRole\"}]}'",
        "mitre": "T1098",
    },
    "iam:PassRole+lambda:CreateFunction": {
        "description": "Can pass an admin role to a new Lambda function, then invoke it for admin access",
        "attack_command": "aws lambda create-function --function-name backdoor --runtime python3.12 --role <ADMIN_ROLE_ARN> --handler lambda_function.handler --zip-file fileb://payload.zip",
        "mitre": "T1098",
    },
    "iam:PassRole+ec2:RunInstances": {
        "description": "Can launch an EC2 instance with an admin instance profile, then access IMDS for credentials",
        "attack_command": "aws ec2 run-instances --image-id <AMI> --instance-type t3.micro --iam-instance-profile Name=<ADMIN_PROFILE>",
        "mitre": "T1098",
    },
    "iam:CreateAccessKey": {
        "description": "Can create access keys for any user, including admin users",
        "attack_command": "aws iam create-access-key --user-name <ADMIN_USER>",
        "mitre": "T1098.001",
    },
}


class ShadowAdminDetector:
    """Detects identities with indirect administrative access."""

    def __init__(self) -> None:
        self.findings: list[dict] = []

    def analyze(
        self,
        iam_action_map: dict[str, list[str]],
        admin_roles: list[str],
    ) -> list[dict]:
        """Analyze for shadow admin identities.

        Args:
            iam_action_map: Mapping of identity name to allowed actions.
            admin_roles: List of confirmed admin role names.

        Returns:
            List of shadow admin findings.
        """
        # Check for empty action map (insufficient permissions)
        if not iam_action_map or all(len(v) == 0 for v in iam_action_map.values()):
            self.findings.append({
                "type": "INSUFFICIENT_PERMISSIONS",
                "severity": "LOW",
                "identity": "SCANNER",
                "description": (
                    "Unable to resolve effective permissions for any identity. "
                    "The scanner credentials may lack iam:GetPolicy and "
                    "iam:GetPolicyVersion permissions required for shadow admin detection."
                ),
                "escalation_vectors": [],
                "remediation": (
                    "Grant iam:GetPolicy, iam:GetPolicyVersion, and "
                    "iam:ListPolicyVersions to the scanner identity."
                ),
                "cvss_score": score_for_finding("INSUFFICIENT_PERMISSIONS"),
                "cvss_vector": vector_string("INSUFFICIENT_PERMISSIONS"),
            })
            logger.warning("Shadow admin detection: insufficient permissions to resolve actions")
            return self.findings

        for identity, actions in iam_action_map.items():
            if not actions:
                continue

            actions_lower = set(a.lower() for a in actions)
            has_wildcard = "*" in actions

            # Pass 1: Check for explicit admin (wildcard actions)
            if has_wildcard:
                cvss = score_for_finding("EXPLICIT_ADMIN")
                self.findings.append({
                    "type": "EXPLICIT_ADMIN",
                    "severity": "CRITICAL",
                    "identity": identity,
                    "description": (
                        f"Identity '{identity}' has explicit full administrator access (Action: *). "
                        f"This identity can perform any action on any resource in the account."
                    ),
                    "escalation_vectors": ["DIRECT_ADMIN"],
                    "remediation": (
                        f"Replace wildcard (*) permissions for '{identity}' with "
                        f"least-privilege policies scoped to required services and actions."
                    ),
                    "cvss_score": cvss,
                    "cvss_vector": vector_string("EXPLICIT_ADMIN"),
                    "mitre": "T1098",
                })
                continue  # No need to check escalation vectors for explicit admins

            # Pass 2: Check for shadow admin via escalation vectors
            found_vectors: list[str] = []
            for vector_action, details in ESCALATION_VECTORS.items():
                if "+" in vector_action:
                    required = vector_action.split("+")
                    if all(r.lower() in actions_lower for r in required):
                        found_vectors.append(vector_action)
                elif vector_action.lower() in actions_lower:
                    found_vectors.append(vector_action)

            if found_vectors:
                cvss = score_for_finding("SHADOW_ADMIN")
                detail_lines = []
                for v in found_vectors:
                    info = ESCALATION_VECTORS.get(v, {})
                    detail_lines.append(f"  [{v}] {info.get('description', '')}")

                self.findings.append({
                    "type": "SHADOW_ADMIN",
                    "severity": "CRITICAL",
                    "identity": identity,
                    "description": (
                        f"Identity '{identity}' is NOT a direct admin but can escalate to full admin "
                        f"through {len(found_vectors)} vector(s):\n"
                        + "\n".join(detail_lines)
                    ),
                    "escalation_vectors": found_vectors,
                    "attack_commands": [
                        ESCALATION_VECTORS[v].get("attack_command", "") for v in found_vectors
                    ],
                    "remediation": (
                        f"Remove the following permissions from '{identity}': "
                        f"{', '.join(found_vectors)}. Apply permission boundaries to prevent re-escalation."
                    ),
                    "cvss_score": cvss,
                    "cvss_vector": vector_string("SHADOW_ADMIN"),
                    "mitre": "T1098",
                })

        logger.info(f"Shadow admin detection complete: {len(self.findings)} findings")
        return self.findings
