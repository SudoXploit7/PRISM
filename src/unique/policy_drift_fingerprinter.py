"""
PRISM -- Policy Drift Fingerprinter (WORLD-FIRST)
Hashes IAM policies and matches against a built-in threat intelligence
database of known dangerous policy patterns.
"""

import hashlib
import json
from typing import Any

from loguru import logger

# -- Threat Intelligence Fingerprint Database ------------------------------
# 20+ known dangerous policy patterns
THREAT_FINGERPRINTS: list[dict[str, Any]] = [
    {
        "name": "God Mode",
        "actions": ["*"],
        "threat_category": "Full Admin Access",
        "risk_score": 100,
        "description": "Policy grants unrestricted access to all services and resources.",
        "remediation": "Replace with least-privilege policy scoped to specific services and actions.",
    },
    {
        "name": "CloudTrail Killer",
        "actions": ["cloudtrail:DeleteTrail", "cloudtrail:StopLogging"],
        "threat_category": "Audit Evasion",
        "risk_score": 95,
        "description": "Can disable or destroy CloudTrail logging, removing all audit visibility.",
        "remediation": "Remove CloudTrail modification permissions. Apply SCP to deny these actions.",
    },
    {
        "name": "Credential Harvester",
        "actions": ["secretsmanager:GetSecretValue", "ssm:GetParameter"],
        "threat_category": "Data Exfiltration",
        "risk_score": 80,
        "description": "Can read all secrets and SSM parameters -- full credential harvesting capability.",
        "remediation": "Restrict to specific secret ARNs and SSM parameter paths.",
    },
    {
        "name": "Account Takeover Prep",
        "actions": ["iam:CreateUser", "iam:AttachUserPolicy"],
        "threat_category": "Persistence",
        "risk_score": 90,
        "description": "Can create new admin users for persistent backdoor access.",
        "remediation": "Remove iam:CreateUser and iam:AttachUserPolicy. Use permission boundaries.",
    },
    {
        "name": "Persistence Backdoor",
        "actions": ["iam:CreateAccessKey", "iam:CreateLoginProfile"],
        "threat_category": "Persistence",
        "risk_score": 85,
        "description": "Can create access keys and console logins for other users -- credential theft vector.",
        "remediation": "Restrict these actions to self-service only using IAM conditions.",
    },
    {
        "name": "Exfiltration Ready",
        "actions": ["s3:GetObject", "s3:PutBucketPolicy", "s3:PutObject"],
        "threat_category": "Data Exfiltration",
        "risk_score": 75,
        "description": "Can read S3 data and modify bucket policies to allow external access.",
        "remediation": "Restrict S3 access to specific buckets. Block PutBucketPolicy.",
    },
    {
        "name": "Lateral Movement",
        "actions": ["sts:AssumeRole", "iam:PassRole", "ec2:RunInstances"],
        "threat_category": "Lateral Movement",
        "risk_score": 85,
        "description": "Can assume roles, pass roles to services, and launch EC2 instances -- full lateral movement.",
        "remediation": "Restrict AssumeRole to specific role ARNs. Remove PassRole or scope to specific roles.",
    },
    {
        "name": "CloudWatch Blinder",
        "actions": ["logs:DeleteLogGroup", "cloudwatch:DeleteAlarms"],
        "threat_category": "Audit Evasion",
        "risk_score": 80,
        "description": "Can delete CloudWatch log groups and alarms, blinding monitoring systems.",
        "remediation": "Remove log and alarm deletion permissions. Protect with SCP.",
    },
    {
        "name": "GuardDuty Killer",
        "actions": ["guardduty:DeleteDetector", "guardduty:UpdateDetector"],
        "threat_category": "Audit Evasion",
        "risk_score": 90,
        "description": "Can disable GuardDuty, removing automated threat detection.",
        "remediation": "Remove GuardDuty modification permissions. Protect at organization level.",
    },
    {
        "name": "Network Manipulator",
        "actions": ["ec2:AuthorizeSecurityGroupIngress", "ec2:CreateSecurityGroup"],
        "threat_category": "Network Exploitation",
        "risk_score": 70,
        "description": "Can modify security groups to open network access for attacker infrastructure.",
        "remediation": "Restrict security group modifications to specific VPCs.",
    },
    {
        "name": "KMS Key Destroyer",
        "actions": ["kms:ScheduleKeyDeletion", "kms:DisableKey"],
        "threat_category": "Destructive",
        "risk_score": 90,
        "description": "Can schedule KMS key deletion, rendering encrypted data permanently inaccessible.",
        "remediation": "Remove KMS deletion permissions. Enable key deletion protection.",
    },
    {
        "name": "Config Disabler",
        "actions": ["config:StopConfigurationRecorder", "config:DeleteConfigRule"],
        "threat_category": "Compliance Evasion",
        "risk_score": 75,
        "description": "Can disable Config, removing compliance monitoring and drift detection.",
        "remediation": "Remove Config modification permissions. Protect with SCP.",
    },
    {
        "name": "IAM Policy Manipulator",
        "actions": ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"],
        "threat_category": "Privilege Escalation",
        "risk_score": 95,
        "description": "Can create and activate new policy versions with admin permissions.",
        "remediation": "Remove policy version manipulation permissions. Apply permission boundaries.",
    },
    {
        "name": "Trust Policy Hijacker",
        "actions": ["iam:UpdateAssumeRolePolicy"],
        "threat_category": "Privilege Escalation",
        "risk_score": 90,
        "description": "Can modify any role's trust policy to allow self-assumption.",
        "remediation": "Remove UpdateAssumeRolePolicy permission. Apply SCP.",
    },
    {
        "name": "Lambda Code Injector",
        "actions": ["lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration"],
        "threat_category": "Code Injection",
        "risk_score": 80,
        "description": "Can modify Lambda function code and configuration to inject backdoors.",
        "remediation": "Restrict Lambda modification to specific function ARNs.",
    },
    {
        "name": "S3 Data Destroyer",
        "actions": ["s3:DeleteObject", "s3:DeleteBucket"],
        "threat_category": "Destructive",
        "risk_score": 85,
        "description": "Can delete S3 objects and entire buckets -- ransomware-style data destruction.",
        "remediation": "Enable S3 versioning and MFA Delete. Restrict deletion permissions.",
    },
    {
        "name": "Organization Manipulator",
        "actions": ["organizations:CreateAccount", "organizations:LeaveOrganization"],
        "threat_category": "Organization Control",
        "risk_score": 95,
        "description": "Can create accounts or detach from organization, bypassing SCPs.",
        "remediation": "Remove organization management permissions from non-root accounts.",
    },
    {
        "name": "DNS Hijacker",
        "actions": ["route53:ChangeResourceRecordSets"],
        "threat_category": "Network Exploitation",
        "risk_score": 80,
        "description": "Can modify DNS records for phishing, traffic interception, or domain takeover.",
        "remediation": "Restrict Route53 modifications to specific hosted zones.",
    },
    {
        "name": "SNS Notification Abuser",
        "actions": ["sns:Publish", "sns:Subscribe"],
        "threat_category": "Social Engineering",
        "risk_score": 50,
        "description": "Can publish to SNS topics and subscribe endpoints, enabling phishing or data exfiltration.",
        "remediation": "Restrict SNS access to specific topics.",
    },
    {
        "name": "STS Token Factory",
        "actions": ["sts:GetSessionToken", "sts:GetFederationToken"],
        "threat_category": "Credential Access",
        "risk_score": 60,
        "description": "Can generate temporary session tokens for creating additional credential sets.",
        "remediation": "Restrict STS token generation with IP and MFA conditions.",
    },
    {
        "name": "EC2 Crypto Miner",
        "actions": ["ec2:RunInstances", "ec2:DescribeInstances"],
        "threat_category": "Financial Abuse",
        "risk_score": 70,
        "description": "Can launch EC2 instances for cryptocurrency mining, causing significant billing impact.",
        "remediation": "Set EC2 instance type restrictions. Enable billing alerts.",
    },
]


class PolicyDriftFingerprinter:
    """Fingerprints IAM policies against a threat intelligence database.

    Hashes each policy document and scans for action combinations that
    match known dangerous patterns. Unique to PRISM -- no other tool
    maintains a fingerprint database of dangerous policy patterns.
    """

    def fingerprint(self, policies: list[dict]) -> dict[str, Any]:
        """Fingerprint all policies against threat database.

        Args:
            policies: List of IAM policy dicts with Document field.

        Returns:
            Fingerprint analysis results.
        """
        fingerprints: list[dict] = []

        for policy in policies:
            policy_name = policy.get("PolicyName", "")
            policy_arn = policy.get("Arn", "")
            document = policy.get("Document", {})

            if not document:
                continue

            # Hash the policy
            policy_hash = self._hash_policy(document)

            # Extract all actions from the policy
            policy_actions = self._extract_actions(document)

            # Match against fingerprint database
            for fp in THREAT_FINGERPRINTS:
                if self._matches_fingerprint(policy_actions, fp["actions"]):
                    matched_actions = [
                        a for a in policy_actions
                        if any(fa.lower() == a.lower() or fa == "*" for fa in fp["actions"])
                    ]

                    fingerprints.append({
                        "policy_name": policy_name,
                        "policy_arn": policy_arn,
                        "matched_pattern": fp["name"],
                        "matched_actions": matched_actions or fp["actions"],
                        "threat_category": fp["threat_category"],
                        "risk_score": fp["risk_score"],
                        "policy_hash": policy_hash,
                        "description": fp["description"],
                        "remediation": fp["remediation"],
                    })

        # Sort by risk score
        fingerprints.sort(key=lambda x: x["risk_score"], reverse=True)

        result = {
            "total_policies_scanned": len(policies),
            "dangerous_fingerprints_found": len(fingerprints),
            "unique_patterns_matched": len(set(f["matched_pattern"] for f in fingerprints)),
            "fingerprints": fingerprints,
            "threat_categories": self._count_categories(fingerprints),
        }

        logger.info(
            f"Policy fingerprinting complete: {len(fingerprints)} dangerous "
            f"fingerprints across {len(policies)} policies"
        )
        return result

    def fingerprint_from_action_map(
        self, iam_action_map: dict[str, list[str]]
    ) -> dict[str, Any]:
        """Fingerprint effective permissions against threat database.

        This is the fallback method when raw policy documents are unavailable
        or empty. It uses the already-resolved iam_action_map to match
        identities against dangerous action patterns.

        Args:
            iam_action_map: Identity to list of allowed actions.

        Returns:
            Fingerprint analysis results by identity.
        """
        fingerprints: list[dict] = []

        for identity, actions in iam_action_map.items():
            if not actions:
                continue

            for fp in THREAT_FINGERPRINTS:
                if self._matches_fingerprint(actions, fp["actions"]):
                    matched_actions = [
                        a for a in actions
                        if any(fa.lower() == a.lower() or fa == "*" for fa in fp["actions"])
                    ]

                    fingerprints.append({
                        "policy_name": f"Effective:{identity}",
                        "policy_arn": "",
                        "matched_pattern": fp["name"],
                        "matched_actions": matched_actions or fp["actions"],
                        "threat_category": fp["threat_category"],
                        "risk_score": fp["risk_score"],
                        "policy_hash": "",
                        "description": f"{identity}: {fp['description']}",
                        "remediation": fp["remediation"],
                    })

        fingerprints.sort(key=lambda x: x["risk_score"], reverse=True)

        result = {
            "total_policies_scanned": len(iam_action_map),
            "dangerous_fingerprints_found": len(fingerprints),
            "unique_patterns_matched": len(set(f["matched_pattern"] for f in fingerprints)),
            "fingerprints": fingerprints,
            "threat_categories": self._count_categories(fingerprints),
        }

        logger.info(
            f"Action-map fingerprinting complete: {len(fingerprints)} dangerous "
            f"patterns across {len(iam_action_map)} identities"
        )
        return result

    def _hash_policy(self, document: dict) -> str:
        """Compute SHA-256 hash of normalized policy JSON."""
        normalized = json.dumps(document, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(normalized.encode()).hexdigest()[:16]

    def _extract_actions(self, document: dict) -> list[str]:
        """Extract all allowed actions from a policy document."""
        actions: list[str] = []
        for statement in document.get("Statement", []):
            if statement.get("Effect") != "Allow":
                continue
            action = statement.get("Action", [])
            if isinstance(action, str):
                actions.append(action)
            elif isinstance(action, list):
                actions.extend(action)
        return actions

    def _matches_fingerprint(
        self, policy_actions: list[str], fingerprint_actions: list[str]
    ) -> bool:
        """Check if policy actions match a fingerprint pattern."""
        policy_lower = set(a.lower() for a in policy_actions)
        has_wildcard = "*" in policy_lower

        # Check if all fingerprint actions are present
        for fp_action in fingerprint_actions:
            if fp_action == "*":
                if has_wildcard:
                    return True
                continue
            if fp_action.lower() not in policy_lower and not has_wildcard:
                return False

        return True

    def _count_categories(self, fingerprints: list[dict]) -> dict[str, int]:
        """Count fingerprints by threat category."""
        categories: dict[str, int] = {}
        for fp in fingerprints:
            cat = fp.get("threat_category", "Unknown")
            categories[cat] = categories.get(cat, 0) + 1
        return categories
