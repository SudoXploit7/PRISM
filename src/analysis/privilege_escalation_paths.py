"""
PRISM -- Privilege Escalation Path Detector
Maps 21 privilege escalation vectors per identity.
"""

from typing import Any

from loguru import logger

from src.scoring.cvss import score_for_finding, vector_string

# -- Privilege Escalation Vectors ------------------------------------------
PRIVESC_VECTORS: list[dict[str, Any]] = [
    {
        "id": "PRIVESC-00",
        "name": "Explicit Administrator Access",
        "category": "Direct Admin",
        "severity": "CRITICAL",
        "required_actions": ["*"],
        "mitre": "T1098",
        "description": "Identity has explicit wildcard (*) access -- direct administrator without escalation needed.",
        "attack_command": "N/A -- identity already has full access",
    },
    {
        "id": "PRIVESC-01",
        "name": "Create Policy Version",
        "category": "Policy Manipulation",
        "severity": "CRITICAL",
        "required_actions": ["iam:CreatePolicyVersion"],
        "mitre": "T1098",
        "description": "Can create new admin policy version and set as default.",
        "attack_command": "aws iam create-policy-version --policy-arn <ARN> --policy-document file://admin.json --set-as-default",
    },
    {
        "id": "PRIVESC-02",
        "name": "Set Default Policy Version",
        "category": "Policy Manipulation",
        "severity": "CRITICAL",
        "required_actions": ["iam:SetDefaultPolicyVersion"],
        "mitre": "T1098",
        "description": "Can activate dormant admin policy versions.",
        "attack_command": "aws iam set-default-policy-version --policy-arn <ARN> --version-id v<N>",
    },
    {
        "id": "PRIVESC-03",
        "name": "Attach Admin User Policy",
        "category": "Policy Attachment",
        "severity": "CRITICAL",
        "required_actions": ["iam:AttachUserPolicy"],
        "mitre": "T1098",
        "description": "Can attach AdministratorAccess to self or any user.",
        "attack_command": "aws iam attach-user-policy --user-name <USER> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
    },
    {
        "id": "PRIVESC-04",
        "name": "Attach Admin Role Policy",
        "category": "Policy Attachment",
        "severity": "CRITICAL",
        "required_actions": ["iam:AttachRolePolicy"],
        "mitre": "T1098",
        "description": "Can attach AdministratorAccess to any role.",
        "attack_command": "aws iam attach-role-policy --role-name <ROLE> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
    },
    {
        "id": "PRIVESC-05",
        "name": "Inject Inline User Policy",
        "category": "Policy Injection",
        "severity": "CRITICAL",
        "required_actions": ["iam:PutUserPolicy"],
        "mitre": "T1098",
        "description": "Can inject inline admin policy into any user.",
        "attack_command": "aws iam put-user-policy --user-name <USER> --policy-name backdoor --policy-document file://admin.json",
    },
    {
        "id": "PRIVESC-06",
        "name": "Inject Inline Role Policy",
        "category": "Policy Injection",
        "severity": "CRITICAL",
        "required_actions": ["iam:PutRolePolicy"],
        "mitre": "T1098",
        "description": "Can inject inline admin policy into any role.",
        "attack_command": "aws iam put-role-policy --role-name <ROLE> --policy-name backdoor --policy-document file://admin.json",
    },
    {
        "id": "PRIVESC-07",
        "name": "Hijack Role Trust Policy",
        "category": "Trust Manipulation",
        "severity": "CRITICAL",
        "required_actions": ["iam:UpdateAssumeRolePolicy"],
        "mitre": "T1098",
        "description": "Can modify any role's trust to allow self-assumption.",
        "attack_command": "aws iam update-assume-role-policy --role-name <ADMIN_ROLE> --policy-document file://trust.json",
    },
    {
        "id": "PRIVESC-08",
        "name": "PassRole + Lambda Execution",
        "category": "Service Exploitation",
        "severity": "CRITICAL",
        "required_actions": ["iam:PassRole", "lambda:CreateFunction"],
        "mitre": "T1098",
        "description": "Can pass admin role to Lambda for code execution with elevated privileges.",
        "attack_command": "aws lambda create-function --function-name backdoor --runtime python3.12 --role <ADMIN_ROLE_ARN> --handler h.handler --zip-file fileb://payload.zip",
    },
    {
        "id": "PRIVESC-09",
        "name": "PassRole + EC2 Instance",
        "category": "Service Exploitation",
        "severity": "CRITICAL",
        "required_actions": ["iam:PassRole", "ec2:RunInstances"],
        "mitre": "T1098",
        "description": "Can launch EC2 with admin profile, access credentials via IMDS.",
        "attack_command": "aws ec2 run-instances --image-id <AMI> --instance-type t3.micro --iam-instance-profile Name=<ADMIN_PROFILE>",
    },
    {
        "id": "PRIVESC-10",
        "name": "Create Access Key",
        "category": "Credential Creation",
        "severity": "HIGH",
        "required_actions": ["iam:CreateAccessKey"],
        "mitre": "T1098.001",
        "description": "Can create access keys for any user including admin users.",
        "attack_command": "aws iam create-access-key --user-name <ADMIN_USER>",
    },
    {
        "id": "PRIVESC-11",
        "name": "Create Login Profile",
        "category": "Credential Creation",
        "severity": "HIGH",
        "required_actions": ["iam:CreateLoginProfile"],
        "mitre": "T1098.001",
        "description": "Can create console login for any user without existing password.",
        "attack_command": "aws iam create-login-profile --user-name <USER> --password 'P@ssw0rd!' --no-password-reset-required",
    },
    {
        "id": "PRIVESC-12",
        "name": "Update Login Profile",
        "category": "Credential Manipulation",
        "severity": "HIGH",
        "required_actions": ["iam:UpdateLoginProfile"],
        "mitre": "T1098.001",
        "description": "Can change console password for any user.",
        "attack_command": "aws iam update-login-profile --user-name <USER> --password 'NewP@ss!'",
    },
    {
        "id": "PRIVESC-13",
        "name": "Lambda Code Injection",
        "category": "Code Injection",
        "severity": "HIGH",
        "required_actions": ["lambda:UpdateFunctionCode"],
        "mitre": "T1525",
        "description": "Can inject code into existing Lambda functions to steal role credentials.",
        "attack_command": "aws lambda update-function-code --function-name <FN> --zip-file fileb://payload.zip",
    },
    {
        "id": "PRIVESC-14",
        "name": "Attach Group Policy",
        "category": "Policy Attachment",
        "severity": "HIGH",
        "required_actions": ["iam:AttachGroupPolicy"],
        "mitre": "T1098",
        "description": "Can attach admin policy to any group.",
        "attack_command": "aws iam attach-group-policy --group-name <GROUP> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
    },
    {
        "id": "PRIVESC-15",
        "name": "Inject Inline Group Policy",
        "category": "Policy Injection",
        "severity": "HIGH",
        "required_actions": ["iam:PutGroupPolicy"],
        "mitre": "T1098",
        "description": "Can inject inline admin policy to any group.",
        "attack_command": "aws iam put-group-policy --group-name <GROUP> --policy-name backdoor --policy-document file://admin.json",
    },
    {
        "id": "PRIVESC-16",
        "name": "Add User To Group",
        "category": "Group Manipulation",
        "severity": "MEDIUM",
        "required_actions": ["iam:AddUserToGroup"],
        "mitre": "T1098",
        "description": "Can add self to admin groups.",
        "attack_command": "aws iam add-user-to-group --group-name admins --user-name <SELF>",
    },
    {
        "id": "PRIVESC-17",
        "name": "PassRole + CloudFormation",
        "category": "Service Exploitation",
        "severity": "HIGH",
        "required_actions": ["iam:PassRole", "cloudformation:CreateStack"],
        "mitre": "T1098",
        "description": "Can create CloudFormation stack with admin role.",
        "attack_command": "aws cloudformation create-stack --stack-name backdoor --template-body file://template.yml --role-arn <ADMIN_ROLE_ARN>",
    },
    {
        "id": "PRIVESC-18",
        "name": "PassRole + Glue Dev Endpoint",
        "category": "Service Exploitation",
        "severity": "HIGH",
        "required_actions": ["iam:PassRole", "glue:CreateDevEndpoint"],
        "mitre": "T1098",
        "description": "Can create Glue endpoint with admin role for SSH access to credentials.",
        "attack_command": "aws glue create-dev-endpoint --endpoint-name backdoor --role-arn <ADMIN_ROLE_ARN> --public-key file://key.pub",
    },
    {
        "id": "PRIVESC-19",
        "name": "PassRole + SageMaker Notebook",
        "category": "Service Exploitation",
        "severity": "HIGH",
        "required_actions": ["iam:PassRole", "sagemaker:CreateNotebookInstance"],
        "mitre": "T1098",
        "description": "Can create SageMaker notebook with admin role.",
        "attack_command": "aws sagemaker create-notebook-instance --notebook-instance-name backdoor --instance-type ml.t2.medium --role-arn <ADMIN_ROLE_ARN>",
    },
    {
        "id": "PRIVESC-20",
        "name": "STS AssumeRole to Admin",
        "category": "Role Assumption",
        "severity": "HIGH",
        "required_actions": ["sts:AssumeRole"],
        "mitre": "T1078.004",
        "description": "Can assume roles that may include admin roles.",
        "attack_command": "aws sts assume-role --role-arn <ADMIN_ROLE_ARN> --role-session-name escalation",
    },
]


class PrivescPathDetector:
    """Detects privilege escalation paths for each IAM identity."""

    def __init__(self) -> None:
        self.findings: list[dict] = []

    def analyze(
        self,
        iam_action_map: dict[str, list[str]],
        admin_roles: list[str],
    ) -> dict[str, Any]:
        """Find all privilege escalation paths.

        Args:
            iam_action_map: Mapping of identity to allowed actions.
            admin_roles: List of confirmed admin role names.

        Returns:
            Dict with 'findings' and 'summary'.
        """
        for identity, actions in iam_action_map.items():
            if not actions:
                continue

            actions_lower = set(a.lower() for a in actions)
            has_wildcard = "*" in actions

            for vector in PRIVESC_VECTORS:
                required = vector["required_actions"]

                # PRIVESC-00 (explicit admin) -- only flag if wildcard present
                if vector["id"] == "PRIVESC-00":
                    if has_wildcard:
                        cvss = score_for_finding("PRIVESC_ADMIN_EXPLICIT")
                        self.findings.append({
                            "type": "PRIVESC_PATH",
                            "severity": vector["severity"],
                            "identity": identity,
                            "vector_id": vector["id"],
                            "vector_name": vector["name"],
                            "category": vector["category"],
                            "mitre": vector["mitre"],
                            "description": vector["description"],
                            "attack_command": vector["attack_command"],
                            "remediation": (
                                f"Remove explicit administrator access from '{identity}'. "
                                f"Replace with least-privilege policies."
                            ),
                            "cvss_score": cvss,
                            "cvss_vector": vector_string("PRIVESC_ADMIN_EXPLICIT"),
                        })
                    continue

                # Check if identity has all required actions
                if has_wildcard or all(r.lower() in actions_lower for r in required):

                    cvss = score_for_finding("PRIVESC_PATH")
                    self.findings.append({
                        "type": "PRIVESC_PATH",
                        "severity": vector["severity"],
                        "identity": identity,
                        "vector_id": vector["id"],
                        "vector_name": vector["name"],
                        "category": vector["category"],
                        "mitre": vector["mitre"],
                        "description": vector["description"],
                        "attack_command": vector["attack_command"],
                        "remediation": (
                            f"Remove {', '.join(required)} from '{identity}'. "
                            f"Apply permission boundaries."
                        ),
                        "cvss_score": cvss,
                        "cvss_vector": vector_string("PRIVESC_PATH"),
                    })

        # Deduplicate by identity+vector_id
        seen: set[str] = set()
        unique: list[dict] = []
        for f in self.findings:
            key = f"{f['identity']}:{f['vector_id']}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        self.findings = unique

        summary = {
            "total_paths": len(self.findings),
            "affected_identities": len(set(f["identity"] for f in self.findings)),
            "critical_paths": sum(1 for f in self.findings if f["severity"] == "CRITICAL"),
        }

        logger.info(
            f"Privilege escalation analysis complete: {summary['total_paths']} paths "
            f"across {summary['affected_identities']} identities"
        )

        return {"findings": self.findings, "summary": summary}