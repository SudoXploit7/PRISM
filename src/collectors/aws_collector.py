"""
PRISM - AWS Collector
Collects IAM, EC2, S3, Lambda, Secrets Manager, SSM, CloudTrail, VPC data.
Accepts (access_key, secret_key, region) as constructor params.
"""

import json
from typing import Any, Optional

import boto3
import botocore.exceptions
from loguru import logger

# ── Constants ────────────────────────────────────────────────────────────
CREDENTIAL_REPORT_MAX_RETRIES: int = 10
CREDENTIAL_REPORT_WAIT_SECONDS: int = 2


class AWSCollector:
    """Collects AWS resource data using explicit credentials passed at runtime."""

    def __init__(self, access_key: str, secret_key: str, region: str) -> None:
        self._access_key = access_key
        self._secret_key = secret_key
        self._region     = region
        """Initialize boto3 session with user-supplied credentials.

        Args:
            access_key: AWS Access Key ID.
            secret_key: AWS Secret Access Key.
            region: AWS region name (e.g. us-east-1).
        """
        self.session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
        )
        self.iam = self.session.client("iam")
        self.sts = self.session.client("sts")
        self.region = region
        self._account_id: Optional[str] = None

    # ─── Helpers ─────────────────────────────────────────────────────────

    def _client(self, service: str) -> Any:
        """Create a boto3 client for the given service using session creds."""
        return self.session.client(service)

    # ─── Account Context ─────────────────────────────────────────────────

    def get_caller_identity(self) -> dict:
        """Validate credentials and return caller identity."""
        try:
            identity = self.sts.get_caller_identity()
            self._account_id = identity["Account"]
            return {
                "Account": identity["Account"],
                "Arn": identity["Arn"],
                "UserId": identity["UserId"],
            }
        except botocore.exceptions.ClientError as e:
            logger.error(f"STS GetCallerIdentity failed: {e}")
            raise
        except botocore.exceptions.NoCredentialsError as e:
            logger.error(f"No credentials: {e}")
            raise

    def get_account_id(self) -> str:
        """Return cached account ID or fetch it."""
        if not self._account_id:
            self.get_caller_identity()
        return self._account_id or ""

    # ─── IAM Users ───────────────────────────────────────────────────────

    def get_users(self) -> list[str]:
        """List all IAM user names using pagination."""
        users: list[str] = []
        try:
            paginator = self.iam.get_paginator("list_users")
            for page in paginator.paginate():
                for u in page["Users"]:
                    users.append(u["UserName"])
            logger.info(f"Collected {len(users)} IAM users")
        except botocore.exceptions.ClientError as e:
            logger.warning(f"Could not list IAM users: {e}")
        return users

    def get_user_details(self) -> list[dict]:
        """List IAM users with full metadata."""
        users: list[dict] = []
        try:
            paginator = self.iam.get_paginator("list_users")
            for page in paginator.paginate():
                for u in page["Users"]:
                    users.append({
                        "UserName": u["UserName"],
                        "UserId": u["UserId"],
                        "Arn": u["Arn"],
                        "CreateDate": u["CreateDate"].isoformat()
                        if hasattr(u["CreateDate"], "isoformat") else str(u["CreateDate"]),
                        "PasswordLastUsed": u.get("PasswordLastUsed", "").isoformat()
                        if hasattr(u.get("PasswordLastUsed", ""), "isoformat")
                        else str(u.get("PasswordLastUsed", "N/A")),
                    })
        except botocore.exceptions.ClientError as e:
            logger.warning(f"Could not list IAM user details: {e}")
        return users

    # ─── IAM Roles ───────────────────────────────────────────────────────

    def get_roles(self) -> list[str]:
        """List all IAM role names using pagination."""
        roles: list[str] = []
        try:
            paginator = self.iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for r in page["Roles"]:
                    roles.append(r["RoleName"])
            logger.info(f"Collected {len(roles)} IAM roles")
        except botocore.exceptions.ClientError as e:
            logger.warning(f"Could not list IAM roles: {e}")
        return roles

    def get_role_details(self) -> list[dict]:
        """List IAM roles with trust policies."""
        roles: list[dict] = []
        try:
            paginator = self.iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for r in page["Roles"]:
                    roles.append({
                        "RoleName": r["RoleName"],
                        "RoleId": r["RoleId"],
                        "Arn": r["Arn"],
                        "CreateDate": r["CreateDate"].isoformat()
                        if hasattr(r["CreateDate"], "isoformat") else str(r["CreateDate"]),
                        "AssumeRolePolicyDocument": r.get("AssumeRolePolicyDocument", {}),
                    })
        except botocore.exceptions.ClientError as e:
            logger.warning(f"Could not list IAM role details: {e}")
        return roles

    # ─── Trust Relationships ─────────────────────────────────────────────

    def get_trust_relationships(self) -> list[tuple[str, str, str]]:
        """Map all role trust relationships as (source, target_role, rel_type)."""
        trusts: list[tuple[str, str, str]] = []
        try:
            paginator = self.iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page["Roles"]:
                    role_name = role["RoleName"]
                    policy = role.get("AssumeRolePolicyDocument", {})
                    for stmt in policy.get("Statement", []):
                        principal = stmt.get("Principal", {})
                        aws_principals = principal.get("AWS", [])
                        if isinstance(aws_principals, str):
                            aws_principals = [aws_principals]
                        services = principal.get("Service", [])
                        if isinstance(services, str):
                            services = [services]
                        for p in aws_principals:
                            trusts.append((p, role_name, "AssumeRole"))
                        for s in services:
                            trusts.append((s, role_name, "ServiceTrust"))
            logger.info(f"Mapped {len(trusts)} trust relationships")
        except botocore.exceptions.ClientError as e:
            logger.warning(f"Could not map trust relationships: {e}")
        return trusts

    # ─── Policy Statements ───────────────────────────────────────────────

    def get_all_policy_statements(self, identity: str, is_user: bool = True) -> list[dict]:
        """Retrieve all inline + attached policy statements for a user or role."""
        statements: list[dict] = []
        try:
            if is_user:
                attached = self.iam.list_attached_user_policies(UserName=identity)
                inline = self.iam.list_user_policies(UserName=identity)
            else:
                attached = self.iam.list_attached_role_policies(RoleName=identity)
                inline = self.iam.list_role_policies(RoleName=identity)
        except botocore.exceptions.ClientError as e:
            logger.debug(f"Could not get policies for {identity}: {e}")
            return statements

        # Attached managed policies
        for p in attached.get("AttachedPolicies", []):
            try:
                pol = self.iam.get_policy(PolicyArn=p["PolicyArn"])
                ver = self.iam.get_policy_version(
                    PolicyArn=p["PolicyArn"],
                    VersionId=pol["Policy"]["DefaultVersionId"],
                )
                doc = ver["PolicyVersion"]["Document"]
                for stmt in doc.get("Statement", []):
                    stmt["_policy_name"] = p.get("PolicyName", "")
                    stmt["_policy_arn"] = p.get("PolicyArn", "")
                    statements.append(stmt)
            except botocore.exceptions.ClientError as e:
                logger.debug(f"Could not read policy {p['PolicyArn']}: {e}")

        # Inline policies
        policy_names = inline.get("PolicyNames", [])
        for name in policy_names:
            try:
                if is_user:
                    pol = self.iam.get_user_policy(UserName=identity, PolicyName=name)
                else:
                    pol = self.iam.get_role_policy(RoleName=identity, PolicyName=name)
                for stmt in pol["PolicyDocument"].get("Statement", []):
                    stmt["_policy_name"] = name
                    stmt["_policy_arn"] = f"inline:{name}"
                    statements.append(stmt)
            except botocore.exceptions.ClientError as e:
                logger.debug(f"Could not read inline policy {name}: {e}")

        return statements

    def get_all_policies(self) -> list[dict]:
        """List all customer-managed and AWS-managed policies attached to identities."""
        policies: list[dict] = []
        try:
            paginator = self.iam.get_paginator("list_policies")
            for page in paginator.paginate(Scope="Local"):
                for p in page["Policies"]:
                    policy_data: dict = {
                        "PolicyName": p["PolicyName"],
                        "PolicyId": p["PolicyId"],
                        "Arn": p["Arn"],
                        "AttachmentCount": p.get("AttachmentCount", 0),
                        "DefaultVersionId": p.get("DefaultVersionId", "v1"),
                    }
                    # Fetch the document
                    try:
                        ver = self.iam.get_policy_version(
                            PolicyArn=p["Arn"],
                            VersionId=p.get("DefaultVersionId", "v1"),
                        )
                        policy_data["Document"] = ver["PolicyVersion"]["Document"]
                    except botocore.exceptions.ClientError:
                        policy_data["Document"] = {}
                    policies.append(policy_data)
            logger.info(f"Collected {len(policies)} customer-managed policies")
        except botocore.exceptions.ClientError as e:
            logger.warning(f"Could not list policies: {e}")
        return policies

    # ─── IAM Action Map Builder ──────────────────────────────────────────

    def build_iam_action_map(self, users: list[str], roles: list[str]) -> dict[str, list[str]]:
        """Build identityactions mapping for all users and roles."""
        iam_action_map: dict[str, list[str]] = {}
        for u in users:
            stmts = self.get_all_policy_statements(u, is_user=True)
            actions: list[str] = []
            for s in stmts:
                if s.get("Effect") != "Allow":
                    continue
                a = s.get("Action", [])
                actions.extend(a if isinstance(a, list) else [a])
            iam_action_map[u] = actions

        for r in roles:
            stmts = self.get_all_policy_statements(r, is_user=False)
            actions = []
            for s in stmts:
                if s.get("Effect") != "Allow":
                    continue
                a = s.get("Action", [])
                actions.extend(a if isinstance(a, list) else [a])
            iam_action_map[r] = actions

        logger.info(f"Built IAM action map for {len(iam_action_map)} identities")
        return iam_action_map

    def has_admin_policy(self, identity: str, is_user: bool = True) -> bool:
        """Check if identity has Action=* Resource=*."""
        statements = self.get_all_policy_statements(identity, is_user)
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            action = stmt.get("Action", [])
            resource = stmt.get("Resource", [])
            if isinstance(action, str):
                action = [action]
            if isinstance(resource, str):
                resource = [resource]
            if "*" in action and "*" in resource:
                return True
        return False

    # ─── Credential Report ───────────────────────────────────────────────

    def get_credential_report(self) -> list[dict]:
        """Generate and parse IAM credential report."""
        import csv
        import io
        import time

        try:
            self.iam.generate_credential_report()
            for _ in range(CREDENTIAL_REPORT_MAX_RETRIES):
                try:
                    resp = self.iam.get_credential_report()
                    content = resp["Content"].decode("utf-8")
                    reader = csv.DictReader(io.StringIO(content))
                    report = list(reader)
                    logger.info(f"Credential report: {len(report)} entries")
                    return report
                except self.iam.exceptions.CredentialReportNotReadyException:
                    time.sleep(CREDENTIAL_REPORT_WAIT_SECONDS)
        except botocore.exceptions.ClientError as e:
            logger.warning(f"Could not generate credential report: {e}")
        return []

    def get_service_last_accessed(self, arn: str) -> list[dict]:
        """Get service-last-accessed details for an IAM entity."""
        import time

        try:
            resp = self.iam.generate_service_last_accessed_details(Arn=arn)
            job_id = resp["JobId"]
            for _ in range(CREDENTIAL_REPORT_MAX_RETRIES):
                result = self.iam.get_service_last_accessed_details(JobId=job_id)
                if result["JobStatus"] == "COMPLETED":
                    return result.get("ServicesLastAccessed", [])
                time.sleep(CREDENTIAL_REPORT_WAIT_SECONDS)
        except botocore.exceptions.ClientError as e:
            logger.debug(f"Could not get service last accessed for {arn}: {e}")
        return []

    # ─── Access Key Metadata ─────────────────────────────────────────────

    def get_access_key_metadata(self, users: list[str]) -> list[dict]:
        """Get access key age and last-used for all users."""
        results: list[dict] = []
        for username in users:
            try:
                keys_response = self.iam.list_access_keys(UserName=username)
                key_list: list[dict] = []
                for key in keys_response.get("AccessKeyMetadata", []):
                    key_info: dict = {
                        "AccessKeyId": key["AccessKeyId"],
                        "Status": key["Status"],
                        "CreateDate": key["CreateDate"].isoformat()
                        if hasattr(key["CreateDate"], "isoformat") else str(key["CreateDate"]),
                    }
                    try:
                        last_used = self.iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])
                        lu_info = last_used.get("AccessKeyLastUsed", {})
                        if lu_info.get("LastUsedDate"):
                            key_info["LastUsedDate"] = lu_info["LastUsedDate"].isoformat() \
                                if hasattr(lu_info["LastUsedDate"], "isoformat") \
                                else str(lu_info["LastUsedDate"])
                    except botocore.exceptions.ClientError:
                        pass
                    key_list.append(key_info)
                results.append({"UserName": username, "AccessKeys": key_list})
            except botocore.exceptions.ClientError as e:
                logger.debug(f"Could not get keys for {username}: {e}")
        logger.info(f"Collected access key metadata for {len(results)} users")
        return results

    # ─── MFA Status ──────────────────────────────────────────────────────

    def get_user_mfa_status(self, users: list[str]) -> dict[str, bool]:
        """Check MFA enrollment for each user."""
        mfa_map: dict[str, bool] = {}
        for username in users:
            try:
                response = self.iam.list_mfa_devices(UserName=username)
                mfa_map[username] = len(response.get("MFADevices", [])) > 0
            except botocore.exceptions.ClientError as e:
                logger.debug(f"Could not check MFA for {username}: {e}")
                mfa_map[username] = False
        logger.info(f"Collected MFA status for {len(mfa_map)} users")
        return mfa_map

    # ─── Lambda Functions ────────────────────────────────────────────────

    def get_lambda_functions(self) -> list[dict]:
        """Collect all Lambda functions with configuration."""
        functions: list[dict] = []
        try:
            client = self._client("lambda")
            paginator = client.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page["Functions"]:
                    functions.append({
                        "FunctionName": fn["FunctionName"],
                        "FunctionArn": fn["FunctionArn"],
                        "Role": fn.get("Role", ""),
                        "Runtime": fn.get("Runtime", ""),
                        "Handler": fn.get("Handler", ""),
                        "LastModified": fn.get("LastModified", ""),
                        "Environment": fn.get("Environment", {}),
                    })
            logger.info(f"Collected {len(functions)} Lambda functions")
        except botocore.exceptions.ClientError as e:
            logger.warning(f"Could not collect Lambda functions: {e}")
        return functions

    # ─── Secrets Manager ─────────────────────────────────────────────────

    def get_secrets_list(self) -> list[dict]:
        """List all secrets in Secrets Manager (metadata only)."""
        secrets: list[dict] = []
        try:
            client = self._client("secretsmanager")
            paginator = client.get_paginator("list_secrets")
            for page in paginator.paginate():
                for s in page["SecretList"]:
                    secrets.append({
                        "Name": s["Name"],
                        "ARN": s["ARN"],
                        "Description": s.get("Description", ""),
                        "LastAccessed": str(s.get("LastAccessedDate", "")),
                    })
            logger.info(f"Collected {len(secrets)} secrets")
        except botocore.exceptions.ClientError as e:
            logger.warning(f"Could not collect Secrets Manager data: {e}")
        return secrets

    # ─── SSM Parameters ──────────────────────────────────────────────────

    def get_ssm_parameters(self) -> list[dict]:
        """List all SSM parameters (metadata only)."""
        params: list[dict] = []
        try:
            client = self._client("ssm")
            paginator = client.get_paginator("describe_parameters")
            for page in paginator.paginate():
                for p in page["Parameters"]:
                    params.append({
                        "Name": p["Name"],
                        "Type": p["Type"],
                        "Description": p.get("Description", ""),
                        "LastModified": str(p.get("LastModifiedDate", "")),
                    })
            logger.info(f"Collected {len(params)} SSM parameters")
        except botocore.exceptions.ClientError as e:
            logger.warning(f"Could not collect SSM parameters: {e}")
        return params

    # ─── CloudTrail ──────────────────────────────────────────────────────

    def get_cloudtrail_status(self) -> list[dict]:
        """Get CloudTrail trails and logging status."""
        trails: list[dict] = []
        try:
            client = self._client("cloudtrail")
            response = client.describe_trails()
            for trail in response.get("trailList", []):
                try:
                    status = client.get_trail_status(Name=trail["TrailARN"])
                except botocore.exceptions.ClientError:
                    status = {}
                trails.append({
                    "Name": trail["Name"],
                    "ARN": trail["TrailARN"],
                    "S3Bucket": trail.get("S3BucketName", ""),
                    "IsMultiRegion": trail.get("IsMultiRegionTrail", False),
                    "IsLogging": status.get("IsLogging", False),
                    "LatestDelivery": str(status.get("LatestDeliveryTime", "")),
                    "HasLogFileValidation": trail.get("LogFileValidationEnabled", False),
                    "CloudWatchLogsLogGroupArn": trail.get("CloudWatchLogsLogGroupArn", ""),
                })
            logger.info(f"Collected {len(trails)} CloudTrail trails")
        except botocore.exceptions.ClientError as e:
            logger.warning(f"Could not collect CloudTrail data: {e}")
        return trails

    # ─── S3 Buckets ──────────────────────────────────────────────────────

    def get_s3_buckets(self) -> list[dict]:
        """List all S3 buckets."""
        buckets: list[dict] = []
        try:
            client = self._client("s3")
            response = client.list_buckets()
            for b in response.get("Buckets", []):
                bucket_info: dict = {
                    "Name": b["Name"],
                    "Created": str(b.get("CreationDate", "")),
                }
                # Check public access
                try:
                    acl = client.get_bucket_acl(Bucket=b["Name"])
                    for grant in acl.get("Grants", []):
                        grantee = grant.get("Grantee", {})
                        if grantee.get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers":
                            bucket_info["PublicAccess"] = True
                except botocore.exceptions.ClientError:
                    pass
                buckets.append(bucket_info)
            logger.info(f"Collected {len(buckets)} S3 buckets")
        except botocore.exceptions.ClientError as e:
            logger.warning(f"Could not collect S3 buckets: {e}")
        return buckets

    # ─── EC2 Instances ───────────────────────────────────────────────────

    def get_ec2_instances(self) -> list[dict]:
        """List all EC2 instances with metadata options."""
        instances: list[dict] = []
        try:
            client = self._client("ec2")
            paginator = client.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page["Reservations"]:
                    for inst in reservation["Instances"]:
                        instances.append({
                            "InstanceId": inst["InstanceId"],
                            "PublicIpAddress": inst.get("PublicIpAddress"),
                            "PrivateIpAddress": inst.get("PrivateIpAddress"),
                            "MetadataOptions": inst.get("MetadataOptions", {}),
                            "State": inst["State"]["Name"],
                            "Type": inst["InstanceType"],
                            "IamInstanceProfile": inst.get("IamInstanceProfile", {}).get("Arn", ""),
                            "SecurityGroups": [
                                sg["GroupId"] for sg in inst.get("SecurityGroups", [])
                            ],
                        })
            logger.info(f"Collected {len(instances)} EC2 instances")
        except botocore.exceptions.ClientError as e:
            logger.warning(f"Could not collect EC2 instances: {e}")
        return instances

    # ─── Security Groups ─────────────────────────────────────────────────

    def get_security_groups(self) -> list[dict]:
        """List all Security Groups with ingress/egress rules."""
        groups: list[dict] = []
        try:
            client = self._client("ec2")
            paginator = client.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page["SecurityGroups"]:
                    groups.append({
                        "GroupId": sg["GroupId"],
                        "GroupName": sg.get("GroupName", ""),
                        "Description": sg.get("Description", ""),
                        "VpcId": sg.get("VpcId", ""),
                        "IpPermissions": sg.get("IpPermissions", []),
                        "IpPermissionsEgress": sg.get("IpPermissionsEgress", []),
                    })
            logger.info(f"Collected {len(groups)} Security Groups")
        except botocore.exceptions.ClientError as e:
            logger.warning(f"Could not collect Security Groups: {e}")
        return groups

    # ─── VPCs ────────────────────────────────────────────────────────────

    def get_vpcs(self) -> list[dict]:
        """List all VPCs."""
        vpcs: list[dict] = []
        try:
            client = self._client("ec2")
            response = client.describe_vpcs()
            for v in response.get("Vpcs", []):
                vpcs.append({
                    "VpcId": v["VpcId"],
                    "CidrBlock": v.get("CidrBlock", ""),
                    "IsDefault": v.get("IsDefault", False),
                    "State": v.get("State", ""),
                })
            logger.info(f"Collected {len(vpcs)} VPCs")
        except botocore.exceptions.ClientError as e:
            logger.warning(f"Could not collect VPCs: {e}")
        return vpcs


    # ── New: expose boto3 and client kwargs for offensive modules ──────────
    @property
    def boto3(self):
        import boto3 as _boto3
        return _boto3

    @property
    def _client_kwargs(self) -> dict:
        return {
            "aws_access_key_id":     self._access_key,
            "aws_secret_access_key": self._secret_key,
            "region_name":           self._region,
        }

    def get_s3_bucket_details(self, bucket_name: str) -> dict:
        """Get detailed S3 bucket config for ransomware analysis."""
        details: dict = {}
        try:
            s3 = self.boto3.client("s3", **self._client_kwargs)
            try:
                ver = s3.get_bucket_versioning(Bucket=bucket_name)
                details["versioning"] = ver.get("Status", "Disabled")
            except Exception:
                details["versioning"] = "Disabled"
            try:
                s3.get_object_lock_configuration(Bucket=bucket_name)
                details["object_lock"] = True
            except Exception:
                details["object_lock"] = False
            try:
                bpa = s3.get_public_access_block(Bucket=bucket_name)
                details["block_public_access"] = bpa.get("PublicAccessBlockConfiguration", {})
            except Exception:
                details["block_public_access"] = {}
            try:
                rep = s3.get_bucket_replication(Bucket=bucket_name)
                details["replication"] = bool(rep.get("ReplicationConfiguration"))
            except Exception:
                details["replication"] = False
        except Exception as e:
            from loguru import logger
            logger.debug(f"S3 detail fetch failed for {bucket_name}: {e}")
        return details

    def clear_credentials(self) -> None:
        """Remove all credential references from memory."""
        self.session = None  # type: ignore
        self.iam = None  # type: ignore
        self.sts = None  # type: ignore
        logger.info("AWS credentials cleared from memory")
