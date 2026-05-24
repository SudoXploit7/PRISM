"""
PRISM -- Network Exposure Analyzer
Detects security groups with dangerous ingress rules and public S3 buckets.
"""

from typing import Any

from loguru import logger

from src.scoring.cvss import score_for_finding, vector_string

# -- Dangerous port mapping ------------------------------------------------
DANGEROUS_PORTS: dict[int, str] = {
    22:   "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    445:  "SMB",
    23:   "Telnet",
    21:   "FTP",
    11211: "Memcached",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}


class NetworkExposureAnalyzer:
    """Detects dangerous network exposure configurations."""

    def __init__(self) -> None:
        self.findings: list[dict] = []

    def analyze(
        self,
        security_groups: list[dict],
        s3_public_access: list[dict] | None = None,
    ) -> list[dict]:
        """Analyze security groups and S3 public access for exposure.

        Args:
            security_groups: List of EC2 security group dicts.
            s3_public_access: Optional list of S3 bucket public access configs.

        Returns:
            List of network exposure findings.
        """
        for sg in security_groups:
            sg_id = sg.get("GroupId", "")
            sg_name = sg.get("GroupName", "")

            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                to_port = rule.get("ToPort", 65535)

                for ip_range in rule.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp", "")
                    if cidr not in ("0.0.0.0/0", "::/0"):
                        continue

                    # All ports open to internet
                    if from_port == 0 and to_port == 65535:
                        cvss = score_for_finding("ALL_PORTS_OPEN")
                        self.findings.append({
                            "type": "ALL_PORTS_OPEN",
                            "severity": "CRITICAL",
                            "identity": sg_name,
                            "resource": sg_id,
                            "mitre": "T1190",
                            "description": (
                                f"Security group '{sg_name}' ({sg_id}) allows ALL ports (0-65535) "
                                f"from the internet ({cidr}). Complete network exposure."
                            ),
                            "remediation": (
                                f"aws ec2 revoke-security-group-ingress --group-id {sg_id} "
                                f"--protocol -1 --cidr {cidr}"
                            ),
                            "cvss_score": cvss,
                            "cvss_vector": vector_string("ALL_PORTS_OPEN"),
                        })
                        continue

                    # Specific dangerous ports open to internet
                    for port, service in DANGEROUS_PORTS.items():
                        if from_port <= port <= to_port:
                            cvss = score_for_finding("OPEN_SECURITY_GROUP")
                            self.findings.append({
                                "type": "OPEN_SECURITY_GROUP",
                                "severity": "HIGH",
                                "identity": sg_name,
                                "resource": sg_id,
                                "mitre": "T1190",
                                "description": (
                                    f"Security group '{sg_name}' ({sg_id}) exposes "
                                    f"{service} (port {port}) to the internet ({cidr})."
                                ),
                                "remediation": (
                                    f"aws ec2 revoke-security-group-ingress --group-id {sg_id} "
                                    f"--protocol tcp --port {port} --cidr {cidr}"
                                ),
                                "cvss_score": cvss,
                                "cvss_vector": vector_string("OPEN_SECURITY_GROUP"),
                            })

            # Check default security group for self-referencing inbound rules
            if sg_name == "default":
                inbound_count = len(sg.get("IpPermissions", []))
                if inbound_count > 0:
                    cvss = score_for_finding("DEFAULT_SG_OPEN")
                    self.findings.append({
                        "type": "DEFAULT_SG_OPEN",
                        "severity": "MEDIUM",
                        "identity": sg_name,
                        "resource": sg_id,
                        "mitre": "T1580",
                        "description": (
                            f"Default security group ({sg_id}) has {inbound_count} inbound "
                            f"rule(s). CIS Benchmark recommends default SG has no inbound rules."
                        ),
                        "remediation": (
                            f"aws ec2 revoke-security-group-ingress --group-id {sg_id} "
                            f"--protocol -1 --source-group {sg_id}"
                        ),
                        "cvss_score": cvss,
                        "cvss_vector": vector_string("DEFAULT_SG_OPEN"),
                    })

        # S3 Block Public Access analysis
        if s3_public_access:
            for bucket_info in s3_public_access:
                bucket_name = bucket_info.get("BucketName", "")
                bpa = bucket_info.get("PublicAccessBlockConfiguration", {})

                # Check if all four BPA settings are enabled
                block_public_acls = bpa.get("BlockPublicAcls", False)
                ignore_public_acls = bpa.get("IgnorePublicAcls", False)
                block_public_policy = bpa.get("BlockPublicPolicy", False)
                restrict_public_buckets = bpa.get("RestrictPublicBuckets", False)

                if not all([block_public_acls, ignore_public_acls,
                           block_public_policy, restrict_public_buckets]):
                    missing = []
                    if not block_public_acls:
                        missing.append("BlockPublicAcls")
                    if not ignore_public_acls:
                        missing.append("IgnorePublicAcls")
                    if not block_public_policy:
                        missing.append("BlockPublicPolicy")
                    if not restrict_public_buckets:
                        missing.append("RestrictPublicBuckets")

                    cvss = score_for_finding("PUBLIC_S3_BUCKET")
                    self.findings.append({
                        "type": "PUBLIC_S3_BUCKET",
                        "severity": "HIGH",
                        "identity": bucket_name,
                        "resource": f"s3://{bucket_name}",
                        "mitre": "T1530",
                        "description": (
                            f"S3 bucket '{bucket_name}' has incomplete Block Public Access "
                            f"settings. Missing: {', '.join(missing)}. Data exfiltration risk."
                        ),
                        "remediation": (
                            f"aws s3api put-public-access-block --bucket {bucket_name} "
                            f"--public-access-block-configuration "
                            f"BlockPublicAcls=true,IgnorePublicAcls=true,"
                            f"BlockPublicPolicy=true,RestrictPublicBuckets=true"
                        ),
                        "cvss_score": cvss,
                        "cvss_vector": vector_string("PUBLIC_S3_BUCKET"),
                    })

        logger.info(f"Network exposure analysis complete: {len(self.findings)} findings")
        return self.findings
