"""
PRISM -- Supply Chain Attack Mapper
Lambda layers, ECR images, CodeBuild, OIDC providers as attack surfaces.
References SolarWinds (2020), 3CX (2023), XZ Utils (2024).
"""
from __future__ import annotations
from typing import Any
from loguru import logger

class SupplyChainMapper:
    def analyze(self, collector, lambda_functions, iam_action_map):
        findings = []
        findings.extend(self._layers(collector, lambda_functions))
        findings.extend(self._ecr(collector))
        findings.extend(self._cicd(collector))
        findings.extend(self._oidc(collector))
        critical = [f for f in findings if f.get("severity")=="CRITICAL"]
        high     = [f for f in findings if f.get("severity")=="HIGH"]
        return {
            "findings": findings, "total_findings": len(findings),
            "critical_count": len(critical), "high_count": len(high),
            "lambda_risks":  [f for f in findings if "LAMBDA" in f.get("type","")],
            "ecr_risks":     [f for f in findings if "ECR" in f.get("type","")],
            "cicd_risks":    [f for f in findings if "CODEBUILD" in f.get("type","")],
            "oidc_risks":    [f for f in findings if "OIDC" in f.get("type","")],
            "overall_risk":  "CRITICAL" if critical else ("HIGH" if high else "MEDIUM"),
            "mitre": "T1195.002",
            "real_world_ref": "SolarWinds (2020), 3CX (2023), XZ Utils (2024)",
        }

    def _layers(self, collector, lambda_functions):
        findings = []
        try:
            import boto3
            lam = boto3.client("lambda", **collector._client_kwargs)
            layer_usage = {}
            for fn in lambda_functions:
                fn_name = fn.get("FunctionName","")
                for layer in fn.get("Layers",[]):
                    arn = layer.get("Arn","")
                    layer_usage.setdefault(arn, []).append(fn_name)
            for layer_arn, functions in layer_usage.items():
                if len(functions) > 1:
                    name = layer_arn.split(":")[-2] if ":" in layer_arn else layer_arn
                    findings.append({
                        "type":"LAMBDA_SHARED_LAYER","severity":"HIGH","cvss_score":8.1,"mitre":"T1195.002",
                        "resource":name,
                        "description":f"Layer '{name}' is shared across {len(functions)} functions: {', '.join(functions[:3])}. "
                                      "Compromising this layer backdoors all consuming functions simultaneously -- the SolarWinds pattern.",
                        "attack_scenario":"Attacker with lambda:UpdateLayerVersion publishes a backdoored layer. "
                                          "All functions execute attacker code with the function's IAM role.",
                        "remediation":"Pin all functions to a specific layer version ARN. Review layer update permissions.",
                    })
        except Exception as e:
            logger.warning(f"Lambda layer analysis skipped: {e}")
        return findings

    def _ecr(self, collector):
        findings = []
        try:
            import boto3
            ecr = boto3.client("ecr", **collector._client_kwargs)
            repos = ecr.describe_repositories().get("repositories", [])
            for repo in repos:
                name = repo.get("repositoryName","")
                if not repo.get("imageScanningConfiguration",{}).get("scanOnPush"):
                    findings.append({
                        "type":"ECR_NO_SCAN","severity":"HIGH","cvss_score":7.5,"mitre":"T1195.002",
                        "resource":name,
                        "description":f"ECR repository '{name}' does not scan images on push. "
                                      "Malicious images deploy without detection -- the 3CX supply chain pattern.",
                        "remediation":f"aws ecr put-image-scanning-configuration --repository-name {name} --image-scanning-configuration scanOnPush=true",
                    })
                if repo.get("imageTagMutability","MUTABLE") == "MUTABLE":
                    findings.append({
                        "type":"ECR_MUTABLE_TAGS","severity":"HIGH","cvss_score":8.0,"mitre":"T1195.002",
                        "resource":name,
                        "description":f"ECR repository '{name}' allows mutable tags. Attacker can overwrite 'latest' with backdoored image.",
                        "remediation":f"aws ecr put-image-tag-mutability --repository-name {name} --image-tag-mutability IMMUTABLE",
                    })
        except Exception as e:
            logger.warning(f"ECR analysis skipped: {e}")
        return findings

    def _cicd(self, collector):
        findings = []
        try:
            import boto3
            cb = boto3.client("codebuild", **collector._client_kwargs)
            names = []
            for page in cb.get_paginator("list_projects").paginate():
                names.extend(page.get("projects",[]))
            if not names: return findings
            for proj in cb.batch_get_projects(names=names[:20]).get("projects",[]):
                name = proj.get("name","")
                env  = proj.get("environment",{})
                if env.get("privilegedMode"):
                    findings.append({
                        "type":"CODEBUILD_PRIVILEGED","severity":"CRITICAL","cvss_score":9.8,"mitre":"T1611",
                        "resource":name,
                        "description":f"CodeBuild project '{name}' runs in privileged mode. "
                                      "Docker socket access enables container escape and EC2 host compromise.",
                        "attack_scenario":"Attacker injects malicious buildspec step. Script uses Docker socket "
                                          "to access EC2 metadata and steal instance IAM credentials.",
                        "remediation":"Disable privileged mode unless building Docker images.",
                    })
                for var in env.get("environmentVariables",[]):
                    if var.get("type","PLAINTEXT")=="PLAINTEXT" and any(
                        kw in var.get("name","").upper() for kw in ["KEY","SECRET","PASSWORD","TOKEN"]):
                        findings.append({
                            "type":"CODEBUILD_PLAINTEXT_SECRET","severity":"HIGH","cvss_score":8.5,"mitre":"T1552.001",
                            "resource":name,
                            "description":f"CodeBuild project '{name}' stores '{var.get('name','')}' as plaintext env var. "
                                          "Any build log viewer or compromised build script can exfiltrate this.",
                            "remediation":"Migrate to AWS Secrets Manager or SSM SecureString.",
                        })
        except Exception as e:
            logger.warning(f"CodeBuild analysis skipped: {e}")
        return findings

    def _oidc(self, collector):
        findings = []
        try:
            import boto3
            iam = boto3.client("iam", **collector._client_kwargs)
            providers = iam.list_open_id_connect_providers().get("OpenIDConnectProviderList",[])
            for p in providers:
                arn  = p.get("Arn","")
                info = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn)
                url  = info.get("Url","")
                audiences = info.get("ClientIDList",[])
                if "*" in audiences:
                    findings.append({
                        "type":"OIDC_WILDCARD","severity":"CRITICAL","cvss_score":9.1,"mitre":"T1550.001",
                        "resource":url,
                        "description":f"OIDC provider '{url}' has wildcard audience. Any repository on this provider can assume your roles.",
                        "remediation":"Scope the sub condition in role trust policy to specific repository.",
                    })
                if "token.actions.githubusercontent.com" in url:
                    findings.append({
                        "type":"OIDC_GITHUB","severity":"HIGH","cvss_score":8.0,"mitre":"T1550.001",
                        "resource":url,
                        "description":"GitHub Actions OIDC provider configured. Verify all trusting roles scope to specific repos/branches.",
                        "remediation":"Add StringEquals condition on 'sub' field scoped to your org/repo.",
                    })
        except Exception as e:
            logger.warning(f"OIDC analysis skipped: {e}")
        return findings
