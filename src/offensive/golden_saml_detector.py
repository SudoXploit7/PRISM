"""
PRISM -- Golden SAML & Federation Attack Detector
Detects conditions enabling SAML assertion forgery and OIDC federation abuse.
The Golden SAML attack was used in the SolarWinds nation-state breach (2020).
No other open-source tool detects these conditions.
"""
from __future__ import annotations
from typing import Any
from loguru import logger

HIGH_RISK_IDP = ["adfs","okta","onelogin","ping","shibboleth","azure"]

class GoldenSAMLDetector:
    def analyze(self, collector, iam_action_map, roles):
        findings = []
        findings.extend(self._saml(collector))
        findings.extend(self._fed_roles(collector, iam_action_map))
        findings.extend(self._modifiers(iam_action_map))
        critical = [f for f in findings if f.get("severity")=="CRITICAL"]
        high     = [f for f in findings if f.get("severity")=="HIGH"]
        return {
            "findings": findings, "total_findings": len(findings),
            "critical_count": len(critical), "high_count": len(high),
            "saml_findings": [f for f in findings if "SAML" in f.get("type","")],
            "role_findings": [f for f in findings if "FED" in f.get("type","")],
            "modifier_findings": [f for f in findings if "MODIFIER" in f.get("type","")],
            "overall_risk": "CRITICAL" if critical else ("HIGH" if high else "LOW"),
            "mitre": "T1606.002",
            "real_world_ref": "SolarWinds UNC2452 Golden SAML attack (December 2020)",
            "technique_summary": ("Golden SAML: attacker who compromises an IdP can forge SAML assertions "
                                  "for ANY user, bypassing MFA and audit trails entirely."),
        }

    def _saml(self, collector):
        findings = []
        try:
            iam = collector.iam
            providers = iam.list_saml_providers().get("SAMLProviderList",[])
            for p in providers:
                arn = p.get("Arn","")
                name = arn.split("/")[-1] if "/" in arn else arn
                try:
                    info = iam.get_saml_provider(SAMLProviderArn=arn)
                    meta = info.get("SAMLMetadataDocument","").lower()
                    for pattern in HIGH_RISK_IDP:
                        if pattern in meta or pattern in name.lower():
                            findings.append({
                                "type":"SAML_HIGH_RISK_IDP","severity":"HIGH","cvss_score":8.5,"mitre":"T1606.002",
                                "resource":name,
                                "description":f"SAML provider '{name}' uses {pattern.upper()} as IdP. "
                                              f"If {pattern.upper()} is compromised, attacker can forge assertions for any user "
                                              "including administrators -- bypassing all AWS MFA requirements.",
                                "attack_scenario":"Step 1: Compromise IdP. Step 2: Export signing certificate. "
                                                 "Step 3: Forge SAML assertion for admin@company.com. "
                                                 "Step 4: AWS grants session tokens. Step 5: Looks like normal SSO login in CloudTrail.",
                                "remediation":"Alert on AssumeRoleWithSAML from unexpected IPs. Enforce session duration limits on federated roles.",
                            })
                            break
                except Exception as e:
                    logger.debug(f"SAML provider detail error: {e}")
        except Exception as e:
            logger.warning(f"SAML analysis skipped: {e}")
        return findings

    def _fed_roles(self, collector, iam_action_map):
        findings = []
        try:
            iam = collector.iam
            for page in iam.get_paginator("list_roles").paginate():
                for role in page.get("Roles",[]):
                    name = role.get("RoleName","")
                    for stmt in role.get("AssumeRolePolicyDocument",{}).get("Statement",[]):
                        federated = stmt.get("Principal",{}).get("Federated","")
                        if not federated: continue
                        conditions = stmt.get("Condition",{})
                        has_scope = any(
                            "sub" in str(k).lower() or "email" in str(k).lower()
                            for op, cd in conditions.items() for k in (cd.keys() if isinstance(cd,dict) else [])
                        )
                        if not has_scope:
                            is_admin = "*" in iam_action_map.get(name,[])
                            findings.append({
                                "type":"SAML_UNSCOPED_ROLE","severity":"CRITICAL" if is_admin else "HIGH",
                                "cvss_score":9.8 if is_admin else 8.5,"mitre":"T1606.002",
                                "resource":name,
                                "description":f"Role '{name}' trusts federation provider '{federated}' with no subject scoping. "
                                              "Any authenticated user at the IdP can assume this role.",
                                "remediation":f"Add Condition to trust policy of '{name}': StringEquals on SAML:sub scoped to specific users.",
                            })
        except Exception as e:
            logger.warning(f"Federated role analysis skipped: {e}")
        return findings

    def _modifiers(self, iam_action_map):
        findings = []
        dangerous = ["iam:UpdateSAMLProvider","iam:DeleteSAMLProvider","iam:CreateSAMLProvider","iam:UpdateOpenIDConnectProviderThumbprint"]
        for identity, actions in iam_action_map.items():
            aset = set(a.lower() for a in actions)
            wildcard = "*" in aset or "iam:*" in aset
            matched = [d for d in dangerous if wildcard or d.lower() in aset]
            if matched:
                findings.append({
                    "type":"FEDERATION_MODIFIER","severity":"CRITICAL","cvss_score":9.9,"mitre":"T1606.002",
                    "resource":identity,
                    "description":f"Identity '{identity}' can modify federation configuration ({', '.join(matched[:2])}). "
                                  "By replacing the SAML metadata with an attacker-controlled certificate, they can forge assertions for any user.",
                    "remediation":f"Remove iam:UpdateSAMLProvider from '{identity}'. Federation changes require break-glass procedures.",
                })
        return findings
