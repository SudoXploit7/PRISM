import pytest
import os
import sys

# Ensure src is in the python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.offensive.mvc_engine import MVCEngine
from src.offensive.golden_saml_detector import GoldenSAMLDetector
from src.analysis.iam_shadow_admin_detector import ShadowAdminDetector
from src.unique.permission_entropy_engine import PermissionEntropyEngine

class TestMVCEngine:
    def test_already_admin(self):
        engine = MVCEngine()
        iam_action_map = {"admin_user": ["iam:*", "ec2:*"]}
        trusts = []
        admin_roles = ["admin_user"]
        shadow = []
        privesc = []
        
        result = engine.analyze(iam_action_map, trusts, admin_roles, shadow, privesc)
        assert result["total_paths"] == 1
        assert result["paths"][0]["hops"] == 0
        assert result["paths"][0]["start_identity"] == "admin_user"
        
    def test_one_hop_assume_root(self):
        engine = MVCEngine()
        iam_action_map = {
            "low_priv_user": ["s3:ListBucket"],
            "admin_role": ["*"]
        }
        trusts = [("low_priv_user", "admin_role", "AssumeRole")]
        admin_roles = ["admin_role"]
        shadow = []
        privesc = []
        
        result = engine.analyze(iam_action_map, trusts, admin_roles, shadow, privesc)
        assert result["total_paths"] >= 2
        paths = result["paths"]
        
        low_priv_path = next(p for p in paths if p["start_identity"] == "low_priv_user")
        assert low_priv_path["hops"] == 1
        assert low_priv_path["end_identity"] == "admin_role"

class TestGoldenSAMLDetector:
    def test_federation_modifier_detected(self):
        detector = GoldenSAMLDetector()
        iam_action_map = {"risky_user": ["iam:UpdateSAMLProvider"]}
        
        modifiers = detector._modifiers(iam_action_map)
        assert len(modifiers) == 1
        assert modifiers[0]["severity"] == "CRITICAL"
        assert "iam:UpdateSAMLProvider" in modifiers[0]["description"]

class TestShadowAdminDetector:
    def test_detects_shadow_admin_via_passrole(self):
        detector = ShadowAdminDetector()
        iam_map = {"sneaky_user": ["iam:PassRole", "ec2:RunInstances"]}
        admin_roles = ["legit_admin_role"]
        
        findings = detector.analyze(iam_map, admin_roles)
        assert len(findings) == 1
        assert "PassRole" in findings[0].get("description", "") or "PassRole" in findings[0].get("vector", "")
        assert findings[0]["severity"] in ("HIGH", "CRITICAL")

class TestPermissionEntropyEngine:
    def test_entropy_computation_clean(self):
        engine = PermissionEntropyEngine()
        iam_map = {
            "dev1": ["s3:GetObject", "s3:ListBucket"],
            "dev2": ["s3:GetObject", "s3:ListBucket"]
        }
        
        result = engine.compute(iam_map)
        assert "entropy_score" in result
        assert result["entropy_score"] < 50.0  # Should be low entropy

    def test_entropy_computation_chaos(self):
        engine = PermissionEntropyEngine()
        iam_map = {
            "dev1": ["s3:GetObject"],
            "dev2": ["iam:PassRole", "ec2:RunInstances"],
            "admin": ["*"],
            "bot": ["lambda:InvokeFunction"]
        }
        
        result = engine.compute(iam_map)
        assert "entropy_score" in result
        # High variation across identities leads to higher chaos score
