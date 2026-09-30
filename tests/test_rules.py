"""
Unit tests for the IAM Rule Engine.

All tests use synthetic mock IAM data. No real AWS calls are made.
"""

import pytest
from scanner.rule_engine import RuleEngine
from scanner.risk_scorer import RiskScorer
from scanner.mitre_attack import MitreAttackMapper, RULE_MITRE_MAP


@pytest.fixture
def engine():
    return RuleEngine()


def make_mock_user(username, console_access=False, mfa_devices=None, attached_policies=None,
                   inline_policies=None, access_keys=None, groups=None, arn=None):
    """Helper to build a realistic mock user dict."""
    if mfa_devices is None:
        mfa_devices = []
    if attached_policies is None:
        attached_policies = []
    if inline_policies is None:
        inline_policies = []
    if access_keys is None:
        access_keys = []
    if groups is None:
        groups = []
    if arn is None:
        arn = f"arn:aws:iam::123456789012:user/{username}"

    return {
        "UserName": username,
        "UserId": f"AIDA{username.upper()}",
        "Arn": arn,
        "CreateDate": "2024-01-01T00:00:00Z",
        "PasswordLastUsed": None,
        "console_access": console_access,
        "mfa_devices": mfa_devices,
        "attached_policies": attached_policies,
        "inline_policies": inline_policies,
        "access_keys": access_keys,
        "groups": groups
    }


def make_mock_role(name, trust_doc=None, attached_policies=None, inline_policies=None):
    if attached_policies is None:
        attached_policies = []
    if inline_policies is None:
        inline_policies = []
    if trust_doc is None:
        trust_doc = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                "Action": "sts:AssumeRole"
            }]
        }

    return {
        "RoleName": name,
        "RoleId": f"AROA{name.upper()}",
        "Arn": f"arn:aws:iam::123456789012:role/{name}",
        "CreateDate": "2024-01-01T00:00:00Z",
        "AssumeRolePolicyDocument": trust_doc,
        "RoleLastUsed": None,
        "attached_policies": attached_policies,
        "inline_policies": inline_policies
    }


def make_full_admin_policy(name="FullAdmin"):
    return {
        "PolicyName": name,
        "PolicyArn": f"arn:aws:iam::aws:policy/{name}",
        "PolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }]
        }
    }


def make_wildcard_inline(name="WildInline"):
    return {
        "PolicyName": name,
        "PolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }]
        }
    }


def make_priv_esc_policy(name="PrivEsc"):
    return {
        "PolicyName": name,
        "PolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["iam:CreatePolicyVersion", "iam:PassRole"],
                "Resource": "*"
            }]
        }
    }


def make_sensitive_no_cond(name="BroadNoCond"):
    return {
        "PolicyName": name,
        "PolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:*", "ec2:*"],
                "Resource": "*"
                # deliberately no Condition
            }]
        }
    }


# -----------------------------
# RULE_001 tests
# -----------------------------
def test_rule_001_root_mfa_triggers(engine):
    iam_data = {
        "users": [],
        "roles": [],
        "groups": [],
        "password_policy": {},
        "account_summary": {"AccountMFAEnabled": 0}
    }
    findings = engine.run_all_rules(iam_data)
    rule_ids = [f["rule_id"] for f in findings]
    assert "RULE_001" in rule_ids
    root_findings = [f for f in findings if f["rule_id"] == "RULE_001"]
    assert root_findings[0]["severity"] == "CRITICAL"
    assert "Root account" in root_findings[0]["description"]


def test_rule_001_root_mfa_does_not_trigger_when_enabled(engine):
    iam_data = {
        "users": [], "roles": [], "groups": [],
        "password_policy": {},
        "account_summary": {"AccountMFAEnabled": 1}
    }
    findings = engine.run_all_rules(iam_data)
    assert "RULE_001" not in [f["rule_id"] for f in findings]


# -----------------------------
# RULE_002 tests
# -----------------------------
def test_rule_002_user_no_mfa_triggers(engine):
    user = make_mock_user("console-user", console_access=True, mfa_devices=[])
    findings = engine.run_all_rules({"users": [user], "roles": [], "groups": [], "password_policy": {}, "account_summary": {}})
    rule_ids = [f["rule_id"] for f in findings]
    assert "RULE_002" in rule_ids


def test_rule_002_user_no_mfa_does_not_trigger_without_console(engine):
    user = make_mock_user("no-console", console_access=False, mfa_devices=[])
    findings = engine.run_all_rules({"users": [user], "roles": [], "groups": [], "password_policy": {}, "account_summary": {}})
    assert "RULE_002" not in [f["rule_id"] for f in findings]


def test_rule_002_user_no_mfa_does_not_trigger_with_mfa(engine):
    user = make_mock_user("mfa-user", console_access=True, mfa_devices=[{"SerialNumber": "arn:...:mfa/user"}])
    findings = engine.run_all_rules({"users": [user], "roles": [], "groups": [], "password_policy": {}, "account_summary": {}})
    assert "RULE_002" not in [f["rule_id"] for f in findings]


# -----------------------------
# RULE_003 tests
# -----------------------------
def test_rule_003_wildcard_admin_triggers_on_user(engine):
    user = make_mock_user("admin-user", attached_policies=[make_full_admin_policy()])
    findings = engine.run_all_rules({"users": [user], "roles": [], "groups": [], "password_policy": {}, "account_summary": {}})
    assert any(f["rule_id"] == "RULE_003" for f in findings)


def test_rule_003_wildcard_admin_does_not_trigger_safe_policy(engine):
    safe_policy = {
        "PolicyName": "Safe",
        "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::mybucket"}]}
    }
    user = make_mock_user("safe-user", attached_policies=[safe_policy])
    findings = engine.run_all_rules({"users": [user], "roles": [], "groups": [], "password_policy": {}, "account_summary": {}})
    assert "RULE_003" not in [f["rule_id"] for f in findings]


# -----------------------------
# RULE_004 STALE ACCESS KEY (>90 days unused)
# -----------------------------
def test_rule_004_stale_access_key_triggers(engine):
    key = {
        "AccessKeyId": "AKIAOLDKEY",
        "Status": "Active",
        "CreateDate": "2023-01-01T00:00:00Z",
        "LastUsedDate": "2024-01-01T00:00:00Z",  # >90 days ago from test time would be older
        "DaysSinceLastUsed": 200,
        "AgeDays": 500
    }
    user = make_mock_user("stale-user", access_keys=[key])
    findings = engine.run_all_rules({"users": [user], "roles": [], "groups": [], "password_policy": {}, "account_summary": {}})
    assert any(f["rule_id"] == "RULE_004" for f in findings)


def test_rule_004_stale_does_not_trigger_recent_key(engine):
    key = {"AccessKeyId": "AKIARECENT", "Status": "Active", "DaysSinceLastUsed": 10, "AgeDays": 20}
    user = make_mock_user("fresh-user", access_keys=[key])
    findings = engine.run_all_rules({"users": [user], "roles": [], "groups": [], "password_policy": {}, "account_summary": {}})
    assert "RULE_004" not in [f["rule_id"] for f in findings]


# -----------------------------
# RULE_005 ACCESS KEY AGE
# -----------------------------
def test_rule_005_access_key_age_triggers(engine):
    key = {"AccessKeyId": "AKIAOLD", "Status": "Active", "AgeDays": 120, "DaysSinceLastUsed": 5}
    user = make_mock_user("oldkey-user", access_keys=[key])
    findings = engine.run_all_rules({"users": [user], "roles": [], "groups": [], "password_policy": {}, "account_summary": {}})
    assert any(f["rule_id"] == "RULE_005" for f in findings)


def test_rule_005_access_key_age_does_not_trigger_young_key(engine):
    key = {"AccessKeyId": "AKIAYOUNG", "Status": "Active", "AgeDays": 30, "DaysSinceLastUsed": 2}
    user = make_mock_user("young-user", access_keys=[key])
    findings = engine.run_all_rules({"users": [user], "roles": [], "groups": [], "password_policy": {}, "account_summary": {}})
    assert "RULE_005" not in [f["rule_id"] for f in findings]


# -----------------------------
# RULE_006 INLINE WILDCARD
# -----------------------------
def test_rule_006_inline_wildcard_triggers(engine):
    user = make_mock_user("wild-inline-user", inline_policies=[make_wildcard_inline()])
    findings = engine.run_all_rules({"users": [user], "roles": [], "groups": [], "password_policy": {}, "account_summary": {}})
    assert any(f["rule_id"] == "RULE_006" for f in findings)


def test_rule_006_inline_wildcard_does_not_trigger_safe_inline(engine):
    safe_inline = {"PolicyName": "SafeInline", "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"}]}}
    user = make_mock_user("safe-inline", inline_policies=[safe_inline])
    findings = engine.run_all_rules({"users": [user], "roles": [], "groups": [], "password_policy": {}, "account_summary": {}})
    assert "RULE_006" not in [f["rule_id"] for f in findings]


# -----------------------------
# RULE_007 OVERLY PERMISSIVE TRUST (*)
# -----------------------------
def test_rule_007_permissive_trust_triggers(engine):
    bad_trust = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]}
    role = make_mock_role("open-role", trust_doc=bad_trust)
    findings = engine.run_all_rules({"users": [], "roles": [role], "groups": [], "password_policy": {}, "account_summary": {}})
    assert any(f["rule_id"] == "RULE_007" for f in findings)


def test_rule_007_permissive_trust_does_not_trigger_restricted(engine):
    good_trust = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Action": "sts:AssumeRole"}]}
    role = make_mock_role("restricted-role", trust_doc=good_trust)
    findings = engine.run_all_rules({"users": [], "roles": [role], "groups": [], "password_policy": {}, "account_summary": {}})
    assert "RULE_007" not in [f["rule_id"] for f in findings]


# -----------------------------
# RULE_008 PRIVILEGE ESCALATION
# -----------------------------
def test_rule_008_privilege_escalation_triggers(engine):
    user = make_mock_user("esc-user", attached_policies=[make_priv_esc_policy()])
    findings = engine.run_all_rules({"users": [user], "roles": [], "groups": [], "password_policy": {}, "account_summary": {}})
    assert any(f["rule_id"] == "RULE_008" for f in findings)


def test_rule_008_privilege_escalation_does_not_trigger_safe(engine):
    safe = {"PolicyName": "Safe", "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}]}}
    user = make_mock_user("safe-esc", attached_policies=[safe])
    findings = engine.run_all_rules({"users": [user], "roles": [], "groups": [], "password_policy": {}, "account_summary": {}})
    assert "RULE_008" not in [f["rule_id"] for f in findings]


# -----------------------------
# RULE_009 WEAK PASSWORD POLICY
# -----------------------------
def test_rule_009_weak_password_policy_triggers(engine):
    weak_policy = {
        "MinimumPasswordLength": 8,
        "RequireSymbols": False,
        "RequireNumbers": False,
        "RequireUppercaseCharacters": False,
        "RequireLowercaseCharacters": True,
        "MaxPasswordAge": 180,
        "PasswordReusePrevention": 1
    }
    iam_data = {"users": [], "roles": [], "groups": [], "password_policy": weak_policy, "account_summary": {}}
    findings = engine.run_all_rules(iam_data)
    assert any(f["rule_id"] == "RULE_009" for f in findings)


def test_rule_009_weak_password_policy_does_not_trigger_strong(engine):
    strong = {
        "MinimumPasswordLength": 14,
        "RequireSymbols": True,
        "RequireNumbers": True,
        "RequireUppercaseCharacters": True,
        "RequireLowercaseCharacters": True,
        "MaxPasswordAge": 90,
        "PasswordReusePrevention": 5
    }
    iam_data = {"users": [], "roles": [], "groups": [], "password_policy": strong, "account_summary": {}}
    findings = engine.run_all_rules(iam_data)
    assert "RULE_009" not in [f["rule_id"] for f in findings]


# -----------------------------
# RULE_010 DIRECT POLICY ATTACHMENT
# -----------------------------
def test_rule_010_direct_attachment_triggers(engine):
    user = make_mock_user("direct-user", attached_policies=[{"PolicyName": "SomePolicy", "PolicyDocument": {}}])
    findings = engine.run_all_rules({"users": [user], "roles": [], "groups": [], "password_policy": {}, "account_summary": {}})
    assert any(f["rule_id"] == "RULE_010" for f in findings)


def test_rule_010_direct_attachment_does_not_trigger_group_only_user(engine):
    user = make_mock_user("group-user", groups=[{"GroupName": "Admins"}], attached_policies=[], inline_policies=[])
    findings = engine.run_all_rules({"users": [user], "roles": [], "groups": [], "password_policy": {}, "account_summary": {}})
    assert "RULE_010" not in [f["rule_id"] for f in findings]


# -----------------------------
# RULE_011 CROSS ACCOUNT NO EXTERNAL ID
# -----------------------------
def test_rule_011_cross_account_no_external_triggers(engine):
    cross_trust = {
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
            "Action": "sts:AssumeRole"
            # no Condition
        }]
    }
    role = make_mock_role("cross-role", trust_doc=cross_trust)
    findings = engine.run_all_rules({"users": [], "roles": [role], "groups": [], "password_policy": {}, "account_summary": {}})
    assert any(f["rule_id"] == "RULE_011" for f in findings)


def test_rule_011_cross_account_does_not_trigger_with_external_id(engine):
    cross_with_ext = {
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"sts:ExternalId": "my-secret-id"}}
        }]
    }
    role = make_mock_role("safe-cross", trust_doc=cross_with_ext)
    findings = engine.run_all_rules({"users": [], "roles": [role], "groups": [], "password_policy": {}, "account_summary": {}})
    assert "RULE_011" not in [f["rule_id"] for f in findings]


# -----------------------------
# RULE_012 NO CONDITION ON SENSITIVE
# -----------------------------
def test_rule_012_no_condition_sensitive_triggers(engine):
    user = make_mock_user("broad-user", attached_policies=[make_sensitive_no_cond()])
    findings = engine.run_all_rules({"users": [user], "roles": [], "groups": [], "password_policy": {}, "account_summary": {}})
    assert any(f["rule_id"] == "RULE_012" for f in findings)


def test_rule_012_no_condition_does_not_trigger_with_condition(engine):
    with_cond = {
        "PolicyName": "WithCond",
        "PolicyDocument": {
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*",
                "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
            }]
        }
    }
    user = make_mock_user("cond-user", attached_policies=[with_cond])
    findings = engine.run_all_rules({"users": [user], "roles": [], "groups": [], "password_policy": {}, "account_summary": {}})
    assert "RULE_012" not in [f["rule_id"] for f in findings]


# -----------------------------
# RiskScorer unit tests
# -----------------------------
def test_risk_scorer_base_scores():
    scorer = RiskScorer()
    assert scorer.calculate_score("CRITICAL") == 9.0
    assert scorer.calculate_score("HIGH") == 7.5
    assert scorer.calculate_score("MEDIUM") == 5.5
    assert scorer.calculate_score("LOW") == 3.0
    assert scorer.calculate_score("INFO") == 1.0


def test_risk_scorer_modifiers():
    scorer = RiskScorer()
    score = scorer.calculate_score("HIGH", {"no_mfa": True, "admin_access": True})
    assert score == 8.5

    score2 = scorer.calculate_score("CRITICAL", {"has_condition": True, "has_compensating_control": True})
    assert score2 == 7.5


def test_risk_scorer_cap_at_10():
    scorer = RiskScorer()
    score = scorer.calculate_score("CRITICAL", {"no_mfa": True, "admin_access": True, "externally_accessible": True})
    assert score == 10.0


def test_get_severity_from_score():
    scorer = RiskScorer()
    assert scorer.get_severity_from_score(9.5) == "CRITICAL"
    assert scorer.get_severity_from_score(7.2) == "HIGH"
    assert scorer.get_severity_from_score(5.0) == "MEDIUM"
    assert scorer.get_severity_from_score(2.5) == "LOW"
    assert scorer.get_severity_from_score(0.5) == "INFO"


# -----------------------------
# MITRE ATT&CK mapping tests
# -----------------------------
def test_mitre_mapper_all_rules_have_techniques():
    mapper = MitreAttackMapper()
    for rule_id in RULE_MITRE_MAP:
        mapping = mapper.get_mapping(rule_id)
        assert mapping["framework"] == "MITRE ATT&CK"
        assert mapping["primary_tactic"]
        assert len(mapping["techniques"]) >= 1
        assert mapping["techniques"][0]["technique_id"].startswith("T")
        assert "url" in mapping["techniques"][0]


def test_findings_include_mitre_attack(engine):
    iam_data = {
        "users": [],
        "roles": [],
        "groups": [],
        "password_policy": {},
        "account_summary": {"AccountMFAEnabled": 0},
    }
    findings = engine.run_all_rules(iam_data)
    root = [f for f in findings if f["rule_id"] == "RULE_001"][0]
    assert "mitre_attack" in root
    assert root["mitre_attack"]["primary_tactic"] == "Privilege Escalation"
    tech_ids = [t["technique_id"] for t in root["mitre_attack"]["techniques"]]
    assert "T1078.004" in tech_ids


def test_mitre_privilege_escalation_maps_to_t1098(engine):
    from scanner.rule_engine import RuleEngine  # noqa: F401 — uses engine fixture
    user = make_mock_user("esc-user", attached_policies=[make_priv_esc_policy()])
    findings = engine.run_all_rules(
        {"users": [user], "roles": [], "groups": [], "password_policy": {}, "account_summary": {}}
    )
    esc = [f for f in findings if f["rule_id"] == "RULE_008"][0]
    tech_ids = [t["technique_id"] for t in esc["mitre_attack"]["techniques"]]
    assert "T1098" in tech_ids or "T1098.001" in tech_ids
    assert esc["mitre_attack"]["primary_tactic"] == "Privilege Escalation"


def test_mitre_summary_counts():
    mapper = MitreAttackMapper()
    findings = [
        {
            "rule_id": "RULE_001",
            "mitre_attack": mapper.get_mapping("RULE_001"),
        },
        {
            "rule_id": "RULE_002",
            "mitre_attack": mapper.get_mapping("RULE_002"),
        },
        {
            "rule_id": "RULE_008",
            "mitre_attack": mapper.get_mapping("RULE_008"),
        },
    ]
    summary = mapper.summarize_findings(findings)
    assert summary["framework"] == "MITRE ATT&CK"
    assert summary["unique_techniques"] >= 1
    assert summary["unique_tactics"] >= 1
    assert any(t["technique_id"] == "T1078.004" for t in summary["techniques"])
