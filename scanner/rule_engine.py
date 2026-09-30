"""
Rule Engine Module

Runs all 12 security rules against collected IAM data.
Each rule produces structured findings.
Findings include cvss_score calculated by RiskScorer
and MITRE ATT&CK technique mappings.
"""

from typing import List, Dict, Any
from datetime import datetime, timezone
from .policy_parser import PolicyParser
from .risk_scorer import RiskScorer
from .mitre_attack import MitreAttackMapper


class RuleEngine:
    """
    Applies security rules to IAM data and produces findings.
    """

    def __init__(self, mitre_mapper: MitreAttackMapper = None):
        self.policy_parser = PolicyParser()
        self.risk_scorer = RiskScorer()
        self.mitre_mapper = mitre_mapper or MitreAttackMapper.from_rules_config()

    def _create_finding(
        self,
        rule_id: str,
        rule_name: str,
        severity: str,
        affected_entity: str,
        entity_type: str,
        description: str,
        remediation: str,
        modifiers: Dict[str, bool] = None
    ) -> Dict[str, Any]:
        """Helper to build a standardized finding dict with MITRE ATT&CK mapping."""
        if modifiers is None:
            modifiers = {}

        cvss_score = self.risk_scorer.calculate_score(severity, modifiers)
        mitre_attack = self.mitre_mapper.get_mapping(rule_id)

        return {
            "rule_id": rule_id,
            "rule_name": rule_name,
            "severity": severity,
            "affected_entity": affected_entity,
            "entity_type": entity_type,
            "description": description,
            "remediation": remediation,
            "cvss_score": cvss_score,
            "mitre_attack": mitre_attack,
        }

    def run_all_rules(self, iam_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Run every rule against the provided IAM data.
        Returns list of findings (unsorted).
        """
        findings = []

        users = iam_data.get('users', []) or []
        groups = iam_data.get('groups', []) or []
        roles = iam_data.get('roles', []) or []
        password_policy = iam_data.get('password_policy', {}) or {}
        account_summary = iam_data.get('account_summary', {}) or {}

        # RULE_001: ROOT_ACCOUNT_NO_MFA
        findings.extend(self._rule_001_root_mfa(account_summary))

        # RULE_002: USER_NO_MFA
        findings.extend(self._rule_002_user_no_mfa(users))

        # RULE_003 + RULE_006 + RULE_008 + RULE_010 + RULE_012 for users, groups, roles
        findings.extend(self._rule_003_wildcard_admin(users, groups, roles))
        findings.extend(self._rule_006_inline_wildcard(users, groups, roles))
        findings.extend(self._rule_008_privilege_escalation(users, roles))
        findings.extend(self._rule_010_direct_policy_attachment(users))
        findings.extend(self._rule_012_no_condition_sensitive(users, roles))

        # RULE_004 + RULE_005: access keys
        findings.extend(self._rule_004_stale_access_key(users))
        findings.extend(self._rule_005_access_key_age(users))

        # ROLE trust policy rules
        findings.extend(self._rule_007_overly_permissive_trust(roles))
        findings.extend(self._rule_011_cross_account_no_external_id(roles))

        # RULE_009: password policy
        findings.extend(self._rule_009_weak_password_policy(password_policy))

        return findings

    # ------------------------------------------------------------------
    # RULE IMPLEMENTATIONS
    # ------------------------------------------------------------------

    def _rule_001_root_mfa(self, account_summary: Dict) -> List[Dict]:
        findings = []
        # AccountMFAEnabled == 0 means root has no MFA
        mfa_enabled = account_summary.get('AccountMFAEnabled', 1)
        if mfa_enabled == 0:
            findings.append(self._create_finding(
                rule_id="RULE_001",
                rule_name="ROOT_ACCOUNT_NO_MFA",
                severity="CRITICAL",
                affected_entity="arn:aws:iam::root",
                entity_type="ACCOUNT",
                description="Root account does not have MFA enabled. Root account has unrestricted access to all AWS resources.",
                remediation="Enable MFA on root account immediately. Use a hardware MFA device if possible.",
                modifiers={"no_mfa": True, "admin_access": True}
            ))
        return findings

    def _rule_002_user_no_mfa(self, users: List[Dict]) -> List[Dict]:
        findings = []
        for user in users:
            username = user.get('UserName', 'unknown')
            arn = user.get('Arn', f"arn:aws:iam::unknown:user/{username}")
            console_access = user.get('console_access', False)
            mfa_devices = user.get('mfa_devices', []) or []

            # Only triggers if console access AND no MFA
            if console_access and len(mfa_devices) == 0:
                findings.append(self._create_finding(
                    rule_id="RULE_002",
                    rule_name="USER_NO_MFA",
                    severity="HIGH",
                    affected_entity=arn,
                    entity_type="USER",
                    description=f"IAM user '{username}' has console access but no MFA enabled.",
                    remediation=f"Enable MFA for user '{username}'. Consider enforcing MFA via IAM policy with condition aws:MultiFactorAuthPresent.",
                    modifiers={"no_mfa": True}
                ))
        return findings

    def _check_entity_policies_for_admin(self, entity, entity_type, findings_list):
        """Helper used by multiple rules to inspect attached + inline policies."""
        name = entity.get('UserName') or entity.get('GroupName') or entity.get('RoleName') or 'unknown'
        arn = entity.get('Arn', name)

        # Attached managed policies
        for policy in entity.get('attached_policies', []):
            doc = policy.get('PolicyDocument')
            if doc:
                analysis = self.policy_parser.analyze_policy(doc)
                if analysis.get('is_full_admin'):
                    findings_list.append(self._create_finding(
                        rule_id="RULE_003",
                        rule_name="WILDCARD_ADMIN_POLICY",
                        severity="CRITICAL",
                        affected_entity=arn,
                        entity_type=entity_type,
                        description=f"Policy '{policy['PolicyName']}' attached to {entity_type} '{name}' grants full administrative access (Action:* Resource:*).",
                        remediation="Replace with least-privilege policy specifying only required actions and resources.",
                        modifiers={"admin_access": True}
                    ))

        # Inline policies
        for policy in entity.get('inline_policies', []):
            doc = policy.get('PolicyDocument')
            if doc:
                analysis = self.policy_parser.analyze_policy(doc)
                if analysis.get('is_full_admin'):
                    findings_list.append(self._create_finding(
                        rule_id="RULE_003",
                        rule_name="WILDCARD_ADMIN_POLICY",
                        severity="CRITICAL",
                        affected_entity=arn,
                        entity_type=entity_type,
                        description=f"Policy '{policy['PolicyName']}' attached to {entity_type} '{name}' grants full administrative access (Action:* Resource:*).",
                        remediation="Replace with least-privilege policy specifying only required actions and resources.",
                        modifiers={"admin_access": True}
                    ))

    def _rule_003_wildcard_admin(self, users, groups, roles) -> List[Dict]:
        findings = []
        for user in users:
            self._check_entity_policies_for_admin(user, "USER", findings)
        for group in groups:
            self._check_entity_policies_for_admin(group, "GROUP", findings)
        for role in roles:
            self._check_entity_policies_for_admin(role, "ROLE", findings)
        return findings

    def _rule_004_stale_access_key(self, users: List[Dict]) -> List[Dict]:
        findings = []
        for user in users:
            username = user.get('UserName', 'unknown')
            arn = user.get('Arn', username)
            for key in user.get('access_keys', []):
                if key.get('Status') == 'Active':
                    days = key.get('DaysSinceLastUsed')
                    if days is not None and days > 90:
                        key_id = key.get('AccessKeyId', 'unknown')
                        findings.append(self._create_finding(
                            rule_id="RULE_004",
                            rule_name="STALE_ACCESS_KEY",
                            severity="HIGH",
                            affected_entity=arn,
                            entity_type="USER",
                            description=f"Access key '{key_id}' for user '{username}' has not been used in {days} days but remains active.",
                            remediation="Deactivate and delete unused access key. Rotate active keys every 90 days.",
                            modifiers={}
                        ))
        return findings

    def _rule_005_access_key_age(self, users: List[Dict]) -> List[Dict]:
        findings = []
        for user in users:
            username = user.get('UserName', 'unknown')
            arn = user.get('Arn', username)
            for key in user.get('access_keys', []):
                if key.get('Status') == 'Active':
                    age = key.get('AgeDays')
                    if age is not None and age > 90:
                        key_id = key.get('AccessKeyId', 'unknown')
                        findings.append(self._create_finding(
                            rule_id="RULE_005",
                            rule_name="ACCESS_KEY_AGE",
                            severity="MEDIUM",
                            affected_entity=arn,
                            entity_type="USER",
                            description=f"Access key '{key_id}' for user '{username}' is {age} days old and has not been rotated.",
                            remediation="Rotate access key. AWS recommends rotating access keys every 90 days.",
                            modifiers={}
                        ))
        return findings

    def _check_inline_wildcard(self, entity, entity_type, findings_list):
        name = entity.get('UserName') or entity.get('GroupName') or entity.get('RoleName') or 'unknown'
        arn = entity.get('Arn', name)

        for policy in entity.get('inline_policies', []):
            doc = policy.get('PolicyDocument')
            if doc:
                analysis = self.policy_parser.analyze_policy(doc)
                if analysis.get('has_wildcard_action') and analysis.get('has_wildcard_resource'):
                    findings_list.append(self._create_finding(
                        rule_id="RULE_006",
                        rule_name="INLINE_POLICY_WILDCARD",
                        severity="HIGH",
                        affected_entity=arn,
                        entity_type=entity_type,
                        description=f"Inline policy '{policy['PolicyName']}' on {entity_type} '{name}' grants wildcard permissions. Inline policies are harder to audit than managed policies.",
                        remediation="Convert to a managed policy with least-privilege permissions.",
                        modifiers={"admin_access": True}
                    ))

    def _rule_006_inline_wildcard(self, users, groups, roles) -> List[Dict]:
        findings = []
        for user in users:
            self._check_inline_wildcard(user, "USER", findings)
        for group in groups:
            self._check_inline_wildcard(group, "GROUP", findings)
        for role in roles:
            self._check_inline_wildcard(role, "ROLE", findings)
        return findings

    def _rule_007_overly_permissive_trust(self, roles: List[Dict]) -> List[Dict]:
        findings = []
        for role in roles:
            role_name = role.get('RoleName', 'unknown')
            arn = role.get('Arn', role_name)
            trust_doc = role.get('AssumeRolePolicyDocument')

            if not trust_doc:
                continue

            statements = trust_doc.get('Statement', [])
            if isinstance(statements, dict):
                statements = [statements]

            for stmt in statements:
                if not isinstance(stmt, dict):
                    continue
                if str(stmt.get('Effect', '')).lower() != 'allow':
                    continue

                principal = stmt.get('Principal')
                # Principal can be "*" or {"AWS": "*"} or {"AWS": "arn:..."}
                is_wildcard = False
                if principal == "*" or principal == {"AWS": "*"}:
                    is_wildcard = True
                elif isinstance(principal, dict):
                    aws_princ = principal.get('AWS')
                    if aws_princ == "*" or (isinstance(aws_princ, list) and "*" in aws_princ):
                        is_wildcard = True

                if is_wildcard:
                    findings.append(self._create_finding(
                        rule_id="RULE_007",
                        rule_name="OVERLY_PERMISSIVE_TRUST_POLICY",
                        severity="CRITICAL",
                        affected_entity=arn,
                        entity_type="ROLE",
                        description=f"Role '{role_name}' has a trust policy that allows any principal to assume it. This exposes the role to unauthorized access.",
                        remediation="Restrict trust policy Principal to specific AWS accounts, services, or IAM entities.",
                        modifiers={"externally_accessible": True, "admin_access": True}
                    ))
                    break  # one finding per role
        return findings

    def _rule_008_privilege_escalation(self, users: List[Dict], roles: List[Dict]) -> List[Dict]:
        findings = []
        escalation_actions = {
            "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:PassRole",
            "iam:AttachUserPolicy", "iam:PutUserPolicy", "iam:CreateUser",
            "iam:CreateAccessKey", "iam:UpdateAssumeRolePolicy"
        }

        def check_entity(entity, entity_type):
            name = entity.get('UserName') or entity.get('RoleName', 'unknown')
            arn = entity.get('Arn', name)

            all_dangerous = set()

            # Check attached + inline policies
            for policy_list in [entity.get('attached_policies', []), entity.get('inline_policies', [])]:
                for policy in policy_list:
                    doc = policy.get('PolicyDocument')
                    if doc:
                        analysis = self.policy_parser.analyze_policy(doc)
                        for da in analysis.get('dangerous_actions', []):
                            # Only consider the specific escalation set
                            for esc in escalation_actions:
                                if da.lower() == esc.lower() or da == '*':
                                    all_dangerous.add(esc)

            if all_dangerous:
                dangerous_list = ", ".join(sorted(all_dangerous))
                findings.append(self._create_finding(
                    rule_id="RULE_008",
                    rule_name="PRIVILEGE_ESCALATION_PERMISSIONS",
                    severity="HIGH",
                    affected_entity=arn,
                    entity_type=entity_type,
                    description=f"User/Role '{name}' has permissions that could allow privilege escalation: {dangerous_list}.",
                    remediation="Remove privilege escalation permissions unless explicitly required. Apply strict conditions if these permissions are necessary.",
                    modifiers={"admin_access": True}
                ))

        for user in users:
            check_entity(user, "USER")
        for role in roles:
            check_entity(role, "ROLE")
        return findings

    def _rule_009_weak_password_policy(self, password_policy: Dict) -> List[Dict]:
        failures = []

        min_len = password_policy.get('MinimumPasswordLength', 0)
        if min_len < 14:
            failures.append(f"MinimumPasswordLength={min_len} (should be >=14)")

        if not password_policy.get('RequireUppercaseCharacters', False):
            failures.append("RequireUppercaseCharacters=False")

        if not password_policy.get('RequireNumbers', False):
            failures.append("RequireNumbers=False")

        if not password_policy.get('RequireSymbols', False):
            failures.append("RequireSymbols=False")

        max_age = password_policy.get('MaxPasswordAge')
        if max_age is None or max_age > 90:
            failures.append(f"MaxPasswordAge={max_age} (should be <=90)")

        reuse = password_policy.get('PasswordReusePrevention')
        if reuse is None or reuse < 5:
            failures.append(f"PasswordReusePrevention={reuse} (should be >=5)")

        if failures:
            failure_str = "; ".join(failures)
            return [self._create_finding(
                rule_id="RULE_009",
                rule_name="WEAK_PASSWORD_POLICY",
                severity="MEDIUM",
                affected_entity="ACCOUNT",
                entity_type="ACCOUNT",
                description=f"Account password policy does not meet security best practices. Failures: {failure_str}.",
                remediation="Update password policy: minimum 14 chars, require complexity, max age 90 days, prevent reuse of last 5 passwords.",
                modifiers={}
            )]
        return []

    def _rule_010_direct_policy_attachment(self, users: List[Dict]) -> List[Dict]:
        findings = []
        for user in users:
            username = user.get('UserName', 'unknown')
            arn = user.get('Arn', username)
            attached = user.get('attached_policies', []) or []
            inline = user.get('inline_policies', []) or []

            if len(attached) > 0 or len(inline) > 0:
                findings.append(self._create_finding(
                    rule_id="RULE_010",
                    rule_name="DIRECT_POLICY_ATTACHMENT",
                    severity="LOW",
                    affected_entity=arn,
                    entity_type="USER",
                    description=f"Policies are attached directly to user '{username}' instead of via IAM groups. This makes access management harder to audit at scale.",
                    remediation="Move user into appropriate IAM groups and attach policies to groups instead of individual users.",
                    modifiers={}
                ))
        return findings

    def _has_external_id_condition(self, condition: Dict) -> bool:
        """Return True if Condition requires sts:ExternalId (any operator)."""
        if not isinstance(condition, dict) or not condition:
            return False
        for operator, keys in condition.items():
            if not isinstance(keys, dict):
                continue
            for cond_key in keys.keys():
                if str(cond_key).lower() in ("sts:externalid", "externalid"):
                    return True
        # Fallback: string search for common misspellings / nested forms
        return "externalid" in str(condition).lower()

    def _extract_aws_principals(self, principal) -> List[str]:
        """Normalize Principal to a list of AWS principal strings."""
        if principal is None:
            return []
        if principal == "*":
            return ["*"]
        if isinstance(principal, str):
            return [principal]
        if isinstance(principal, dict):
            aws_p = principal.get("AWS")
            if aws_p is None:
                return []
            if isinstance(aws_p, list):
                return [p for p in aws_p if isinstance(p, str)]
            if isinstance(aws_p, str):
                return [aws_p]
        return []

    def _account_id_from_arn(self, arn: str) -> str:
        """Extract 12-digit account id from an IAM ARN, or empty string."""
        if not arn or not isinstance(arn, str):
            return ""
        # arn:aws:iam::123456789012:role/Name
        parts = arn.split(":")
        if len(parts) >= 5 and parts[4].isdigit() and len(parts[4]) == 12:
            return parts[4]
        return ""

    def _rule_011_cross_account_no_external_id(self, roles: List[Dict]) -> List[Dict]:
        findings = []
        for role in roles:
            role_name = role.get('RoleName', 'unknown')
            arn = role.get('Arn', role_name)
            role_account = self._account_id_from_arn(arn)
            trust_doc = role.get('AssumeRolePolicyDocument')

            if not trust_doc:
                continue

            statements = trust_doc.get('Statement', [])
            if isinstance(statements, dict):
                statements = [statements]

            for stmt in statements:
                if not isinstance(stmt, dict):
                    continue
                if str(stmt.get('Effect', '')).lower() != 'allow':
                    continue

                condition = stmt.get('Condition', {}) or {}
                if self._has_external_id_condition(condition):
                    continue

                # Flag wildcard or foreign-account AWS principals without ExternalId.
                # Same-account principals and service principals are skipped.
                aws_principals = self._extract_aws_principals(stmt.get('Principal'))
                is_cross_account = False
                for p in aws_principals:
                    if p == "*":
                        is_cross_account = True
                        break
                    if "arn:aws:iam::" not in p:
                        continue
                    principal_account = self._account_id_from_arn(p)
                    if not principal_account:
                        # Account ARN present but unparsable — still treat as external risk
                        is_cross_account = True
                        break
                    if role_account and principal_account != role_account:
                        is_cross_account = True
                        break
                    if not role_account:
                        # Role ARN missing account — flag any IAM principal ARN
                        is_cross_account = True
                        break

                if is_cross_account:
                    findings.append(self._create_finding(
                        rule_id="RULE_011",
                        rule_name="CROSS_ACCOUNT_TRUST_NO_EXTERNAL_ID",
                        severity="HIGH",
                        affected_entity=arn,
                        entity_type="ROLE",
                        description=f"Role '{role_name}' allows cross-account assumption without requiring ExternalId condition. Vulnerable to confused deputy attacks.",
                        remediation="Add sts:ExternalId condition to trust policy to prevent confused deputy attacks.",
                        modifiers={"externally_accessible": True}
                    ))
                    break
        return findings

    def _rule_012_no_condition_sensitive(self, users: List[Dict], roles: List[Dict]) -> List[Dict]:
        findings = []

        sensitive_prefixes = ['iam:', 's3:', 'ec2:']

        def check_entity(entity, entity_type):
            name = entity.get('UserName') or entity.get('RoleName', 'unknown')
            arn = entity.get('Arn', name)

            broad_actions = set()

            for policy_list in [entity.get('attached_policies', []), entity.get('inline_policies', [])]:
                for policy in policy_list:
                    doc = policy.get('PolicyDocument')
                    if not doc:
                        continue

                    analysis = self.policy_parser.analyze_policy(doc)
                    # Look at allow statements for sensitive actions without condition
                    for stmt in analysis.get('allow_statements', []):
                        if stmt.get('Condition'):
                            continue  # has condition at statement level

                        actions = stmt.get('Action')
                        actions_list = [actions] if isinstance(actions, str) else (actions or [])
                        if not isinstance(actions_list, list):
                            actions_list = [actions_list]

                        for act in actions_list:
                            if not isinstance(act, str):
                                continue
                            act_lower = act.lower()
                            if act_lower == '*' or any(act_lower.startswith(p) for p in sensitive_prefixes):
                                broad_actions.add(act)

            if broad_actions:
                action_str = ", ".join(sorted(broad_actions)[:5])
                if len(broad_actions) > 5:
                    action_str += ", ..."
                findings.append(self._create_finding(
                    rule_id="RULE_012",
                    rule_name="NO_CONDITION_SENSITIVE_ACTIONS",
                    severity="MEDIUM",
                    affected_entity=arn,
                    entity_type=entity_type,
                    description=f"{name} has broad permissions ({action_str}) with no condition constraints, allowing unrestricted use from any IP or context.",
                    remediation="Add conditions to restrict sensitive actions by IP range (aws:SourceIp), MFA requirement, or time of day.",
                    modifiers={}
                ))

        for user in users:
            check_entity(user, "USER")
        for role in roles:
            check_entity(role, "ROLE")
        return findings
