"""
IAM Collector Module

Collects IAM configuration data from AWS using Boto3.
All list operations use paginators to handle large result sets.
All API calls are wrapped in try/except to ensure one failure does not crash the scan.
The scanner is READ-ONLY: only Get/List/Describe calls are used.
"""

import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone
from dateutil import parser as dateutil_parser
import json
import logging

# Configure logging for errors during collection
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


class IamCollector:
    """
    Collects comprehensive IAM data for security analysis.

    AWS clients are created lazily so offline file-mode scans work
    without any AWS credentials configured.
    """

    def __init__(self, profile_name=None, region_name=None):
        """
        Initialize the IAM collector.

        :param profile_name: Optional AWS profile name from ~/.aws/credentials
        :param region_name: Optional AWS region (IAM is global but client needs region)
        """
        self.profile_name = profile_name
        self.region_name = region_name
        self._session = None
        self._iam_client = None
        self._sts_client = None

    def _ensure_clients(self):
        """Create Boto3 session/clients only when live AWS access is needed."""
        if self._iam_client is not None:
            return

        session_kwargs = {}
        if self.profile_name:
            session_kwargs['profile_name'] = self.profile_name
        if self.region_name:
            session_kwargs['region_name'] = self.region_name

        self._session = boto3.Session(**session_kwargs)
        self._iam_client = self._session.client('iam')
        self._sts_client = self._session.client('sts')

    @property
    def iam_client(self):
        self._ensure_clients()
        return self._iam_client

    @property
    def sts_client(self):
        self._ensure_clients()
        return self._sts_client

    def _get_account_id(self):
        """Get the current AWS account ID."""
        try:
            response = self.sts_client.get_caller_identity()
            return response['Account']
        except ClientError as e:
            logger.error(f"Failed to get account ID: {e}")
            return "UNKNOWN"

    def _get_today(self):
        """Return current UTC date (timezone-aware)."""
        return datetime.now(timezone.utc)

    def _parse_date(self, date_val):
        """
        Parse various date formats to timezone-aware datetime in UTC.
        AWS returns datetime objects (often naive in UTC).
        """
        if date_val is None:
            return None
        if isinstance(date_val, datetime):
            if date_val.tzinfo is None:
                return date_val.replace(tzinfo=timezone.utc)
            return date_val
        try:
            parsed = dateutil_parser.parse(str(date_val))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except Exception:
            return None

    def _calculate_days_since(self, date_val, today=None):
        """Calculate days since a given date (integer)."""
        if date_val is None:
            return None
        today = today or self._get_today()
        date_val = self._parse_date(date_val)
        if date_val is None:
            return None
        delta = today - date_val
        return max(0, delta.days)

    def _get_full_policy_document(self, policy_arn):
        """
        Retrieve the full policy document for a managed policy.
        Requires two calls: get_policy + get_policy_version.
        Returns the policy document dict or None on failure.
        """
        try:
            policy_resp = self.iam_client.get_policy(PolicyArn=policy_arn)
            default_version_id = policy_resp['Policy']['DefaultVersionId']

            version_resp = self.iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=default_version_id
            )
            return version_resp['PolicyVersion']['Document']
        except ClientError as e:
            logger.error(f"Failed to get full policy document for {policy_arn}: {e}")
            return None

    def _get_inline_policy_document(self, entity_type, entity_name, policy_name):
        """
        Retrieve inline policy document for user/group/role.
        """
        try:
            if entity_type == 'user':
                resp = self.iam_client.get_user_policy(
                    UserName=entity_name, PolicyName=policy_name
                )
            elif entity_type == 'group':
                resp = self.iam_client.get_group_policy(
                    GroupName=entity_name, PolicyName=policy_name
                )
            elif entity_type == 'role':
                resp = self.iam_client.get_role_policy(
                    RoleName=entity_name, PolicyName=policy_name
                )
            else:
                return None
            return resp['PolicyDocument']
        except ClientError as e:
            logger.error(f"Failed to get inline policy {policy_name} for {entity_type} {entity_name}: {e}")
            return None

    def collect_users(self):
        """
        Collect detailed information for all IAM users.
        Uses paginator for list_users.
        """
        users = []
        today = self._get_today()

        try:
            paginator = self.iam_client.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page.get('Users', []):
                    username = user['UserName']
                    user_data = {
                        'UserName': username,
                        'UserId': user.get('UserId'),
                        'Arn': user.get('Arn'),
                        'CreateDate': self._parse_date(user.get('CreateDate')),
                        'PasswordLastUsed': self._parse_date(user.get('PasswordLastUsed')),
                        'mfa_devices': [],
                        'console_access': False,
                        'access_keys': [],
                        'attached_policies': [],
                        'inline_policies': [],
                        'groups': []
                    }

                    # 1. MFA devices - use paginator
                    try:
                        mfa_paginator = self.iam_client.get_paginator('list_mfa_devices')
                        for mfa_page in mfa_paginator.paginate(UserName=username):
                            for mfa in mfa_page.get('MFADevices', []):
                                user_data['mfa_devices'].append({
                                    'SerialNumber': mfa.get('SerialNumber'),
                                    'EnableDate': self._parse_date(mfa.get('EnableDate'))
                                })
                    except ClientError as e:
                        logger.error(f"Failed to list MFA devices for {username}: {e}")

                    # 2. Console access - check login profile
                    try:
                        self.iam_client.get_login_profile(UserName=username)
                        user_data['console_access'] = True
                    except ClientError as e:
                        if e.response.get('Error', {}).get('Code') == 'NoSuchEntity':
                            user_data['console_access'] = False
                        else:
                            logger.error(f"Failed to check login profile for {username}: {e}")

                    # 3. Access keys + last used
                    try:
                        key_paginator = self.iam_client.get_paginator('list_access_keys')
                        for key_page in key_paginator.paginate(UserName=username):
                            for key in key_page.get('AccessKeyMetadata', []):
                                access_key_id = key['AccessKeyId']
                                key_data = {
                                    'AccessKeyId': access_key_id,
                                    'Status': key.get('Status'),
                                    'CreateDate': self._parse_date(key.get('CreateDate')),
                                    'LastUsedDate': None,
                                    'DaysSinceLastUsed': None
                                }

                                # Get last used info
                                try:
                                    last_used = self.iam_client.get_access_key_last_used(
                                        AccessKeyId=access_key_id
                                    )
                                    last_used_date = last_used.get('AccessKeyLastUsed', {}).get('LastUsedDate')
                                    key_data['LastUsedDate'] = self._parse_date(last_used_date)
                                    key_data['DaysSinceLastUsed'] = self._calculate_days_since(
                                        key_data['LastUsedDate'], today
                                    )
                                except ClientError as e:
                                    logger.error(f"Failed to get last used for key {access_key_id}: {e}")

                                # Calculate age from creation (for RULE_005)
                                create_date = key_data['CreateDate']
                                if create_date:
                                    key_data['AgeDays'] = self._calculate_days_since(create_date, today)
                                else:
                                    key_data['AgeDays'] = None

                                user_data['access_keys'].append(key_data)
                    except ClientError as e:
                        logger.error(f"Failed to list access keys for {username}: {e}")

                    # 4. Attached managed policies + full documents
                    try:
                        attach_paginator = self.iam_client.get_paginator('list_attached_user_policies')
                        for attach_page in attach_paginator.paginate(UserName=username):
                            for policy in attach_page.get('AttachedPolicies', []):
                                policy_arn = policy['PolicyArn']
                                policy_name = policy['PolicyName']
                                full_doc = self._get_full_policy_document(policy_arn)
                                user_data['attached_policies'].append({
                                    'PolicyName': policy_name,
                                    'PolicyArn': policy_arn,
                                    'PolicyDocument': full_doc
                                })
                    except ClientError as e:
                        logger.error(f"Failed to list attached policies for {username}: {e}")

                    # 5. Inline policies + full documents
                    try:
                        inline_paginator = self.iam_client.get_paginator('list_user_policies')
                        for inline_page in inline_paginator.paginate(UserName=username):
                            for policy_name in inline_page.get('PolicyNames', []):
                                doc = self._get_inline_policy_document('user', username, policy_name)
                                user_data['inline_policies'].append({
                                    'PolicyName': policy_name,
                                    'PolicyDocument': doc
                                })
                    except ClientError as e:
                        logger.error(f"Failed to list inline policies for {username}: {e}")

                    # 6. Groups the user belongs to
                    try:
                        group_paginator = self.iam_client.get_paginator('list_groups_for_user')
                        for group_page in group_paginator.paginate(UserName=username):
                            for group in group_page.get('Groups', []):
                                user_data['groups'].append({
                                    'GroupName': group.get('GroupName'),
                                    'GroupId': group.get('GroupId'),
                                    'Arn': group.get('Arn')
                                })
                    except ClientError as e:
                        logger.error(f"Failed to list groups for user {username}: {e}")

                    users.append(user_data)

        except ClientError as e:
            logger.error(f"Failed during user collection: {e}")

        return users

    def collect_groups(self):
        """
        Collect detailed information for all IAM groups.
        """
        groups = []

        try:
            paginator = self.iam_client.get_paginator('list_groups')
            for page in paginator.paginate():
                for group in page.get('Groups', []):
                    group_name = group['GroupName']
                    group_data = {
                        'GroupName': group_name,
                        'GroupId': group.get('GroupId'),
                        'Arn': group.get('Arn'),
                        'attached_policies': [],
                        'inline_policies': []
                    }

                    # Attached managed policies with full docs
                    try:
                        attach_paginator = self.iam_client.get_paginator('list_attached_group_policies')
                        for attach_page in attach_paginator.paginate(GroupName=group_name):
                            for policy in attach_page.get('AttachedPolicies', []):
                                policy_arn = policy['PolicyArn']
                                policy_name = policy['PolicyName']
                                full_doc = self._get_full_policy_document(policy_arn)
                                group_data['attached_policies'].append({
                                    'PolicyName': policy_name,
                                    'PolicyArn': policy_arn,
                                    'PolicyDocument': full_doc
                                })
                    except ClientError as e:
                        logger.error(f"Failed to list attached policies for group {group_name}: {e}")

                    # Inline policies
                    try:
                        inline_paginator = self.iam_client.get_paginator('list_group_policies')
                        for inline_page in inline_paginator.paginate(GroupName=group_name):
                            for policy_name in inline_page.get('PolicyNames', []):
                                doc = self._get_inline_policy_document('group', group_name, policy_name)
                                group_data['inline_policies'].append({
                                    'PolicyName': policy_name,
                                    'PolicyDocument': doc
                                })
                    except ClientError as e:
                        logger.error(f"Failed to list inline policies for group {group_name}: {e}")

                    groups.append(group_data)

        except ClientError as e:
            logger.error(f"Failed during group collection: {e}")

        return groups

    def collect_roles(self):
        """
        Collect detailed information for all IAM roles.
        """
        roles = []

        try:
            paginator = self.iam_client.get_paginator('list_roles')
            for page in paginator.paginate():
                for role in page.get('Roles', []):
                    role_name = role['RoleName']
                    role_data = {
                        'RoleName': role_name,
                        'RoleId': role.get('RoleId'),
                        'Arn': role.get('Arn'),
                        'CreateDate': self._parse_date(role.get('CreateDate')),
                        'AssumeRolePolicyDocument': role.get('AssumeRolePolicyDocument'),
                        'RoleLastUsed': None,
                        'attached_policies': [],
                        'inline_policies': []
                    }

                    # RoleLastUsed (if present in response)
                    if 'RoleLastUsed' in role and role['RoleLastUsed']:
                        last_used = role['RoleLastUsed'].get('LastUsedDate')
                        role_data['RoleLastUsed'] = self._parse_date(last_used)

                    # Attached managed policies
                    try:
                        attach_paginator = self.iam_client.get_paginator('list_attached_role_policies')
                        for attach_page in attach_paginator.paginate(RoleName=role_name):
                            for policy in attach_page.get('AttachedPolicies', []):
                                policy_arn = policy['PolicyArn']
                                policy_name = policy['PolicyName']
                                full_doc = self._get_full_policy_document(policy_arn)
                                role_data['attached_policies'].append({
                                    'PolicyName': policy_name,
                                    'PolicyArn': policy_arn,
                                    'PolicyDocument': full_doc
                                })
                    except ClientError as e:
                        logger.error(f"Failed to list attached policies for role {role_name}: {e}")

                    # Inline policies
                    try:
                        inline_paginator = self.iam_client.get_paginator('list_role_policies')
                        for inline_page in inline_paginator.paginate(RoleName=role_name):
                            for policy_name in inline_page.get('PolicyNames', []):
                                doc = self._get_inline_policy_document('role', role_name, policy_name)
                                role_data['inline_policies'].append({
                                    'PolicyName': policy_name,
                                    'PolicyDocument': doc
                                })
                    except ClientError as e:
                        logger.error(f"Failed to list inline policies for role {role_name}: {e}")

                    roles.append(role_data)

        except ClientError as e:
            logger.error(f"Failed during role collection: {e}")

        return roles

    def collect_password_policy(self):
        """
        Collect account password policy.
        If none exists (NoSuchEntity), return weak defaults.
        """
        default_weak_policy = {
            'MinimumPasswordLength': 8,
            'RequireSymbols': False,
            'RequireNumbers': False,
            'RequireUppercaseCharacters': False,
            'RequireLowercaseCharacters': False,
            'AllowUsersToChangePassword': True,
            'ExpirePasswords': False,
            'MaxPasswordAge': None,
            'PasswordReusePrevention': None,
            'HardExpiry': None
        }

        try:
            resp = self.iam_client.get_account_password_policy()
            policy = resp.get('PasswordPolicy', {})
            # Normalize keys to match spec
            return {
                'MinimumPasswordLength': policy.get('MinimumPasswordLength', 8),
                'RequireSymbols': policy.get('RequireSymbols', False),
                'RequireNumbers': policy.get('RequireNumbers', False),
                'RequireUppercaseCharacters': policy.get('RequireUppercaseCharacters', False),
                'RequireLowercaseCharacters': policy.get('RequireLowercaseCharacters', False),
                'AllowUsersToChangePassword': policy.get('AllowUsersToChangePassword', True),
                'ExpirePasswords': policy.get('ExpirePasswords', False),
                'MaxPasswordAge': policy.get('MaxPasswordAge'),
                'PasswordReusePrevention': policy.get('PasswordReusePrevention'),
                'HardExpiry': policy.get('HardExpiry')
            }
        except ClientError as e:
            if e.response.get('Error', {}).get('Code') == 'NoSuchEntity':
                # No password policy set — treat as weak
                logger.warning("No account password policy found. Using weak defaults for analysis.")
                return default_weak_policy
            logger.error(f"Failed to get password policy: {e}")
            return default_weak_policy

    def collect_account_summary(self):
        """
        Collect account summary (used by RULE_001 for root MFA).
        """
        try:
            summary = self.iam_client.get_account_summary()
            return summary.get('SummaryMap', {})
        except ClientError as e:
            logger.error(f"Failed to get account summary: {e}")
            return {}

    def load_from_file(self, file_path: str):
        """
        Load pre-pulled IAM data from a JSON file (e.g. exported from BishopFox iam-vulnerable
        or a previous live scan).

        Returns the same dictionary structure as collect_all().
        Missing fields are filled with safe defaults so downstream code (RuleEngine,
        ReportGenerator, etc.) continues to work without changes.
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(f"Input file not found: {file_path}")
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in file {file_path}: {e}")

        # Gracefully handle missing top-level keys
        return {
            'account_id': data.get('account_id', 'UNKNOWN'),
            'users': data.get('users', []),
            'groups': data.get('groups', []),
            'roles': data.get('roles', []),
            'password_policy': data.get('password_policy', {}),
            'account_summary': data.get('account_summary', {}),
            'scan_time': data.get('scan_time', datetime.now(timezone.utc).isoformat())
        }

    def collect_all(self, data_source: str = "live", input_file: str = None):
        """
        Main entry point. Collects all IAM data.

        Args:
            data_source: "live" (default) to query real AWS via Boto3,
                         or "file" to load previously collected data.
            input_file: Path to JSON file. Required when data_source="file".

        Returns dict with users, groups, roles, password_policy, account_summary, account_id.
        """
        if data_source == "file":
            if not input_file:
                raise ValueError("--input-file is required when --data-source=file")
            print(f"Loading IAM data from file: {input_file}")
            iam_data = self.load_from_file(input_file)
            users = iam_data.get('users', [])
            roles = iam_data.get('roles', [])
            groups = iam_data.get('groups', [])
            print(f"Loaded data for {len(users)} users, {len(roles)} roles, {len(groups)} groups")
            return iam_data

        # === Live AWS collection (original behavior) ===
        print("Collecting IAM data from AWS account...")
        account_id = self._get_account_id()

        users = self.collect_users()
        groups = self.collect_groups()
        roles = self.collect_roles()
        password_policy = self.collect_password_policy()
        account_summary = self.collect_account_summary()

        print(f"Collected data for {len(users)} users, {len(roles)} roles, {len(groups)} groups")

        return {
            'account_id': account_id,
            'users': users,
            'groups': groups,
            'roles': roles,
            'password_policy': password_policy,
            'account_summary': account_summary,
            'scan_time': datetime.now(timezone.utc).isoformat()
        }
