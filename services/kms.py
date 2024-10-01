'''
Class name KMSComplianceChecker
Create functions to check compliants and return as 
'control_id': security contorl id,
'control_title': security control title,
'compliance': passed, failed or not_found,
'severity': CRITICAL, HIGH, MEDIUM or LOW,
'auto_remediation': available or not_available,
'resource_id': account id, resource arn or not_found
'''

import json, boto3 # type: ignore
from botocore.exceptions import ClientError # type: ignore
from utils.decorator_class import DecoratorClass # type: ignore
from utils.validate import ParameterValidation # type: ignore
from utils.cross_account import UseCrossAccount # type: ignore
from utils.global_data import compliance_check_list # type: ignore

class KMSComplianceChecker:
    def __init__(self) -> None:
        self.kms_client = boto3.client('kms')
        self.iam_client = boto3.client('iam')
        self.kms_list = compliance_check_list

    def create_kms_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("KMS", control_id, compliance, severity, auto_remediation):
            return {
                'control_id': control_id,
                'control_title': control_title,
                'compliance': compliance,
                'severity': severity,
                'auto_remediation': auto_remediation,
                'resource_id': resource_id
            }
        else:
            return {
                control_id: 'Invalid parameter',
                control_title: 'Invalid parameter',
                compliance: 'Invalid parameter',
                severity: 'Invalid parameter',
                auto_remediation: 'Invalid parameter',
                resource_id: 'Invalid parameter'
            }
        
    def iam_custom_manage_policy_list(self) -> list:
        try:
            policy_list: list[dict] = []
            response = self.iam_client.list_policies(Scope='Local')
            policy_list.extend(_ for _ in response['Policies'])
            while 'Marker' in response:
                response = self.iam_client.list_policies(Scope='Local', Marker=response['Marker'])
                policy_list.extend(_ for _ in response['Policies'])
            return policy_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def iam_policy_compliant(self, policy_arn: str) -> str:
        try:
            compliant_status = "passed"
            policy_version = self.iam_client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
            policy_document = self.iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)['PolicyVersion']['Document']
            statements = policy_document.get('Statement', [])
            if not isinstance(statements, list):
                statements = [statements]
            for statement in statements:
                if statement.get('Effect') == 'Allow':
                    actions = statement.get('Action', [])
                    resources = statement.get('Resource', [])
                    if not isinstance(actions, list):
                        actions = [actions]
                    if not isinstance(resources, list):
                        resources = [resources]
                    if "kms:Decrypt" in actions and "*" in resources:
                        compliant_status = "failed"
                return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        
    def iam_inline_policy_compliant(self, policy: list[dict]) -> str:
        compliant_status = "passed"
        statements = policy.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        for statement in statements:
            if statement.get('Effect') == 'Allow':
                actions = statement.get('Action', [])
                resources = statement.get('Resource', [])
                if not isinstance(actions, list):
                    actions = [actions]
                if not isinstance(resources, list):
                    resources = [resources]
                if "kms:Decrypt" in actions and "*" in resources:
                    compliant_status = "failed"
        return compliant_status
    
    def iam_user_list(self) -> list[dict]:
        try:
            user_list: list[dict] = []
            response = self.iam_client.list_users()
            user_list.extend(_ for _ in response['Users'])
            while 'Marker' in response:
                response = self.iam_client.list_users(Marker=response['Marker'])
                user_list.extend(_ for _ in response['Users'])
            return user_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def iam_user_inline_policy(self, user_name: str) -> list[dict]:
        try:
            policy_list: list[dict] = []
            response = self.iam_client.list_user_policies(UserName=user_name)
            policy_list.extend(_ for _ in response['PolicyNames'])
            while 'Marker' in response:
                response = self.iam_client.list_user_policies(UserName=user_name, Marker=response['Marker'])
                policy_list.extend(_ for _ in response['PolicyNames'])
            return policy_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def iam_user_policy_document(self, user_name: str, policy_name: str) -> dict:
        try:
            policy_document = self.iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)['PolicyDocument']
            return policy_document
        except ClientError as e:
            print(f"Error: {e}")
            return {}
        
    def iam_group_list(self) -> list[dict]:
        try:
            group_list: list[dict] = []
            response = self.iam_client.list_groups()
            group_list.extend(_ for _ in response['Groups'])
            while 'Marker' in response:
                response = self.iam_client.list_groups(Marker=response['Marker'])
                group_list.extend(_ for _ in response['Groups'])
            return group_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def iam_group_inline_policy(self, group_name: str) -> list[dict]:
        try:
            policy_list: list[dict] = []
            response = self.iam_client.list_group_policies(GroupName=group_name)
            policy_list.extend(_ for _ in response['PolicyNames'])
            while 'Marker' in response:
                response = self.iam_client.list_group_policies(GroupName=group_name, Marker=response['Marker'])
                policy_list.extend(_ for _ in response['PolicyNames'])
            return policy_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def iam_group_policy_document(self, group_name: str, policy_name: str) -> dict:
        try:
            policy_document = self.iam_client.get_group_policy(GroupName=group_name, PolicyName=policy_name)['PolicyDocument']
            return policy_document
        except ClientError as e:
            print(f"Error: {e}")
            return {}
        
    def iam_role_list(self) -> list[dict]:
        try:
            role_list: list[dict] = []
            response = self.iam_client.list_roles()
            role_list.extend(_ for _ in response['Roles'])
            while 'Marker' in response:
                response = self.iam_client.list_roles(Marker=response['Marker'])
                role_list.extend(_ for _ in response['Roles'])
            return role_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def iam_role_inline_policy(self, role_name: str) -> list[dict]:
        try:
            policy_list: list[dict] = []
            response = self.iam_client.list_role_policies(RoleName=role_name)
            policy_list.extend(_ for _ in response['PolicyNames'])
            while 'Marker' in response:
                response = self.iam_client.list_role_policies(RoleName=role_name, Marker=response['Marker'])
                policy_list.extend(_ for _ in response['PolicyNames'])
            return policy_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def iam_role_policy_document(self, role_name: str, policy_name: str) -> dict:
        try:
            policy_document = self.iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)['PolicyDocument']
            return policy_document
        except ClientError as e:
            print(f"Error: {e}")
            return {}
        
    def kms_key_list(self) -> list[dict]:
        key_list: list[dict] = []
        try:
            response = self.kms_client.list_keys()
            key_list.extend(_ for _ in response['Keys'])
            while 'NextMarker' in response:
                response = self.kms_client.list_keys(Marker=response['NextMarker'])
                key_list.extend(_ for _ in response['Keys'])
            return key_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def kms_key_deletion_compliant(self, kms_key_id: str) -> str:
        try:
            compliant_status = "passed"
            describe_key = self.kms_client.describe_key(KeyId=kms_key_id)
            for key_metadata in describe_key['KeyMetadata']:
                if key_metadata.get('KeyState') == 'PendingDeletion':
                    compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        
    def kms_key_rotation_compliant(self, kms_key_id: str) -> str:
        try:
            compliant_status = "passed"
            key_rotation = self.kms_client.get_key_rotation_status(KeyId=kms_key_id)
            if key_rotation.get('KeyRotationEnabled') != True:
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""

    def kms_one(self) -> None:
        result_list = self.iam_custom_manage_policy_list()
        if not result_list:
            self.kms_list.append(self.create_kms_item(
                'KMS.1',
                'IAM customer managed policies should not allow decryption actions on all KMS keys',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.iam_policy_compliant(response_detail['Arn'])
            self.kms_list.append(self.create_kms_item(
                'KMS.1',
                'IAM customer managed policies should not allow decryption actions on all KMS keys',
                compliant_status,
                'MEDIUM',
                'available',
                response_detail['Arn']
            ))

    def kms_two(self) -> None:
        user_list = self.iam_user_list()
        group_list = self.iam_group_list()
        role_list = self.iam_role_list()
        if not user_list and not group_list and not role_list:
            self.kms_list.append(self.create_kms_item(
                'KMS.2',
                'IAM principals should not have IAM inline policies that allow decryption actions on all KMS keys',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in user_list:
            policy_list = self.iam_user_inline_policy(response_detail['UserName'])
            for policy in policy_list:
                policy_document = self.iam_user_policy_document(response_detail['UserName'], policy)
                compliant_status = self.iam_inline_policy_compliant(policy_document)
                self.kms_list.append(self.create_kms_item(
                    'KMS.2',
                    'IAM principals should not have IAM inline policies that allow decryption actions on all KMS keys',
                    compliant_status,
                    'MEDIUM',
                    'available',
                    response_detail['Arn']
                ))
        for response_detail in group_list:
            policy_list = self.iam_group_inline_policy(response_detail['GroupName'])
            for policy in policy_list:
                policy_document = self.iam_group_policy_document(response_detail['GroupName'], policy)
                compliant_status = self.iam_inline_policy_compliant(policy_document)
                self.kms_list.append(self.create_kms_item(
                    'KMS.2',
                    'IAM principals should not have IAM inline policies that allow decryption actions on all KMS keys',
                    compliant_status,
                    'MEDIUM',
                    'available',
                    response_detail['Arn']
                ))
        for response_detail in role_list:
            policy_list = self.iam_role_inline_policy(response_detail['RoleName'])
            for policy in policy_list:
                policy_document = self.iam_role_policy_document(response_detail['RoleName'], policy)
                compliant_status = self.iam_inline_policy_compliant(policy_document)
                self.kms_list.append(self.create_kms_item(
                    'KMS.2',
                    'IAM principals should not have IAM inline policies that allow decryption actions on all KMS keys',
                    compliant_status,
                    'MEDIUM',
                    'available',
                    response_detail['Arn']
                ))

    def kms_three(self) -> None:
        result_list = self.kms_key_list()
        if not result_list:
            self.kms_list.append(self.create_kms_item(
                'KMS.3',
                'AWS KMS keys should not be deleted unintentionally',
                'not_found',
                'CRITICAL',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.kms_key_deletion_compliant(response_detail['KeyId'])
            self.kms_list.append(self.create_kms_item(
                'KMS.3',
                'AWS KMS keys should not be deleted unintentionally',
                compliant_status,
                'CRITICAL',
                'not_available',
                response_detail['KeyArn']
            ))

    def kms_four(self) -> None:
        result_list = self.kms_key_list()
        if not result_list:
            self.kms_list.append(self.create_kms_item(
                'KMS.4',
                'AWS KMS key rotation should be enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.kms_key_rotation_compliant(response_detail['KeyId'])
            self.kms_list.append(self.create_kms_item(
                'KMS.4',
                'AWS KMS key rotation should be enabled',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['KeyArn']
            ))

class KMSAutoRemediation:
    def __init__(self) -> None:
        self.kms_client = boto3.client('kms')
        self.session_region = boto3.session.Session().region_name
        self.session_account = boto3.client('sts').get_caller_identity().get('Account')
        self.automate_key_description = "Automate Security Remediation Key with Best Practices"
        self.policy_document = {
            "Version": "2012-10-17",
            "Id": "key-default-1",
            "Statement": [
                {
                    "Sid": "Enable IAM User Permissions",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{self.session_account}:root"
                    },
                    "Action": "kms:*",
                    "Resource": "*"
                },
                {
                    "Sid": "Enable CloudWatch Log Group Permissions",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "*"
                    },
                    "Action": [
                        "kms:Encrypt*",
                        "kms:Decrypt*",
                        "kms:ReEncrypt*",
                        "kms:GenerateDataKey*",
                        "kms:Describe*"
                    ],
                    "Resource": f"arn:aws:kms:{self.session_region}:{self.session_account}:key/*"
                }
            ]
        }

    def create_kms_key(self) -> str:
        try:
            response = self.kms_client.create_key()
            key_id = response['KeyMetadata']['KeyId']
            key_arn = response['KeyMetadata']['Arn']
            self.kms_client.update_key_description(
                KeyId=key_id,
                Description=self.automate_key_description
            )
            self.kms_client.put_key_policy(
                KeyId=key_id,
                PolicyName='default',
                Policy=json.dumps(self.policy_document)
            )
            self.kms_client.create_alias(
                AliasName="alias/AutomateSecurityRemediationKey",
                TargetKeyId=key_id
            )
            self.kms_client.enable_key_rotation(
                KeyId=key_id
            )
            print(f"KMS key created: {key_arn}")
            return key_arn
        except ClientError as e:
            print(f"Error: {e}")
            return ""
    
    def get_kms_key_arn(self) -> str:
        try:
            key_list: list[dict] = []
            response = self.kms_client.list_keys()
            key_list.extend(_ for _ in response['Keys'])
            while 'NextMarker' in response:
                response = self.kms_client.list_keys(Marker=response['NextMarker'])
                key_list.extend(_ for _ in response['Keys'])
            kms_key_arn_check = [_['KeyArn'] \
                    for _ in key_list \
                    if self.kms_client.describe_key(KeyId=_['KeyId'])['KeyMetadata']['Description'] == self.automate_key_description]
            if kms_key_arn_check:
                kms_key_arn = kms_key_arn_check[0]
            else:
                kms_key_arn = self.create_kms_key()
            return kms_key_arn
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        
class CrossAccountKMSComplianceChecker:
    def __init__(self) -> None:
        self.kms_client = UseCrossAccount().client('kms')
        self.iam_client = UseCrossAccount().client('iam')
        self.kms_list = compliance_check_list

    def create_kms_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("KMS", control_id, compliance, severity, auto_remediation):
            return {
                'control_id': control_id,
                'control_title': control_title,
                'compliance': compliance,
                'severity': severity,
                'auto_remediation': auto_remediation,
                'resource_id': resource_id
            }
        else:
            return {
                control_id: 'Invalid parameter',
                control_title: 'Invalid parameter',
                compliance: 'Invalid parameter',
                severity: 'Invalid parameter',
                auto_remediation: 'Invalid parameter',
                resource_id: 'Invalid parameter'
            }
        
    def iam_custom_manage_policy_list(self) -> list:
        try:
            policy_list: list[dict] = []
            response = self.iam_client.list_policies(Scope='Local')
            policy_list.extend(_ for _ in response['Policies'])
            while 'Marker' in response:
                response = self.iam_client.list_policies(Scope='Local', Marker=response['Marker'])
                policy_list.extend(_ for _ in response['Policies'])
            return policy_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def iam_policy_compliant(self, policy_arn: str) -> str:
        try:
            compliant_status = "passed"
            policy_version = self.iam_client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
            policy_document = self.iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)['PolicyVersion']['Document']
            statements = policy_document.get('Statement', [])
            if not isinstance(statements, list):
                statements = [statements]
            for statement in statements:
                if statement.get('Effect') == 'Allow':
                    actions = statement.get('Action', [])
                    resources = statement.get('Resource', [])
                    if not isinstance(actions, list):
                        actions = [actions]
                    if not isinstance(resources, list):
                        resources = [resources]
                    if "kms:Decrypt" in actions and "*" in resources:
                        compliant_status = "failed"
                return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        
    def iam_inline_policy_compliant(self, policy: list[dict]) -> str:
        compliant_status = "passed"
        statements = policy.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        for statement in statements:
            if statement.get('Effect') == 'Allow':
                actions = statement.get('Action', [])
                resources = statement.get('Resource', [])
                if not isinstance(actions, list):
                    actions = [actions]
                if not isinstance(resources, list):
                    resources = [resources]
                if "kms:Decrypt" in actions and "*" in resources:
                    compliant_status = "failed"
        return compliant_status
    
    def iam_user_list(self) -> list[dict]:
        try:
            user_list: list[dict] = []
            response = self.iam_client.list_users()
            user_list.extend(_ for _ in response['Users'])
            while 'Marker' in response:
                response = self.iam_client.list_users(Marker=response['Marker'])
                user_list.extend(_ for _ in response['Users'])
            return user_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def iam_user_inline_policy(self, user_name: str) -> list[dict]:
        try:
            policy_list: list[dict] = []
            response = self.iam_client.list_user_policies(UserName=user_name)
            policy_list.extend(_ for _ in response['PolicyNames'])
            while 'Marker' in response:
                response = self.iam_client.list_user_policies(UserName=user_name, Marker=response['Marker'])
                policy_list.extend(_ for _ in response['PolicyNames'])
            return policy_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def iam_user_policy_document(self, user_name: str, policy_name: str) -> dict:
        try:
            policy_document = self.iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)['PolicyDocument']
            return policy_document
        except ClientError as e:
            print(f"Error: {e}")
            return {}
        
    def iam_group_list(self) -> list[dict]:
        try:
            group_list: list[dict] = []
            response = self.iam_client.list_groups()
            group_list.extend(_ for _ in response['Groups'])
            while 'Marker' in response:
                response = self.iam_client.list_groups(Marker=response['Marker'])
                group_list.extend(_ for _ in response['Groups'])
            return group_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def iam_group_inline_policy(self, group_name: str) -> list[dict]:
        try:
            policy_list: list[dict] = []
            response = self.iam_client.list_group_policies(GroupName=group_name)
            policy_list.extend(_ for _ in response['PolicyNames'])
            while 'Marker' in response:
                response = self.iam_client.list_group_policies(GroupName=group_name, Marker=response['Marker'])
                policy_list.extend(_ for _ in response['PolicyNames'])
            return policy_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def iam_group_policy_document(self, group_name: str, policy_name: str) -> dict:
        try:
            policy_document = self.iam_client.get_group_policy(GroupName=group_name, PolicyName=policy_name)['PolicyDocument']
            return policy_document
        except ClientError as e:
            print(f"Error: {e}")
            return {}
        
    def iam_role_list(self) -> list[dict]:
        try:
            role_list: list[dict] = []
            response = self.iam_client.list_roles()
            role_list.extend(_ for _ in response['Roles'])
            while 'Marker' in response:
                response = self.iam_client.list_roles(Marker=response['Marker'])
                role_list.extend(_ for _ in response['Roles'])
            return role_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def iam_role_inline_policy(self, role_name: str) -> list[dict]:
        try:
            policy_list: list[dict] = []
            response = self.iam_client.list_role_policies(RoleName=role_name)
            policy_list.extend(_ for _ in response['PolicyNames'])
            while 'Marker' in response:
                response = self.iam_client.list_role_policies(RoleName=role_name, Marker=response['Marker'])
                policy_list.extend(_ for _ in response['PolicyNames'])
            return policy_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def iam_role_policy_document(self, role_name: str, policy_name: str) -> dict:
        try:
            policy_document = self.iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)['PolicyDocument']
            return policy_document
        except ClientError as e:
            print(f"Error: {e}")
            return {}
        
    def kms_key_list(self) -> list[dict]:
        key_list: list[dict] = []
        try:
            response = self.kms_client.list_keys()
            key_list.extend(_ for _ in response['Keys'])
            while 'NextMarker' in response:
                response = self.kms_client.list_keys(Marker=response['NextMarker'])
                key_list.extend(_ for _ in response['Keys'])
            return key_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def kms_key_deletion_compliant(self, kms_key_id: str) -> str:
        try:
            compliant_status = "passed"
            describe_key = self.kms_client.describe_key(KeyId=kms_key_id)
            for key_metadata in describe_key['KeyMetadata']:
                if key_metadata.get('KeyState') == 'PendingDeletion':
                    compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        
    def kms_key_rotation_compliant(self, kms_key_id: str) -> str:
        try:
            compliant_status = "passed"
            key_rotation = self.kms_client.get_key_rotation_status(KeyId=kms_key_id)
            if key_rotation.get('KeyRotationEnabled') != True:
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""

    def kms_one(self) -> None:
        result_list = self.iam_custom_manage_policy_list()
        if not result_list:
            self.kms_list.append(self.create_kms_item(
                'KMS.1',
                'IAM customer managed policies should not allow decryption actions on all KMS keys',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.iam_policy_compliant(response_detail['Arn'])
            self.kms_list.append(self.create_kms_item(
                'KMS.1',
                'IAM customer managed policies should not allow decryption actions on all KMS keys',
                compliant_status,
                'MEDIUM',
                'available',
                response_detail['Arn']
            ))

    def kms_two(self) -> None:
        user_list = self.iam_user_list()
        group_list = self.iam_group_list()
        role_list = self.iam_role_list()
        if not user_list and not group_list and not role_list:
            self.kms_list.append(self.create_kms_item(
                'KMS.2',
                'IAM principals should not have IAM inline policies that allow decryption actions on all KMS keys',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in user_list:
            policy_list = self.iam_user_inline_policy(response_detail['UserName'])
            for policy in policy_list:
                policy_document = self.iam_user_policy_document(response_detail['UserName'], policy)
                compliant_status = self.iam_inline_policy_compliant(policy_document)
                self.kms_list.append(self.create_kms_item(
                    'KMS.2',
                    'IAM principals should not have IAM inline policies that allow decryption actions on all KMS keys',
                    compliant_status,
                    'MEDIUM',
                    'available',
                    response_detail['Arn']
                ))
        for response_detail in group_list:
            policy_list = self.iam_group_inline_policy(response_detail['GroupName'])
            for policy in policy_list:
                policy_document = self.iam_group_policy_document(response_detail['GroupName'], policy)
                compliant_status = self.iam_inline_policy_compliant(policy_document)
                self.kms_list.append(self.create_kms_item(
                    'KMS.2',
                    'IAM principals should not have IAM inline policies that allow decryption actions on all KMS keys',
                    compliant_status,
                    'MEDIUM',
                    'available',
                    response_detail['Arn']
                ))
        for response_detail in role_list:
            policy_list = self.iam_role_inline_policy(response_detail['RoleName'])
            for policy in policy_list:
                policy_document = self.iam_role_policy_document(response_detail['RoleName'], policy)
                compliant_status = self.iam_inline_policy_compliant(policy_document)
                self.kms_list.append(self.create_kms_item(
                    'KMS.2',
                    'IAM principals should not have IAM inline policies that allow decryption actions on all KMS keys',
                    compliant_status,
                    'MEDIUM',
                    'available',
                    response_detail['Arn']
                ))

    def kms_three(self) -> None:
        result_list = self.kms_key_list()
        if not result_list:
            self.kms_list.append(self.create_kms_item(
                'KMS.3',
                'AWS KMS keys should not be deleted unintentionally',
                'not_found',
                'CRITICAL',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.kms_key_deletion_compliant(response_detail['KeyId'])
            self.kms_list.append(self.create_kms_item(
                'KMS.3',
                'AWS KMS keys should not be deleted unintentionally',
                compliant_status,
                'CRITICAL',
                'not_available',
                response_detail['KeyArn']
            ))

    def kms_four(self) -> None:
        result_list = self.kms_key_list()
        if not result_list:
            self.kms_list.append(self.create_kms_item(
                'KMS.4',
                'AWS KMS key rotation should be enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.kms_key_rotation_compliant(response_detail['KeyId'])
            self.kms_list.append(self.create_kms_item(
                'KMS.4',
                'AWS KMS key rotation should be enabled',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['KeyArn']
            ))

class CrossAccountKMSAutoRemediation:
    def __init__(self) -> None:
        self.kms_client = UseCrossAccount().client('kms')
        self.session_region = UseCrossAccount().session_region_name
        self.session_account = UseCrossAccount().client('sts').get_caller_identity().get('Account')
        self.automate_key_description = "Automate Security Remediation Key with Best Practices"
        self.policy_document = {
            "Version": "2012-10-17",
            "Id": "key-default-1",
            "Statement": [
                {
                    "Sid": "Enable IAM User Permissions",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{self.session_account}:root"
                    },
                    "Action": "kms:*",
                    "Resource": "*"
                },
                {
                    "Sid": "Enable CloudWatch Log Group Permissions",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "*"
                    },
                    "Action": [
                        "kms:Encrypt*",
                        "kms:Decrypt*",
                        "kms:ReEncrypt*",
                        "kms:GenerateDataKey*",
                        "kms:Describe*"
                    ],
                    "Resource": f"arn:aws:kms:{self.session_region}:{self.session_account}:key/*"
                }
            ]
        }

    def create_kms_key(self) -> str:
        try:
            response = self.kms_client.create_key()
            key_id = response['KeyMetadata']['KeyId']
            key_arn = response['KeyMetadata']['Arn']
            self.kms_client.update_key_description(
                KeyId=key_id,
                Description=self.automate_key_description
            )
            self.kms_client.put_key_policy(
                KeyId=key_id,
                PolicyName='default',
                Policy=json.dumps(self.policy_document)
            )
            self.kms_client.create_alias(
                AliasName="alias/AutomateSecurityRemediationKey",
                TargetKeyId=key_id
            )
            self.kms_client.enable_key_rotation(
                KeyId=key_id
            )
            print(f"KMS key created: {key_arn}")
            return key_arn
        except ClientError as e:
            print(f"Error: {e}")
            return ""
    
    def get_kms_key_arn(self) -> str:
        try:
            key_list: list[dict] = []
            response = self.kms_client.list_keys()
            key_list.extend(_ for _ in response['Keys'])
            while 'NextMarker' in response:
                response = self.kms_client.list_keys(Marker=response['NextMarker'])
                key_list.extend(_ for _ in response['Keys'])
            kms_key_arn_check = [_['KeyArn'] \
                    for _ in key_list \
                    if self.kms_client.describe_key(KeyId=_['KeyId'])['KeyMetadata']['Description'] == self.automate_key_description]
            if kms_key_arn_check:
                kms_key_arn = kms_key_arn_check[0]
            else:
                kms_key_arn = self.create_kms_key()
            return kms_key_arn
        except ClientError as e:
            print(f"Error: {e}")
            return ""