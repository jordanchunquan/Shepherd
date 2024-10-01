'''
Class name IAMComplianceChecker
Create functions to check compliants and return as 
'control_id': security contorl id,
'control_title': security control title,
'compliance': passed, failed or not_found,
'severity': CRITICAL, HIGH, MEDIUM or LOW,
'auto_remediation': available or not_available,
'resource_id': account id, resource arn or not_found
'''

import boto3 # type: ignore
from botocore.exceptions import ClientError # type: ignore
from utils.decorator_class import DecoratorClass # type: ignore
from utils.validate import ParameterValidation # type: ignore
from utils.cross_account import UseCrossAccount # type: ignore
from utils.global_data import compliance_check_list # type: ignore
from datetime import datetime

class IAMComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.iam_client = boto3.client('iam')
        self.accessanalyzer_client = boto3.client('accessanalyzer')
        self.session_account = boto3.client('sts').get_caller_identity().get('Account')
        self.iam_list = compliance_check_list
        self.cloudshell_access_policy_list = [ \
                "arn:aws:iam::aws:policy/AWSCloudShellFullAccess", \
                "arn:aws-cn:iam::aws:policy/AWSCloudShellFullAccess", \
                "arn:aws-us-gov:iam::aws:policy/AWSCloudShellFullAccess" \
            ]

    def create_iam_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("IAM", control_id, compliance, severity, auto_remediation):
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

    def iam_local_policy_list(self) -> list[dict]:
        policy_list: list[dict] = []
        try:
            response = self.iam_client.list_policies(Scope="Local")
            policy_list.extend(_ for _ in response['Policies'])
            while "Marker" in response:
                response = self.iam_client.list_policies(Scope="Local", Marker=response['Marker'])
                policy_list.extend(_ for _ in response['Policies'])
            return policy_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    def iam_local_policy_document_compliant(self, policy_arn: str, policy_version: str) -> str:
        try:
            compliant_status = "passed"
            response = self.iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=policy_version
            )
            if all(['"Effect": "Allow"' in response['PolicyVersion']['Document'], \
                    '"Action": "*"' in response['PolicyVersion']['Document'], \
                    '"Resource": "*"' in response['PolicyVersion']['Document']]):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""

    def iam_user_list(self) -> list[dict]:
        user_list: list[dict] = []
        try:
            response = self.iam_client.list_users()
            user_list.extend(_ for _ in response['Users'])
            while "Marker" in response:
                response = self.iam_client.list_users(Marker=response['Marker'])
                user_list.extend(_ for _ in response['Users'])
            return user_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    def iam_user_policy_compliant(self, user_name: str) -> str:
        try:
            compliant_status = "passed"
            response = self.iam_client.list_user_policies(UserName=user_name)
            if response['PolicyNames']:
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""

    def iam_access_key_list(self) -> list[dict]:
        access_key_list: list[dict] = []
        try:
            response = self.iam_client.list_access_keys()
            access_key_list.extend(_ for _ in response['AccessKeyMetadata'])
            while "Marker" in response:
                response = self.iam_client.list_access_keys(Marker=response['Marker'])
                access_key_list.extend(_ for _ in response['AccessKeyMetadata'])
            return access_key_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    def iam_root_user_access_key(self) -> str:
        compliant_status = "passed"
        try:
            response = self.iam_client.list_access_keys(UserName="root")
            if response['AccessKeyMetadata']:
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            if ClientError.response['Error']['Code'] == "NoSuchEntityException":
                compliant_status = "passed"
                return compliant_status
            else:
                print(f"Error: {e}")
                return ""

    def iam_user_mfa(self, iam_username: str) -> str:
        try:
            compliant_status = "passed"
            response = self.iam_client.list_mfa_devices(UserName=iam_username)
            if not response['MFADevices']:
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            if ClientError.response['Error']['Code'] == "NoSuchEntityException":
                compliant_status = "failed"
                return compliant_status
            else:
                print(f"Error: {e}")
                return ""

    def iam_root_user_hardware_mfa(self) -> str:
        try:
            compliant_status = "passed"
            response = self.iam_client.list_mfa_devices(UserName="root")
            if all([_['SerialNumber'].startswith('arn:aws:iam::') for _ in response['MFADevices']]):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            if ClientError.response['Error']['Code'] == "NoSuchEntityException":
                compliant_status = "failed"
                return compliant_status
            else:
                print(f"Error: {e}")
                return ""

    def iam_password_policy(self) -> dict:
        try:
            response = self.iam_client.get_account_password_policy()
            return response['PasswordPolicy']
        except ClientError as e:
            print(f"Error: {e}")
            return {}

    def iam_root_user_mfa(self) -> str:
        try:
            compliant_status = "passed"
            response = self.iam_client.list_mfa_devices(UserName="root")
            if not response['MFADevices']:
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            if ClientError.response['Error']['Code'] == "NoSuchEntityException":
                compliant_status = "failed"
                return compliant_status
            else:
                print(f"Error: {e}")
                return ""

    def aws_support_compliant(self) -> str:
        try:
            compliant_status = "passed"
            response = self.iam_client.get_policy(PolicyArn="arn:aws:iam::aws:policy/AWSSupportAccess")
            if response['Policy']['AttachmentCount'] < 1:
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""

    def access_analyzer_analyzer_list(self) -> list[dict]:
        analyzer_list: list[dict] = []
        try:
            response = self.accessanalyzer_client.list_analyzers()
            analyzer_list.extend(_ for _ in response['analyzers'])
            while "nextToken" in response:
                response = self.accessanalyzer_client.list_analyzers(NextToken=response['nextToken'])
                analyzer_list.extend(_ for _ in response['analyzers'])
            return analyzer_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    def access_analyzer_complaint(self, analyzer_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.accessanalyzer_client.list_tags_for_resource(resourceArn=analyzer_arn)
            tag_key_list = [_['key'] for _ in response['tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""

    def iam_tag_compliant(self, iam_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.iam_client.list_tags_for_resource(ResourceArn=iam_arn)
            tag_key_list = [_['Key'] for _ in response['Tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""

    def iam_role_list(self) -> list[dict]:
        role_list: list[dict] = []
        try:
            response = self.iam_client.list_roles()
            role_list.extend(_ for _ in response['Roles'])
            while "Marker" in response:
                response = self.iam_client.list_roles(Marker=response['Marker'])
                role_list.extend(_ for _ in response['Roles'])
            return role_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    def iam_server_certificate(self) -> list[dict]:
        certificate_list: list[dict] = []
        try:
            response = self.iam_client.list_server_certificates()
            certificate_list.extend(_ for _ in response['ServerCertificateMetadataList'])
            while "Marker" in response:
                response = self.iam_client.list_server_certificates(Marker=response['Marker'])
                certificate_list.extend(_ for _ in response['ServerCertificateMetadataList'])
            return certificate_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    def iam_group_list(self) -> list[dict]:
        group_list: list[dict] = []
        try:
            response = self.iam_client.list_groups()
            group_list.extend(_ for _ in response['Groups'])
            while "Marker" in response:
                response = self.iam_client.list_groups(Marker=response['Marker'])
                group_list.extend(_ for _ in response['Groups'])
            return group_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    def iam_role_cloudshell_fullaccess_compliant(self, role_name: str) -> str:
        try:
            compliant_status = "passed"
            response = self.iam_client.list_attached_role_policies(RoleName=role_name)
            for policy in response['AttachedPolicies']:
                if policy['PolicyArn'] in self.cloudshell_access_policy_list:
                    compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""

    def iam_user_cloudshell_fullaccess_compliant(self, user_name: str) -> str:
        try:
            compliant_status = "passed"
            response = self.iam_client.list_attached_user_policies(UserName=user_name)
            for policy in response['AttachedPolicies']:
                if policy['PolicyArn'] in self.cloudshell_access_policy_list:
                    compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""

    def iam_group_cloudshell_fullaccess_compliant(self, group_name: str) -> str:
        try:
            compliant_status = "passed"
            response = self.iam_client.list_attached_group_policies(GroupName=group_name)
            for policy in response['AttachedPolicies']:
                if policy['PolicyArn'] in self.cloudshell_access_policy_list:
                    compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""

    @DecoratorClass.my_decorator
    def iam_one(self) -> None:
        result_list = self.iam_local_policy_list()
        if not result_list:
            self.iam_list.append(self.create_iam_item(
                'IAM.1',
                'IAM policies should not allow full "*" administrative privileges',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for result in result_list:
            compliant_status = self.iam_local_policy_document_compliant(result['Arn'], result['DefaultVersionId'])
            self.iam_list.append(self.create_iam_item(
                'IAM.1',
                'IAM policies should not allow full "*" administrative privileges',
                compliant_status,
                'HIGH',
                'available',
                result['Arn']
            ))

    @DecoratorClass.my_decorator
    def iam_two(self) -> None:
        result_list = self.iam_user_list()
        if not result_list:
            self.iam_list.append(self.create_iam_item(
                'IAM.2',
                'IAM users should not have IAM policies attached',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for result in result_list:
            compliant_status = self.iam_user_policy_compliant(result['UserName'])
            self.iam_list.append(self.create_iam_item(
                'IAM.2',
                'IAM users should not have IAM policies attached',
                compliant_status,
                'LOW',
                'available',
                result['Arn']
            ))

    @DecoratorClass.my_decorator
    def iam_three(self) -> None:
        result_list = self.iam_access_key_list()
        if not result_list:
            self.iam_list.append(self.create_iam_item(
                'IAM.3',
                "IAM users' access keys should be rotated every 90 days or less",
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for result in result_list:
            if (datetime.now().date() - result['CreateDate']).days > 90:
                self.iam_list.append(self.create_iam_item(
                    'IAM.3',
                    "IAM users' access keys should be rotated every 90 days or less",
                    'failed',
                    'MEDIUM',
                    'available',
                    result['AccessKeyId']
                ))
            else:
                self.iam_list.append(self.create_iam_item(
                    'IAM.3',
                    "IAM users' access keys should be rotated every 90 days or less",
                    'passed',
                    'MEDIUM',
                    'available',
                    result['AccessKeyId']
                ))

    @DecoratorClass.my_decorator
    def iam_four(self) -> None:
        compliant_status = self.iam_root_user_access_key()
        self.iam_list.append(self.create_iam_item(
            'IAM.4',
            'IAM root user access key should not exist',
            compliant_status,
            'CRITICAL',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def iam_five(self) -> None:
        result_list = self.iam_user_list()
        result_list = [_ for _ in result_list if _.get('PasswordLastUsed') != None]
        if not result_list:
            self.iam_list.append(self.create_iam_item(
                'IAM.5',
                'MFA should be enabled for all IAM users that have a console password',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for result in result_list:
            compliant_status = self.iam_user_mfa(result['UserName'])
            self.iam_list.append(self.create_iam_item(
                'IAM.5',
                'MFA should be enabled for all IAM users that have a console password',
                compliant_status,
                'MEDIUM',
                'not_available',
                result['Arn']
            ))

    @DecoratorClass.my_decorator
    def iam_six(self) -> None:
        compliant_status = self.iam_root_user_hardware_mfa()
        self.iam_list.append(self.create_iam_item(
            'IAM.6',
            'Hardware MFA should be enabled for the root user',
            compliant_status,
            'MEDIUM',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def iam_seven(self) -> None:
        result = self.iam_password_policy()
        if any([
            result['RequireUppercaseCharacters'] != True,
            result['RequireLowercaseCharacters'] != True,
            result['RequireSymbols'] != True,
            result['RequireNumbers'] != True,
            result['MinimumPasswordLength'] < 8,
            result['PasswordReusePrevention'] < 5,
            result['MaxPasswordAge'] > 90,
        ]):
            self.iam_list.append(self.create_iam_item(
                'IAM.7',
                'Password policies for IAM users should have strong configurations',
                'failed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))
        else:
            self.iam_list.append(self.create_iam_item(
                'IAM.7',
                'Password policies for IAM users should have strong configurations',
                'passed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))

    @DecoratorClass.my_decorator
    def iam_eight(self) -> None:
        result_list = self.iam_user_list()
        if not result_list:
            self.iam_list.append(self.create_iam_item(
                'IAM.8',
                'Unused IAM user credentials should be removed',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if datetime.now().date() - response_detail['PasswordLastUsed'].date() > 90:
                self.iam_list.append(self.create_iam_item(
                    'IAM.8',
                    'Unused IAM user credentials should be removed',
                    'failed',
                    'MEDIUM',
                    'available',
                    response_detail['Arn']
                ))
            else:
                self.iam_list.append(self.create_iam_item(
                    'IAM.8',
                    'Unused IAM user credentials should be removed',
                    'passed',
                    'MEDIUM',
                    'available',
                    response_detail['Arn']
                ))

    @DecoratorClass.my_decorator
    def iam_nine(self) -> None:
        compliant_status = self.iam_root_user_mfa()
        self.iam_list.append(self.create_iam_item(
            'IAM.9',
            'MFA should be enabled for the root user',
            compliant_status,
            'CRITICAL',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def iam_ten(self) -> None:
        result = self.iam_password_policy()
        if any([
            result['RequireUppercaseCharacters'] != True,
            result['RequireLowercaseCharacters'] != True,
            result['RequireNumbers'] != True,
            result['MinimumPasswordLength'] < 7,
            result['PasswordReusePrevention'] < 4,
            result['MaxPasswordAge'] > 90,
        ]):
            self.iam_list.append(self.create_iam_item(
                'IAM.10',
                'Password policies for IAM users should have strong configurations',
                'failed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))
        else:
            self.iam_list.append(self.create_iam_item(
                'IAM.10',
                'Password policies for IAM users should have strong configurations',
                'passed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))

    @DecoratorClass.my_decorator
    def iam_eleven(self) -> None:
        result = self.iam_password_policy()
        if result['RequireUppercaseCharacters'] != True:
            self.iam_list.append(self.create_iam_item(
                'IAM.11',
                'Ensure IAM password policy requires at least one uppercase letter',
                'failed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))
        else:
            self.iam_list.append(self.create_iam_item(
                'IAM.11',
                'Ensure IAM password policy requires at least one uppercase letter',
                'passed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))

    @DecoratorClass.my_decorator
    def iam_twelve(self) -> None:
        result = self.iam_password_policy()
        if result['RequireLowercaseCharacters'] != True:
            self.iam_list.append(self.create_iam_item(
                'IAM.12',
                'Ensure IAM password policy requires at least one lowercase letter',
                'failed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))
        else:
            self.iam_list.append(self.create_iam_item(
                'IAM.12',
                'Ensure IAM password policy requires at least one lowercase letter',
                'passed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))

    @DecoratorClass.my_decorator
    def iam_thirteen(self) -> None:
        result = self.iam_password_policy()
        if result['RequireSymbols'] != True:
            self.iam_list.append(self.create_iam_item(
                'IAM.13',
                'Ensure IAM password policy requires at least one symbol',
                'failed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))
        else:
            self.iam_list.append(self.create_iam_item(
                'IAM.13',
                'Ensure IAM password policy requires at least one symbol',
                'passed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))

    @DecoratorClass.my_decorator
    def iam_fourteen(self) -> None:
        result = self.iam_password_policy()
        if result['RequireNumbers'] != True:
            self.iam_list.append(self.create_iam_item(
                'IAM.14',
                'Ensure IAM password policy requires at least one number',
                'failed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))
        else:
            self.iam_list.append(self.create_iam_item(
                'IAM.14',
                'Ensure IAM password policy requires at least one number',
                'passed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))

    @DecoratorClass.my_decorator
    def iam_fifteen(self) -> None:
        result = self.iam_password_policy()
        if result['MinimumPasswordLength'] < 14:
            self.iam_list.append(self.create_iam_item(
                'IAM.15',
                'Ensure IAM password policy requires minimum password length of 14 or greater',
                'failed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))
        else:
            self.iam_list.append(self.create_iam_item(
                'IAM.15',
                'Ensure IAM password policy requires minimum password length of 14 or greater',
                'passed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))

    @DecoratorClass.my_decorator
    def iam_sixteen(self) -> None:
        result = self.iam_password_policy()
        if result['PasswordReusePrevention'] < 24:
            self.iam_list.append(self.create_iam_item(
                'IAM.16',
                'Ensure IAM password policy prevents password reuser',
                'failed',
                'LOW',
                'not_available',
                self.session_account
            ))
        else:
            self.iam_list.append(self.create_iam_item(
                'IAM.16',
                'Ensure IAM password policy prevents password reuser',
                'passed',
                'LOW',
                'not_available',
                self.session_account
            ))

    @DecoratorClass.my_decorator
    def iam_seventeen(self) -> None:
        result = self.iam_password_policy()
        if result['MaxPasswordAge'] > 90:
            self.iam_list.append(self.create_iam_item(
                'IAM.17',
                'Ensure IAM password policy expires passwords within 90 days or less',
                'failed',
                'LOW',
                'not_available',
                self.session_account
            ))
        else:
            self.iam_list.append(self.create_iam_item(
                'IAM.17',
                'Ensure IAM password policy expires passwords within 90 days or less',
                'passed',
                'LOW',
                'not_available',
                self.session_account
            ))

    @DecoratorClass.my_decorator
    def iam_eighteen(self) -> None:
        compliant_status = self.aws_support_compliant()
        self.iam_list.append(self.create_iam_item(
            'IAM.18',
            'Ensure a support role has been created to manage incidents with AWS Support',
            compliant_status,
            'LOW',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def iam_nineteen(self) -> None:
        result_list = self.iam_user_list()
        if not result_list:
            self.iam_list.append(self.create_iam_item(
                'IAM.19',
                'MFA should be enabled for all IAM users',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for result in result_list:
            compliant_status = self.iam_user_mfa(result['UserName'])
            self.iam_list.append(self.create_iam_item(
                'IAM.19',
                'MFA should be enabled for all IAM users',
                compliant_status,
                'MEDIUM',
                'not_available',
                result['Arn']
            ))

    @DecoratorClass.my_decorator
    def iam_twentyone(self) -> None:
        result_list = self.iam_local_policy_list()
        if not result_list:
            self.iam_list.append(self.create_iam_item(
                'IAM.21',
                'IAM customer managed policies that you create should not allow wildcard actions for services',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for result in result_list:
            compliant_status = self.iam_local_policy_document_compliant(result['Arn'], result['DefaultVersionId'])
            self.iam_list.append(self.create_iam_item(
                'IAM.21',
                'IAM customer managed policies that you create should not allow wildcard actions for services',
                compliant_status,
                'LOW',
                'available',
                result['Arn']
            ))
        
    @DecoratorClass.my_decorator
    def iam_twentytwo(self) -> None:
        result_list = self.iam_user_list()
        if not result_list:
            self.iam_list.append(self.create_iam_item(
                'IAM.22',
                'IAM user credentials unused for 45 days should be removed',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for result in result_list:
            if datetime.now().date() - result['PasswordLastUsed'].date() > 45:
                self.iam_list.append(self.create_iam_item(
                    'IAM.22',
                    'IAM user credentials unused for 45 days should be removed',
                    'failed',
                    'MEDIUM',
                    'available',
                    result['Arn']
                ))
            else:
                self.iam_list.append(self.create_iam_item(
                    'IAM.22',
                    'IAM user credentials unused for 45 days should be removed',
                    'passed',
                    'MEDIUM',
                    'available',
                    result['Arn']
                ))
        
    @DecoratorClass.my_decorator
    def iam_twentythree(self) -> None:
        result_list = self.access_analyzer_analyzer_list()
        if not result_list:
            self.iam_list.append(self.create_iam_item(
                'IAM.23',
                'IAM Access Analyzer analyzers should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for result in result_list:
            compliant_status = self.access_analyzer_complaint(result['arn'])
            self.iam_list.append(self.create_iam_item(
                'IAM.23',
                'IAM Access Analyzer analyzers should be tagged',
                compliant_status,
                'LOW',
                'available',
                result['arn']
            ))
        
    @DecoratorClass.my_decorator
    def iam_twentyfour(self) -> None:
        result_list = self.iam_role_list()
        if not result_list:
            self.iam_list.append(self.create_iam_item(
                'IAM.24',
                'IAM roles should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for result in result_list:
            compliant_status = self.iam_tag_compliant(result['Arn'])
            self.iam_list.append(self.create_iam_item(
                'IAM.24',
                'IAM roles should be tagged',
                compliant_status,
                'LOW',
                'available',
                result['Arn']
            ))
        
    @DecoratorClass.my_decorator
    def iam_twentyfive(self) -> None:
        result_list = self.iam_user_list()
        if not result_list:
            self.iam_list.append(self.create_iam_item(
                'IAM.25',
                'IAM users should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for result in result_list:
            compliant_status = self.iam_tag_compliant(result['Arn'])
            self.iam_list.append(self.create_iam_item(
                'IAM.25',
                'IAM users should be tagged',
                compliant_status,
                'LOW',
                'available',
                result['Arn']
            ))
        
    @DecoratorClass.my_decorator
    def iam_twentysix(self) -> None:
        result_list = self.iam_server_certificate()
        if not result_list:
            self.iam_list.append(self.create_iam_item(
                'IAM.26',
                'Expired SSL/TLS certificates managed in IAM should be removed',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for result in result_list:
            if result['Expiration'] < datetime.now():
                self.iam_list.append(self.create_iam_item(
                    'IAM.26',
                    'Expired SSL/TLS certificates managed in IAM should be removed',
                    'failed',
                    'MEDIUM',
                    'available',
                    result['ServerCertificateId']
                ))
            else:
                self.iam_list.append(self.create_iam_item(
                    'IAM.26',
                    'Expired SSL/TLS certificates managed in IAM should be removed',
                    'passed',
                    'MEDIUM',
                    'available',
                    result['ServerCertificateId']
                ))
        
    @DecoratorClass.my_decorator
    def iam_twentyseven(self) -> None:
        role_result_list = self.iam_role_list()
        user_result_list = self.iam_user_list()
        group_result_list = self.iam_group_list()
        if not role_result_list and not user_result_list and not group_result_list:
            self.iam_list.append(self.create_iam_item(
                'IAM.27',
                'IAM identities should not have the AWSCloudShellFullAccess policy attached',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for role_result in role_result_list:
            compliant_status = self.iam_role_cloudshell_fullaccess_compliant(role_result['RoleName'])
            self.iam_list.append(self.create_iam_item(
                'IAM.27',
                'IAM identities should not have the AWSCloudShellFullAccess policy attached',
                compliant_status,
                'MEDIUM',
                'available',
                role_result['Arn']
            ))
        for user_result in user_result_list:
            compliant_status = self.iam_user_cloudshell_fullaccess_compliant(user_result['UserName'])
            self.iam_list.append(self.create_iam_item(
                'IAM.27',
                'IAM identities should not have the AWSCloudShellFullAccess policy attached',
                compliant_status,
                'MEDIUM',
                'available',
                user_result['Arn']
            ))
        for group_result in group_result_list:
            compliant_status = self.iam_group_cloudshell_fullaccess_compliant(group_result['GroupName'])
            self.iam_list.append(self.create_iam_item(
                'IAM.27',
                'IAM identities should not have the AWSCloudShellFullAccess policy attached',
                compliant_status,
                'MEDIUM',
                'available',
                group_result['Arn']
            ))
        
    @DecoratorClass.my_decorator
    def iam_twentyeight(self) -> None:
        result_list = self.access_analyzer_analyzer_list()
        if not result_list or all([_['Type'] != 'EXTERNAL' for _ in result_list]):
            self.iam_list.append(self.create_iam_item(
                'IAM.28',
                'IAM Access Analyzer external access analyzer should be enabled',
                'failed',
                'HIGH',
                'not_available',
                self.session_account
            ))
        else:
            self.iam_list.append(self.create_iam_item(
                'IAM.28',
                'IAM Access Analyzer external access analyzer should be enabled',
                'passed',
                'HIGH',
                'not_available',
                self.session_account
            ))

class IAMAutoRemediation:
    def __init__(self) -> None:
        self.iam_client = boto3.client('iam')
        
    def create_iam_role(self, role_name: str, assume_role_policy_document: str) -> None:
        try:
            self.iam_client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=assume_role_policy_document
            )
            print(f"IAM role created: {role_name}")
        except ClientError as e:
            print(f"Error: {e}")

    def create_iam_policy(self, policy_name: str, policy_document: str) -> None:
        try:
            self.iam_client.create_policy(
                PolicyName=policy_name,
                PolicyDocument=policy_document
            )
            print(f"IAM policy created: {policy_name}")
        except ClientError as e:
            print(f"Error: {e}")

    def attach_policy_to_role(self, role_name: str, policy_arn: str) -> None:
        try:
            self.iam_client.attach_role_policy(
                RoleName=role_name,
                PolicyArn=policy_arn
            )
            print(f"IAM policy: {policy_arn} attached to IAM role: {role_name}")
        except ClientError as e:
            print(f"Error: {e}")

class CrossAccountIAMComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.iam_client = UseCrossAccount().client('iam')
        self.accessanalyzer_client = UseCrossAccount().client('accessanalyzer')
        self.session_account = UseCrossAccount().client('sts').get_caller_identity().get('Account')
        self.iam_list = compliance_check_list
        self.cloudshell_access_policy_list = [ \
                "arn:aws:iam::aws:policy/AWSCloudShellFullAccess", \
                "arn:aws-cn:iam::aws:policy/AWSCloudShellFullAccess", \
                "arn:aws-us-gov:iam::aws:policy/AWSCloudShellFullAccess" \
            ]

    def create_iam_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("IAM", control_id, compliance, severity, auto_remediation):
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
        
    def iam_local_policy_list(self) -> list[dict]:
        policy_list: list[dict] = []
        try:
            response = self.iam_client.list_policies(Scope="Local")
            policy_list.extend(_ for _ in response['Policies'])
            while "Marker" in response:
                response = self.iam_client.list_policies(Scope="Local", Marker=response['Marker'])
                policy_list.extend(_ for _ in response['Policies'])
            return policy_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def iam_local_policy_document_compliant(self, policy_arn: str, policy_version: str) -> str:
        try:
            compliant_status = "passed"
            response = self.iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=policy_version
            )
            if all(['"Effect": "Allow"' in response['PolicyVersion']['Document'], \
                    '"Action": "*"' in response['PolicyVersion']['Document'], \
                    '"Resource": "*"' in response['PolicyVersion']['Document']]):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        
    def iam_user_list(self) -> list[dict]:
        user_list: list[dict] = []
        try:
            response = self.iam_client.list_users()
            user_list.extend(_ for _ in response['Users'])
            while "Marker" in response:
                response = self.iam_client.list_users(Marker=response['Marker'])
                user_list.extend(_ for _ in response['Users'])
            return user_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def iam_user_policy_compliant(self, user_name: str) -> str:
        try:
            compliant_status = "passed"
            response = self.iam_client.list_user_policies(UserName=user_name)
            if response['PolicyNames']:
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        
    def iam_access_key_list(self) -> list[dict]:
        access_key_list: list[dict] = []
        try:
            response = self.iam_client.list_access_keys()
            access_key_list.extend(_ for _ in response['AccessKeyMetadata'])
            while "Marker" in response:
                response = self.iam_client.list_access_keys(Marker=response['Marker'])
                access_key_list.extend(_ for _ in response['AccessKeyMetadata'])
            return access_key_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def iam_root_user_access_key(self) -> str:
        compliant_status = "passed"
        try:
            response = self.iam_client.list_access_keys(UserName="root")
            if response['AccessKeyMetadata']:
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            if ClientError.response['Error']['Code'] == "NoSuchEntityException":
                compliant_status = "passed"
                return compliant_status
            else:
                print(f"Error: {e}")
                return ""
            
    def iam_user_mfa(self, iam_username: str) -> str:
        try:
            compliant_status = "passed"
            response = self.iam_client.list_mfa_devices(UserName=iam_username)
            if not response['MFADevices']:
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            if ClientError.response['Error']['Code'] == "NoSuchEntityException":
                compliant_status = "failed"
                return compliant_status
            else:
                print(f"Error: {e}")
                return ""
            
    def iam_root_user_hardware_mfa(self) -> str:
        try:
            compliant_status = "passed"
            response = self.iam_client.list_mfa_devices(UserName="root")
            if all([_['SerialNumber'].startswith('arn:aws:iam::') for _ in response['MFADevices']]):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            if ClientError.response['Error']['Code'] == "NoSuchEntityException":
                compliant_status = "failed"
                return compliant_status
            else:
                print(f"Error: {e}")
                return ""
            
    def iam_password_policy(self) -> dict:
        try:
            response = self.iam_client.get_account_password_policy()
            return response['PasswordPolicy']
        except ClientError as e:
            print(f"Error: {e}")
            return {}
            
    def iam_root_user_mfa(self) -> str:
        try:
            compliant_status = "passed"
            response = self.iam_client.list_mfa_devices(UserName="root")
            if not response['MFADevices']:
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            if ClientError.response['Error']['Code'] == "NoSuchEntityException":
                compliant_status = "failed"
                return compliant_status
            else:
                print(f"Error: {e}")
                return ""
            
    def aws_support_compliant(self) -> str:
        try:
            compliant_status = "passed"
            response = self.iam_client.get_policy(PolicyArn="arn:aws:iam::aws:policy/AWSSupportAccess")
            if response['Policy']['AttachmentCount'] < 1:
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        
    def access_analyzer_analyzer_list(self) -> list[dict]:
        analyzer_list: list[dict] = []
        try:
            response = self.accessanalyzer_client.list_analyzers()
            analyzer_list.extend(_ for _ in response['analyzers'])
            while "nextToken" in response:
                response = self.accessanalyzer_client.list_analyzers(NextToken=response['nextToken'])
                analyzer_list.extend(_ for _ in response['analyzers'])
            return analyzer_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def access_analyzer_complaint(self, analyzer_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.accessanalyzer_client.list_tags_for_resource(resourceArn=analyzer_arn)
            tag_key_list = [_['key'] for _ in response['tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        
    def iam_tag_compliant(self, iam_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.iam_client.list_tags_for_resource(ResourceArn=iam_arn)
            tag_key_list = [_['Key'] for _ in response['Tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        
    def iam_role_list(self) -> list[dict]:
        role_list: list[dict] = []
        try:
            response = self.iam_client.list_roles()
            role_list.extend(_ for _ in response['Roles'])
            while "Marker" in response:
                response = self.iam_client.list_roles(Marker=response['Marker'])
                role_list.extend(_ for _ in response['Roles'])
            return role_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def iam_server_certificate(self) -> list[dict]:
        certificate_list: list[dict] = []
        try:
            response = self.iam_client.list_server_certificates()
            certificate_list.extend(_ for _ in response['ServerCertificateMetadataList'])
            while "Marker" in response:
                response = self.iam_client.list_server_certificates(Marker=response['Marker'])
                certificate_list.extend(_ for _ in response['ServerCertificateMetadataList'])
            return certificate_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def iam_group_list(self) -> list[dict]:
        group_list: list[dict] = []
        try:
            response = self.iam_client.list_groups()
            group_list.extend(_ for _ in response['Groups'])
            while "Marker" in response:
                response = self.iam_client.list_groups(Marker=response['Marker'])
                group_list.extend(_ for _ in response['Groups'])
            return group_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def iam_role_cloudshell_fullaccess_compliant(self, role_name: str) -> str:
        try:
            compliant_status = "passed"
            response = self.iam_client.list_attached_role_policies(RoleName=role_name)
            for policy in response['AttachedPolicies']:
                if policy['PolicyArn'] in self.cloudshell_access_policy_list:
                    compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""

    def iam_user_cloudshell_fullaccess_compliant(self, user_name: str) -> str:
        try:
            compliant_status = "passed"
            response = self.iam_client.list_attached_user_policies(UserName=user_name)
            for policy in response['AttachedPolicies']:
                if policy['PolicyArn'] in self.cloudshell_access_policy_list:
                    compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        
    def iam_group_cloudshell_fullaccess_compliant(self, group_name: str) -> str:
        try:
            compliant_status = "passed"
            response = self.iam_client.list_attached_group_policies(GroupName=group_name)
            for policy in response['AttachedPolicies']:
                if policy['PolicyArn'] in self.cloudshell_access_policy_list:
                    compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        
    @DecoratorClass.my_decorator
    def iam_one(self) -> None:
        result_list = self.iam_local_policy_list()
        if not result_list:
            self.iam_list.append(self.create_iam_item(
                'IAM.1',
                'IAM policies should not allow full "*" administrative privileges',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for result in result_list:
            compliant_status = self.iam_local_policy_document_compliant(result['Arn'], result['DefaultVersionId'])
            self.iam_list.append(self.create_iam_item(
                'IAM.1',
                'IAM policies should not allow full "*" administrative privileges',
                compliant_status,
                'HIGH',
                'available',
                result['Arn']
            ))
        
    @DecoratorClass.my_decorator
    def iam_two(self) -> None:
        result_list = self.iam_user_list()
        if not result_list:
            self.iam_list.append(self.create_iam_item(
                'IAM.2',
                'IAM users should not have IAM policies attached',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for result in result_list:
            compliant_status = self.iam_user_policy_compliant(result['UserName'])
            self.iam_list.append(self.create_iam_item(
                'IAM.2',
                'IAM users should not have IAM policies attached',
                compliant_status,
                'LOW',
                'available',
                result['Arn']
            ))
        
    @DecoratorClass.my_decorator
    def iam_three(self) -> None:
        result_list = self.iam_access_key_list()
        if not result_list:
            self.iam_list.append(self.create_iam_item(
                'IAM.3',
                "IAM users' access keys should be rotated every 90 days or less",
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for result in result_list:
            if (datetime.now().date() - result['CreateDate']).days > 90:
                self.iam_list.append(self.create_iam_item(
                    'IAM.3',
                    "IAM users' access keys should be rotated every 90 days or less",
                    'failed',
                    'MEDIUM',
                    'available',
                    result['AccessKeyId']
                ))
            else:
                self.iam_list.append(self.create_iam_item(
                    'IAM.3',
                    "IAM users' access keys should be rotated every 90 days or less",
                    'passed',
                    'MEDIUM',
                    'available',
                    result['AccessKeyId']
                ))
        
    @DecoratorClass.my_decorator
    def iam_four(self) -> None:
        compliant_status = self.iam_root_user_access_key()
        self.iam_list.append(self.create_iam_item(
            'IAM.4',
            'IAM root user access key should not exist',
            compliant_status,
            'CRITICAL',
            'not_available',
            self.session_account
        ))
        
    @DecoratorClass.my_decorator
    def iam_five(self) -> None:
        result_list = self.iam_user_list()
        result_list = [_ for _ in result_list if _.get('PasswordLastUsed') != None]
        if not result_list:
            self.iam_list.append(self.create_iam_item(
                'IAM.5',
                'MFA should be enabled for all IAM users that have a console password',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for result in result_list:
            compliant_status = self.iam_user_mfa(result['UserName'])
            self.iam_list.append(self.create_iam_item(
                'IAM.5',
                'MFA should be enabled for all IAM users that have a console password',
                compliant_status,
                'MEDIUM',
                'not_available',
                result['Arn']
            ))
        
    @DecoratorClass.my_decorator
    def iam_six(self) -> None:
        compliant_status = self.iam_root_user_hardware_mfa()
        self.iam_list.append(self.create_iam_item(
            'IAM.6',
            'Hardware MFA should be enabled for the root user',
            compliant_status,
            'MEDIUM',
            'not_available',
            self.session_account
        ))
        
    @DecoratorClass.my_decorator
    def iam_seven(self) -> None:
        result = self.iam_password_policy()
        if any([
            result['RequireUppercaseCharacters'] != True,
            result['RequireLowercaseCharacters'] != True,
            result['RequireSymbols'] != True,
            result['RequireNumbers'] != True,
            result['MinimumPasswordLength'] < 8,
            result['PasswordReusePrevention'] < 5,
            result['MaxPasswordAge'] > 90,
        ]):
            self.iam_list.append(self.create_iam_item(
                'IAM.7',
                'Password policies for IAM users should have strong configurations',
                'failed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))
        else:
            self.iam_list.append(self.create_iam_item(
                'IAM.7',
                'Password policies for IAM users should have strong configurations',
                'passed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))
        
    @DecoratorClass.my_decorator
    def iam_eight(self) -> None:
        result_list = self.iam_user_list()
        if not result_list:
            self.iam_list.append(self.create_iam_item(
                'IAM.8',
                'Unused IAM user credentials should be removed',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if datetime.now().date() - response_detail['PasswordLastUsed'].date() > 90:
                self.iam_list.append(self.create_iam_item(
                    'IAM.8',
                    'Unused IAM user credentials should be removed',
                    'failed',
                    'MEDIUM',
                    'available',
                    response_detail['Arn']
                ))
            else:
                self.iam_list.append(self.create_iam_item(
                    'IAM.8',
                    'Unused IAM user credentials should be removed',
                    'passed',
                    'MEDIUM',
                    'available',
                    response_detail['Arn']
                ))
        
    @DecoratorClass.my_decorator
    def iam_nine(self) -> None:
        compliant_status = self.iam_root_user_mfa()
        self.iam_list.append(self.create_iam_item(
            'IAM.9',
            'MFA should be enabled for the root user',
            compliant_status,
            'CRITICAL',
            'not_available',
            self.session_account
        ))
        
    @DecoratorClass.my_decorator
    def iam_ten(self) -> None:
        result = self.iam_password_policy()
        if any([
            result['RequireUppercaseCharacters'] != True,
            result['RequireLowercaseCharacters'] != True,
            result['RequireNumbers'] != True,
            result['MinimumPasswordLength'] < 7,
            result['PasswordReusePrevention'] < 4,
            result['MaxPasswordAge'] > 90,
        ]):
            self.iam_list.append(self.create_iam_item(
                'IAM.10',
                'Password policies for IAM users should have strong configurations',
                'failed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))
        else:
            self.iam_list.append(self.create_iam_item(
                'IAM.10',
                'Password policies for IAM users should have strong configurations',
                'passed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))
        
    @DecoratorClass.my_decorator
    def iam_eleven(self) -> None:
        result = self.iam_password_policy()
        if result['RequireUppercaseCharacters'] != True:
            self.iam_list.append(self.create_iam_item(
                'IAM.11',
                'Ensure IAM password policy requires at least one uppercase letter',
                'failed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))
        else:
            self.iam_list.append(self.create_iam_item(
                'IAM.11',
                'Ensure IAM password policy requires at least one uppercase letter',
                'passed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))
        
    @DecoratorClass.my_decorator
    def iam_twelve(self) -> None:
        result = self.iam_password_policy()
        if result['RequireLowercaseCharacters'] != True:
            self.iam_list.append(self.create_iam_item(
                'IAM.12',
                'Ensure IAM password policy requires at least one lowercase letter',
                'failed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))
        else:
            self.iam_list.append(self.create_iam_item(
                'IAM.12',
                'Ensure IAM password policy requires at least one lowercase letter',
                'passed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))
        
    @DecoratorClass.my_decorator
    def iam_thirteen(self) -> None:
        result = self.iam_password_policy()
        if result['RequireSymbols'] != True:
            self.iam_list.append(self.create_iam_item(
                'IAM.13',
                'Ensure IAM password policy requires at least one symbol',
                'failed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))
        else:
            self.iam_list.append(self.create_iam_item(
                'IAM.13',
                'Ensure IAM password policy requires at least one symbol',
                'passed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))
        
    @DecoratorClass.my_decorator
    def iam_fourteen(self) -> None:
        result = self.iam_password_policy()
        if result['RequireNumbers'] != True:
            self.iam_list.append(self.create_iam_item(
                'IAM.14',
                'Ensure IAM password policy requires at least one number',
                'failed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))
        else:
            self.iam_list.append(self.create_iam_item(
                'IAM.14',
                'Ensure IAM password policy requires at least one number',
                'passed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))
        
    @DecoratorClass.my_decorator
    def iam_fifteen(self) -> None:
        result = self.iam_password_policy()
        if result['MinimumPasswordLength'] < 14:
            self.iam_list.append(self.create_iam_item(
                'IAM.15',
                'Ensure IAM password policy requires minimum password length of 14 or greater',
                'failed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))
        else:
            self.iam_list.append(self.create_iam_item(
                'IAM.15',
                'Ensure IAM password policy requires minimum password length of 14 or greater',
                'passed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))
        
    @DecoratorClass.my_decorator
    def iam_sixteen(self) -> None:
        result = self.iam_password_policy()
        if result['PasswordReusePrevention'] < 24:
            self.iam_list.append(self.create_iam_item(
                'IAM.16',
                'Ensure IAM password policy prevents password reuser',
                'failed',
                'LOW',
                'not_available',
                self.session_account
            ))
        else:
            self.iam_list.append(self.create_iam_item(
                'IAM.16',
                'Ensure IAM password policy prevents password reuser',
                'passed',
                'LOW',
                'not_available',
                self.session_account
            ))
        
    @DecoratorClass.my_decorator
    def iam_seventeen(self) -> None:
        result = self.iam_password_policy()
        if result['MaxPasswordAge'] > 90:
            self.iam_list.append(self.create_iam_item(
                'IAM.17',
                'Ensure IAM password policy expires passwords within 90 days or less',
                'failed',
                'LOW',
                'not_available',
                self.session_account
            ))
        else:
            self.iam_list.append(self.create_iam_item(
                'IAM.17',
                'Ensure IAM password policy expires passwords within 90 days or less',
                'passed',
                'LOW',
                'not_available',
                self.session_account
            ))
        
    @DecoratorClass.my_decorator
    def iam_eighteen(self) -> None:
        compliant_status = self.aws_support_compliant()
        self.iam_list.append(self.create_iam_item(
            'IAM.18',
            'Ensure a support role has been created to manage incidents with AWS Support',
            compliant_status,
            'LOW',
            'not_available',
            self.session_account
        ))
        
    @DecoratorClass.my_decorator
    def iam_nineteen(self) -> None:
        result_list = self.iam_user_list()
        if not result_list:
            self.iam_list.append(self.create_iam_item(
                'IAM.19',
                'MFA should be enabled for all IAM users',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for result in result_list:
            compliant_status = self.iam_user_mfa(result['UserName'])
            self.iam_list.append(self.create_iam_item(
                'IAM.19',
                'MFA should be enabled for all IAM users',
                compliant_status,
                'MEDIUM',
                'not_available',
                result['Arn']
            ))
        
    @DecoratorClass.my_decorator
    def iam_twentyone(self) -> None:
        result_list = self.iam_local_policy_list()
        if not result_list:
            self.iam_list.append(self.create_iam_item(
                'IAM.21',
                'IAM customer managed policies that you create should not allow wildcard actions for services',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for result in result_list:
            compliant_status = self.iam_local_policy_document_compliant(result['Arn'], result['DefaultVersionId'])
            self.iam_list.append(self.create_iam_item(
                'IAM.21',
                'IAM customer managed policies that you create should not allow wildcard actions for services',
                compliant_status,
                'LOW',
                'available',
                result['Arn']
            ))
        
    @DecoratorClass.my_decorator
    def iam_twentytwo(self) -> None:
        result_list = self.iam_user_list()
        if not result_list:
            self.iam_list.append(self.create_iam_item(
                'IAM.22',
                'IAM user credentials unused for 45 days should be removed',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for result in result_list:
            if datetime.now().date() - result['PasswordLastUsed'].date() > 45:
                self.iam_list.append(self.create_iam_item(
                    'IAM.22',
                    'IAM user credentials unused for 45 days should be removed',
                    'failed',
                    'MEDIUM',
                    'available',
                    result['Arn']
                ))
            else:
                self.iam_list.append(self.create_iam_item(
                    'IAM.22',
                    'IAM user credentials unused for 45 days should be removed',
                    'passed',
                    'MEDIUM',
                    'available',
                    result['Arn']
                ))
        
    @DecoratorClass.my_decorator
    def iam_twentythree(self) -> None:
        result_list = self.access_analyzer_analyzer_list()
        if not result_list:
            self.iam_list.append(self.create_iam_item(
                'IAM.23',
                'IAM Access Analyzer analyzers should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for result in result_list:
            compliant_status = self.access_analyzer_complaint(result['arn'])
            self.iam_list.append(self.create_iam_item(
                'IAM.23',
                'IAM Access Analyzer analyzers should be tagged',
                compliant_status,
                'LOW',
                'available',
                result['arn']
            ))
        
    @DecoratorClass.my_decorator
    def iam_twentyfour(self) -> None:
        result_list = self.iam_role_list()
        if not result_list:
            self.iam_list.append(self.create_iam_item(
                'IAM.24',
                'IAM roles should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for result in result_list:
            compliant_status = self.iam_tag_compliant(result['Arn'])
            self.iam_list.append(self.create_iam_item(
                'IAM.24',
                'IAM roles should be tagged',
                compliant_status,
                'LOW',
                'available',
                result['Arn']
            ))
        
    @DecoratorClass.my_decorator
    def iam_twentyfive(self) -> None:
        result_list = self.iam_user_list()
        if not result_list:
            self.iam_list.append(self.create_iam_item(
                'IAM.25',
                'IAM users should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for result in result_list:
            compliant_status = self.iam_tag_compliant(result['Arn'])
            self.iam_list.append(self.create_iam_item(
                'IAM.25',
                'IAM users should be tagged',
                compliant_status,
                'LOW',
                'available',
                result['Arn']
            ))
        
    @DecoratorClass.my_decorator
    def iam_twentysix(self) -> None:
        result_list = self.iam_server_certificate()
        if not result_list:
            self.iam_list.append(self.create_iam_item(
                'IAM.26',
                'Expired SSL/TLS certificates managed in IAM should be removed',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for result in result_list:
            if result['Expiration'] < datetime.now():
                self.iam_list.append(self.create_iam_item(
                    'IAM.26',
                    'Expired SSL/TLS certificates managed in IAM should be removed',
                    'failed',
                    'MEDIUM',
                    'available',
                    result['ServerCertificateId']
                ))
            else:
                self.iam_list.append(self.create_iam_item(
                    'IAM.26',
                    'Expired SSL/TLS certificates managed in IAM should be removed',
                    'passed',
                    'MEDIUM',
                    'available',
                    result['ServerCertificateId']
                ))
        
    @DecoratorClass.my_decorator
    def iam_twentyseven(self) -> None:
        role_result_list = self.iam_role_list()
        user_result_list = self.iam_user_list()
        group_result_list = self.iam_group_list()
        if not role_result_list and not user_result_list and not group_result_list:
            self.iam_list.append(self.create_iam_item(
                'IAM.27',
                'IAM identities should not have the AWSCloudShellFullAccess policy attached',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for role_result in role_result_list:
            compliant_status = self.iam_role_cloudshell_fullaccess_compliant(role_result['RoleName'])
            self.iam_list.append(self.create_iam_item(
                'IAM.27',
                'IAM identities should not have the AWSCloudShellFullAccess policy attached',
                compliant_status,
                'MEDIUM',
                'available',
                role_result['Arn']
            ))
        for user_result in user_result_list:
            compliant_status = self.iam_user_cloudshell_fullaccess_compliant(user_result['UserName'])
            self.iam_list.append(self.create_iam_item(
                'IAM.27',
                'IAM identities should not have the AWSCloudShellFullAccess policy attached',
                compliant_status,
                'MEDIUM',
                'available',
                user_result['Arn']
            ))
        for group_result in group_result_list:
            compliant_status = self.iam_group_cloudshell_fullaccess_compliant(group_result['GroupName'])
            self.iam_list.append(self.create_iam_item(
                'IAM.27',
                'IAM identities should not have the AWSCloudShellFullAccess policy attached',
                compliant_status,
                'MEDIUM',
                'available',
                group_result['Arn']
            ))
        
    @DecoratorClass.my_decorator
    def iam_twentyeight(self) -> None:
        result_list = self.access_analyzer_analyzer_list()
        if not result_list or all([_['Type'] != 'EXTERNAL' for _ in result_list]):
            self.iam_list.append(self.create_iam_item(
                'IAM.28',
                'IAM Access Analyzer external access analyzer should be enabled',
                'failed',
                'HIGH',
                'not_available',
                self.session_account
            ))
        else:
            self.iam_list.append(self.create_iam_item(
                'IAM.28',
                'IAM Access Analyzer external access analyzer should be enabled',
                'passed',
                'HIGH',
                'not_available',
                self.session_account
            ))

class CrossAccountIAMAutoRemediation:
    def __init__(self) -> None:
        self.iam_client = UseCrossAccount().client('iam')
        
    def create_iam_role(self, role_name: str, assume_role_policy_document: str) -> None:
        try:
            self.iam_client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=assume_role_policy_document
            )
            print(f"IAM role created: {role_name}")
        except ClientError as e:
            print(f"Error: {e}")

    def create_iam_policy(self, policy_name: str, policy_document: str) -> None:
        try:
            self.iam_client.create_policy(
                PolicyName=policy_name,
                PolicyDocument=policy_document
            )
            print(f"IAM policy created: {policy_name}")
        except ClientError as e:
            print(f"Error: {e}")

    def attach_policy_to_role(self, role_name: str, policy_arn: str) -> None:
        try:
            self.iam_client.attach_role_policy(
                RoleName=role_name,
                PolicyArn=policy_arn
            )
            print(f"IAM policy: {policy_arn} attached to IAM role: {role_name}")
        except ClientError as e:
            print(f"Error: {e}")