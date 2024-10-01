'''
Class name AppSyncComplianceChecker
Create functions to check compliants and return as 
'control_id': security contorl id,
'control_title': security control title,
'compliance': passed, failed or not_found,
'severity': CRITICAL, HIGH, MEDIUM or LOW,
'auto_remediation': available or not_available,
'resource_id': account id, resource arn or not_found

Class name AppSyncAutoRemediation
Autoremediate AppSynce two by update AppSync to enable logging
Unable to autoremediate AppSync four as it requires manual tagging
Autoremediate AppSync five by changing authentication type from API key to AWS IAM
'''

import json, boto3 # type: ignore
from botocore.exceptions import ClientError # type: ignore
from utils.decorator_class import DecoratorClass # type: ignore
from utils.validate import ParameterValidation # type: ignore
from utils.cross_account import UseCrossAccount # type: ignore
from utils.global_data import compliance_check_list # type: ignore

class AppSyncComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.appsync_client = boto3.client('appsync')
        self.appsync_list = compliance_check_list

    def create_appsync_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("AppSync", control_id, compliance, severity, auto_remediation):
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
    
    def graphql(self) -> list[dict]:
        appsync_list: list[dict] = []
        try:
            response = self.appsync_client.list_graphql_apis()
            for response_detail in response['graphqlApis']:
                api_response = self.appsync_client.get_graphql_api(apiId=response_detail['apiId'])
                appsync_list.append(api_response['graphqlApi'])
            while 'nextToken' in response:
                response = self.appsync_client.list_graphql_apis(nextToken=response['nextToken'])
                for response_detail in response['graphqlApis']:
                    api_response = self.appsync_client.get_graphql_api(apiId=response_detail['apiId'])
                    appsync_list.append(api_response['graphqlApi'])
            return appsync_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def graphql_tag(self, graphql_arn:str) -> str:
        try:
            compliant_status = "passed"
            response = self.appsync_client.get_graphql_api(apiId=graphql_arn)
            tag_key_list = [tag['key'] for tag in response['tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""

    @DecoratorClass.my_decorator
    def appsync_two(self) -> None:
        result_list = self.graphql()
        if not result_list:
            self.appsync_list.append(self.create_appsync_item(
                'AppSync.2',
                'AWS AppSync should have field-level logging enabled',
                'not_found',
                'MEDIUM',
                'available',
                'not_found'
            ))
        for api_response in result_list:
            if api_response.get('logConfig', {}).get('fieldLogLevel', "NONE") == "NONE":
                self.appsync_list.append(self.create_appsync_item(
                    'AppSync.2',
                    'AWS AppSync should have field-level logging enabled',
                    'failed',
                    'MEDIUM',
                    'available',
                    api_response['arn']
                ))
            else:
                self.appsync_list.append(self.create_appsync_item(
                    'AppSync.2',
                    'AWS AppSync should have field-level logging enabled',
                    'passed',
                    'MEDIUM',
                    'available',
                    api_response['arn']
                ))

    @DecoratorClass.my_decorator
    def appsync_four(self) -> None:
        result_list = self.graphql()
        if not result_list:
            self.appsync_list.append(self.create_appsync_item(
                'AppSync.4',
                'AWS AppSync GraphQL APIs should be tagged',
                'not_found',
                'LOW',
                'available',
                'not_found'
            ))
        for api_response in result_list:
            compliant_status = self.graphql_tag(api_response['arn'])
            self.appsync_list.append(self.create_appsync_item(
                'AppSync.4',
                'AWS AppSync GraphQL APIs should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                api_response['arn']
            ))

    @DecoratorClass.my_decorator
    def appsync_five(self) -> None:
        result_list = self.graphql()
        if not result_list:
            self.appsync_list.append(self.create_appsync_item(
                'AppSync.5',
                'AWS AppSync GraphQL APIs should not be authenticated with API keys',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for api_response in result_list:
            if 'authenticationType' not in api_response or api_response['authenticationType'] == "API_KEY":
                self.appsync_list.append(self.create_appsync_item(
                    'AppSync.5',
                    'AWS AppSync GraphQL APIs should not be authenticated with API keys',
                    'failed',
                    'HIGH',
                    'not_available',
                    api_response['arn']
                ))
            else:
                self.appsync_list.append(self.create_appsync_item(
                    'AppSync.5',
                    'AWS AppSync GraphQL APIs should not be authenticated with API keys',
                    'passed',
                    'HIGH',
                    'not_available',
                    api_response['arn']
                ))

class AppSyncAutoRemediation:
    def __init__(self) -> None:
        self.sts_client = boto3.client('sts')
        self.iam_client = boto3.client('iam')
        self.appsync_client = boto3.client('appsync')
        self.session_account = self.sts_client.get_caller_identity().get('Account')
        self.policy_name = 'app_sync_cloudwatch_log_role'
        self.role_name = 'AWSAppSyncPushToCloudWatchLogsRole'
        self.appsync_role = {
            "Version": "2012-10-17",
            "Statement": [
                {
                "Effect": "Allow",
                "Principal": {
                    "Service": "appsync.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
                }
            ]
        }

        self.role_arn = self.get_role_arn()
        self.policy_arn = f'arn:aws:iam::aws:policy/service-role/{self.policy_name}'
        self.remediation_appsync_two()
        self.remediation_appsync_five()

    def get_role_arn(self) -> str:
        try:
            role_response = self.iam_client.get_role(RoleName=self.role_name)
            return role_response['Role']['Arn']
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                role_response = self.iam_client.create_role(RoleName=self.role_name, \
                                                                 AssumeRolePolicyDocument=json.dumps(self.appsync_role))
                attach_response = self.iam_client.attach_role_policy(RoleName=self.role_name, \
                                                    PolicyArn=self.policy_arn)
                if attach_response['ResponseMetadata']['HTTPStatusCode'] != 200:
                    print(f"Error attaching {self.policy_arn} to {role_response['Role']['Arn']}")
                return role_response['Role']['Arn']
            print(f"Error: {e}")
            return ""

    def remediation_appsync_two(self) -> None:
        try:
            retry_attempt = 0
            response = self.appsync_client.list_graphql_apis()
            for response_detail in response['graphqlApis']:
                api_response = self.appsync_client.get_graphql_api(apiId=response_detail['apiId'])
                while api_response['graphqlApi'].get('logConfig', {}).get('fieldLogLevel', "NONE") == "NONE":
                    # AppSync log config not updated, retry for 3 times
                    self.appsync_client.update_graphql_api(apiId=api_response['graphqlApi']['apiId'], \
                                                            name=api_response['graphqlApi']['name'], \
                                                            authenticationType=api_response['graphqlApi']['authenticationType'], \
                                                            logConfig={
                                                                'fieldLogLevel': 'ALL',
                                                                'cloudWatchLogsRoleArn': self.role_arn,
                                                                'excludeVerboseContent': False
                                                            })
                    retry_attempt += 1
                    if retry_attempt == 3:
                        break
                    if api_response['graphqlApi'].get('logConfig', {}).get('fieldLogLevel', "NONE") == "ALL":
                        print(f"Auto remediated for AppSync.2: {api_response['graphqlApi']['arn']}")
            while 'nextToken' in response:
                response = self.appsync_client.list_graphql_apis(nextToken=response['nextToken'])
                for response_detail in response['graphqlApis']:
                    api_response = self.appsync_client.get_graphql_api(apiId=response_detail['apiId'])
                    while api_response['graphqlApi'].get('logConfig', {}).get('fieldLogLevel', "NONE") == "NONE":
                        # AppSync log config not updated, retry for 3 times
                        self.appsync_client.update_graphql_api(apiId=api_response['graphqlApi']['apiId'], \
                                                                name=api_response['graphqlApi']['name'], \
                                                                authenticationType=api_response['graphqlApi']['authenticationType'], \
                                                                logConfig={
                                                                    'fieldLogLevel': 'ALL',
                                                                    'cloudWatchLogsRoleArn': self.role_arn,
                                                                    'excludeVerboseContent': False
                                                                })
                        retry_attempt += 1
                        if retry_attempt == 3:
                            break
                        if api_response['graphqlApi'].get('logConfig', {}).get('fieldLogLevel', "NONE") == "ALL":
                            print(f"Auto remediated for AppSync.2: {api_response['graphqlApi']['arn']}")
        except ClientError as e:
            print(f"Error: {e}")

    def remediation_appsync_five(self) -> None:
        try:
            response = self.appsync_client.list_graphql_apis()
            for response_detail in response['graphqlApis']:
                api_response = self.appsync_client.get_graphql_api(apiId=response_detail['apiId'])
                if 'authenticationType' not in api_response['graphqlApi'] \
                or api_response['graphqlApi']['authenticationType'] == "API_KEY":
                    self.appsync_client.update_graphql_api(apiId=api_response['graphqlApi']['apiId'], \
                                                            name=api_response['graphqlApi']['name'], \
                                                            authenticationType="AWS_IAM")
                    print(f"Auto remediated for AppSync.5: {api_response['graphqlApi']['arn']}")
            while 'nextToken' in response:
                response = self.appsync_client.list_graphql_apis(nextToken=response['nextToken'])
                for response_detail in response['graphqlApis']:
                    api_response = self.appsync_client.get_graphql_api(apiId=response_detail['apiId'])
                    if 'authenticationType' not in api_response['graphqlApi'] \
                    or api_response['graphqlApi']['authenticationType'] == "API_KEY":
                        self.appsync_client.update_graphql_api(apiId=api_response['graphqlApi']['apiId'], \
                                                                name=api_response['graphqlApi']['name'], \
                                                                authenticationType="AWS_IAM")
                        print(f"Auto remediated for AppSync.5: {api_response['graphqlApi']['arn']}")
        except ClientError as e:
            print(f"Error: {e}")

class CrossAccountAppSyncComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.appsync_client = UseCrossAccount().client('appsync')
        self.appsync_list = compliance_check_list

    def create_appsync_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("AppSync", control_id, compliance, severity, auto_remediation):
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
    
    def graphql(self) -> list[dict]:
        appsync_list: list[dict] = []
        try:
            response = self.appsync_client.list_graphql_apis()
            for response_detail in response['graphqlApis']:
                api_response = self.appsync_client.get_graphql_api(apiId=response_detail['apiId'])
                appsync_list.append(api_response['graphqlApi'])
            while 'nextToken' in response:
                response = self.appsync_client.list_graphql_apis(nextToken=response['nextToken'])
                for response_detail in response['graphqlApis']:
                    api_response = self.appsync_client.get_graphql_api(apiId=response_detail['apiId'])
                    appsync_list.append(api_response['graphqlApi'])
            return appsync_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def graphql_tag(self, graphql_arn:str) -> str:
        try:
            compliant_status = "passed"
            response = self.appsync_client.get_graphql_api(apiId=graphql_arn)
            tag_key_list = [tag['key'] for tag in response['tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""

    @DecoratorClass.my_decorator
    def appsync_two(self) -> None:
        result_list = self.graphql()
        if not result_list:
            self.appsync_list.append(self.create_appsync_item(
                'AppSync.2',
                'AWS AppSync should have field-level logging enabled',
                'not_found',
                'MEDIUM',
                'available',
                'not_found'
            ))
        for api_response in result_list:
            if api_response.get('logConfig', {}).get('fieldLogLevel', "NONE") == "NONE":
                self.appsync_list.append(self.create_appsync_item(
                    'AppSync.2',
                    'AWS AppSync should have field-level logging enabled',
                    'failed',
                    'MEDIUM',
                    'available',
                    api_response['arn']
                ))
            else:
                self.appsync_list.append(self.create_appsync_item(
                    'AppSync.2',
                    'AWS AppSync should have field-level logging enabled',
                    'passed',
                    'MEDIUM',
                    'available',
                    api_response['arn']
                ))

    @DecoratorClass.my_decorator
    def appsync_four(self) -> None:
        result_list = self.graphql()
        if not result_list:
            self.appsync_list.append(self.create_appsync_item(
                'AppSync.4',
                'AWS AppSync GraphQL APIs should be tagged',
                'not_found',
                'LOW',
                'available',
                'not_found'
            ))
        for api_response in result_list:
            compliant_status = self.graphql_tag(api_response['arn'])
            self.appsync_list.append(self.create_appsync_item(
                'AppSync.4',
                'AWS AppSync GraphQL APIs should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                api_response['arn']
            ))

    @DecoratorClass.my_decorator
    def appsync_five(self) -> None:
        result_list = self.graphql()
        if not result_list:
            self.appsync_list.append(self.create_appsync_item(
                'AppSync.5',
                'AWS AppSync GraphQL APIs should not be authenticated with API keys',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for api_response in result_list:
            if 'authenticationType' not in api_response or api_response['authenticationType'] == "API_KEY":
                self.appsync_list.append(self.create_appsync_item(
                    'AppSync.5',
                    'AWS AppSync GraphQL APIs should not be authenticated with API keys',
                    'failed',
                    'HIGH',
                    'not_available',
                    api_response['arn']
                ))
            else:
                self.appsync_list.append(self.create_appsync_item(
                    'AppSync.5',
                    'AWS AppSync GraphQL APIs should not be authenticated with API keys',
                    'passed',
                    'HIGH',
                    'not_available',
                    api_response['arn']
                ))

class CrossAccountAppSyncAutoRemediation:
    def __init__(self) -> None:
        self.sts_client = UseCrossAccount().client('sts')
        self.iam_client = UseCrossAccount().client('iam')
        self.appsync_client = UseCrossAccount().client('appsync')
        self.session_account = self.sts_client.get_caller_identity().get('Account')
        self.policy_name = 'app_sync_cloudwatch_log_role'
        self.role_name = 'AWSAppSyncPushToCloudWatchLogsRole'
        self.appsync_role = {
            "Version": "2012-10-17",
            "Statement": [
                {
                "Effect": "Allow",
                "Principal": {
                    "Service": "appsync.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
                }
            ]
        }

        self.role_arn = self.get_role_arn()
        self.policy_arn = f'arn:aws:iam::aws:policy/service-role/{self.policy_name}'
        self.remediation_appsync_two()
        self.remediation_appsync_five()

    def get_role_arn(self) -> str:
        try:
            role_response = self.iam_client.get_role(RoleName=self.role_name)
            return role_response['Role']['Arn']
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                role_response = self.iam_client.create_role(RoleName=self.role_name, \
                                                                 AssumeRolePolicyDocument=json.dumps(self.appsync_role))
                attach_response = self.iam_client.attach_role_policy(RoleName=self.role_name, \
                                                    PolicyArn=self.policy_arn)
                if attach_response['ResponseMetadata']['HTTPStatusCode'] != 200:
                    print(f"Error attaching {self.policy_arn} to {role_response['Role']['Arn']}")
                return role_response['Role']['Arn']
            print(f"Error: {e}")
            return ""

    def remediation_appsync_two(self) -> None:
        try:
            retry_attempt = 0
            response = self.appsync_client.list_graphql_apis()
            for response_detail in response['graphqlApis']:
                api_response = self.appsync_client.get_graphql_api(apiId=response_detail['apiId'])
                while api_response['graphqlApi'].get('logConfig', {}).get('fieldLogLevel', "NONE") == "NONE":
                    # AppSync log config not updated, retry for 3 times
                    self.appsync_client.update_graphql_api(apiId=api_response['graphqlApi']['apiId'], \
                                                            name=api_response['graphqlApi']['name'], \
                                                            authenticationType=api_response['graphqlApi']['authenticationType'], \
                                                            logConfig={
                                                                'fieldLogLevel': 'ALL',
                                                                'cloudWatchLogsRoleArn': self.role_arn,
                                                                'excludeVerboseContent': False
                                                            })
                    retry_attempt += 1
                    if retry_attempt == 3:
                        break
                    if api_response['graphqlApi'].get('logConfig', {}).get('fieldLogLevel', "NONE") == "ALL":
                        print(f"Auto remediated for AppSync.2: {api_response['graphqlApi']['arn']}")
            while 'nextToken' in response:
                response = self.appsync_client.list_graphql_apis(nextToken=response['nextToken'])
                for response_detail in response['graphqlApis']:
                    api_response = self.appsync_client.get_graphql_api(apiId=response_detail['apiId'])
                    while api_response['graphqlApi'].get('logConfig', {}).get('fieldLogLevel', "NONE") == "NONE":
                        # AppSync log config not updated, retry for 3 times
                        self.appsync_client.update_graphql_api(apiId=api_response['graphqlApi']['apiId'], \
                                                                name=api_response['graphqlApi']['name'], \
                                                                authenticationType=api_response['graphqlApi']['authenticationType'], \
                                                                logConfig={
                                                                    'fieldLogLevel': 'ALL',
                                                                    'cloudWatchLogsRoleArn': self.role_arn,
                                                                    'excludeVerboseContent': False
                                                                })
                        retry_attempt += 1
                        if retry_attempt == 3:
                            break
                        if api_response['graphqlApi'].get('logConfig', {}).get('fieldLogLevel', "NONE") == "ALL":
                            print(f"Auto remediated for AppSync.2: {api_response['graphqlApi']['arn']}")
        except ClientError as e:
            print(f"Error: {e}")

    def remediation_appsync_five(self) -> None:
        try:
            response = self.appsync_client.list_graphql_apis()
            for response_detail in response['graphqlApis']:
                api_response = self.appsync_client.get_graphql_api(apiId=response_detail['apiId'])
                if 'authenticationType' not in api_response['graphqlApi'] \
                or api_response['graphqlApi']['authenticationType'] == "API_KEY":
                    self.appsync_client.update_graphql_api(apiId=api_response['graphqlApi']['apiId'], \
                                                            name=api_response['graphqlApi']['name'], \
                                                            authenticationType="AWS_IAM")
                    print(f"Auto remediated for AppSync.5: {api_response['graphqlApi']['arn']}")
            while 'nextToken' in response:
                response = self.appsync_client.list_graphql_apis(nextToken=response['nextToken'])
                for response_detail in response['graphqlApis']:
                    api_response = self.appsync_client.get_graphql_api(apiId=response_detail['apiId'])
                    if 'authenticationType' not in api_response['graphqlApi'] \
                    or api_response['graphqlApi']['authenticationType'] == "API_KEY":
                        self.appsync_client.update_graphql_api(apiId=api_response['graphqlApi']['apiId'], \
                                                                name=api_response['graphqlApi']['name'], \
                                                                authenticationType="AWS_IAM")
                        print(f"Auto remediated for AppSync.5: {api_response['graphqlApi']['arn']}")
        except ClientError as e:
            print(f"Error: {e}")