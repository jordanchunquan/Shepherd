'''
Class name LambdaComplianceChecker
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

class LambdaComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.ec2_client = boto3.client('ec2')
        self.lambda_client = boto3.client('lambda')
        self.lambda_list = compliance_check_list
        self.supported_run_time = ['dotnet8', 'dotnet6', 'java21', 'java17', 'java11', 'java8.al2', 'nodejs20.x', 'nodejs18.x', 'python3.12', 'python3.11', 'python3.10', 'python3.9', 'python3.8', 'ruby3.3', 'ruby3.2']

    def create_lambda_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("Lambda", control_id, compliance, severity, auto_remediation):
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
    
    def lambda_function_list(self) -> list[dict]:
        function_list: list[dict] = []
        try:
            response = self.lambda_client.list_functions()
            function_list.extend(_ for _ in response['Functions'])
            while 'NextMarker' in response:
                response = self.lambda_client.list_functions(Marker=response['NextMarker'])
                function_list.extend(_ for _ in response['Functions'])
            return function_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def lambda_policy(self, function_name: str) -> dict:
        try:
            response = self.lambda_client.get_policy(FunctionName=function_name)
            return json.loads(response['Policy'])
        except ClientError as e:
            print(f"Error: {e}")
            return {}
        
    def lambda_policy_compliant(self, policy_statment: dict) -> bool:
        if policy_statment['Effect'] == "Allow" and any([policy_statment['Principal'] == "*", policy_statment['Principal'] == "{ 'AWS': '*'}"]):
            return False
        elif policy_statment['Principal'] == "{'Service': 's3.amazonaws.com'}":
            if 'AWS:SourceAccount' not in policy_statment['Condition'].get('StringEquals', {}).keys():
                return False
        return True
    
    def multi_az_vpc_list(self) -> list[str]:
        vpc_list: list[str] = []
        try:
            vpc_response = self.ec2_client.describe_vpcs()
            for vpc_detail_response in vpc_response['Vpcs']:
                subnet_list: list[str] = []
                subnet_response = self.ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_detail_response['VpcId']]}])
                subnet_list.extend(_ for _ in subnet_response['Subnets'])
                while 'NextToken' in subnet_response:
                    subnet_response = self.ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_detail_response['VpcId']]}], NextToken=subnet_response['NextToken'])
                    subnet_list.extend(_ for _ in subnet_response['Subnets'])
                if len(list(_['AvailabilityZone'] for _ in subnet_list)) > 1:
                    vpc_list.append(vpc_detail_response['VpcId'])
            while 'NextToken' in vpc_response:
                vpc_response = self.ec2_client.describe_vpcs(NextToken=vpc_response['NextToken'])
                for vpc_detail_response in vpc_response['Vpcs']:
                    subnet_list: list[str] = [] # type: ignore
                    subnet_response = self.ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_detail_response['VpcId']]}])
                    subnet_list.extend(_ for _ in subnet_response['Subnets'])
                    while 'NextToken' in subnet_response:
                        subnet_response = self.ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_detail_response['VpcId']]}], NextToken=subnet_response['NextToken'])
                        subnet_list.extend(_ for _ in subnet_response['Subnets'])
                    if len(list(_['AvailabilityZone'] for _ in subnet_list)) > 1:
                        vpc_list.append(vpc_detail_response['VpcId'])
            return vpc_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def lambda_tag_compliant(self, function_arn: str) -> str:
        try:
            compliant_status = "passed"
            tag_response = self.lambda_client.list_tags(Resource=function_arn)
            tag_key_list = [_ for _ in tag_response['Tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
    
    @DecoratorClass.my_decorator
    def lambda_one(self) -> None:
        result_list = self.lambda_function_list()
        if not result_list:
            self.lambda_list.append(self.create_lambda_item(
                'Lambda.1',
                'Lambda function policies should prohibit public access',
                'not_found',
                'CRITICAL',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            function_policy = self.lambda_policy(response_detail['FunctionName'])
            if not all([self.lambda_policy_compliant(_) for _ in function_policy.get('Statement', [])]):
                self.lambda_list.append(self.create_lambda_item(
                    'Lambda.1',
                    'Lambda function policies should prohibit public access',
                    'failed',
                    'CRITICAL',
                    'not_available',
                    response_detail['FunctionArn']
                ))
            else:
                self.lambda_list.append(self.create_lambda_item(
                    'Lambda.1',
                    'Lambda function policies should prohibit public access',
                    'passed',
                    'CRITICAL',
                    'not_available',
                    response_detail['FunctionArn']
                ))

    @DecoratorClass.my_decorator
    def lambda_two(self) -> None:
        result_list = self.lambda_function_list()
        if not result_list:
            self.lambda_list.append(self.create_lambda_item(
                'Lambda.2',
                'Lambda functions should use supported runtimes',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['Runtime'] not in self.supported_run_time:
                self.lambda_list.append(self.create_lambda_item(
                    'Lambda.2',
                    'Lambda functions should use supported runtimes',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FunctionArn']
                ))
            else:
                self.lambda_list.append(self.create_lambda_item(
                    'Lambda.2',
                    'Lambda functions should use supported runtimes',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FunctionArn']
                ))

    @DecoratorClass.my_decorator
    def lambda_three(self) -> None:
        result_list = self.lambda_function_list()
        if not result_list:
            self.lambda_list.append(self.create_lambda_item(
                'Lambda.3',
                'Lambda functions should be in a VPC',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if 'VpcConfig' not in response_detail.keys():
                self.lambda_list.append(self.create_lambda_item(
                    'Lambda.3',
                    'Lambda functions should be in a VPC',
                    'failed',
                    'LOW',
                    'not_available',
                    response_detail['FunctionArn']
                ))
            else:
                self.lambda_list.append(self.create_lambda_item(
                    'Lambda.3',
                    'Lambda functions should be in a VPC',
                    'passed',
                    'LOW',
                    'not_available',
                    response_detail['FunctionArn']
                ))

    @DecoratorClass.my_decorator
    def lambda_five(self) -> None:
        result_list = self.lambda_function_list()
        multi_az_vpc_list = self.multi_az_vpc_list()
        if not result_list:
            self.lambda_list.append(self.create_lambda_item(
                'Lambda.5',
                'VPC Lambda functions should operate in multiple Availability Zones',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('VpcConfig', {}).get('VpcId') not in multi_az_vpc_list:
                self.lambda_list.append(self.create_lambda_item(
                    'Lambda.5',
                    'VPC Lambda functions should operate in multiple Availability Zones',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FunctionArn']
                ))
            else:
                self.lambda_list.append(self.create_lambda_item(
                    'Lambda.5',
                    'VPC Lambda functions should operate in multiple Availability Zones',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FunctionArn']
                ))

    @DecoratorClass.my_decorator
    def lambda_six(self) -> None:
        result_list = self.lambda_function_list()
        if not result_list:
            self.lambda_list.append(self.create_lambda_item(
                'Lambda.6',
                'Lambda functions should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.lambda_tag_compliant(response_detail['FunctionArn'])
            self.lambda_list.append(self.create_lambda_item(
                'Lambda.6',
                'Lambda functions should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['FunctionArn']
            ))

class CrossAccountLambdaComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.ec2_client = UseCrossAccount().client('ec2')
        self.lambda_client = UseCrossAccount().client('lambda')
        self.lambda_list = compliance_check_list
        self.supported_run_time = ['dotnet8', 'dotnet6', 'java21', 'java17', 'java11', 'java8.al2', 'nodejs20.x', 'nodejs18.x', 'python3.12', 'python3.11', 'python3.10', 'python3.9', 'python3.8', 'ruby3.3', 'ruby3.2']

    def create_lambda_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("Lambda", control_id, compliance, severity, auto_remediation):
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
    
    def lambda_function_list(self) -> list[dict]:
        function_list: list[dict] = []
        try:
            response = self.lambda_client.list_functions()
            function_list.extend(_ for _ in response['Functions'])
            while 'NextMarker' in response:
                response = self.lambda_client.list_functions(Marker=response['NextMarker'])
                function_list.extend(_ for _ in response['Functions'])
            return function_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def lambda_policy(self, function_name: str) -> dict:
        try:
            response = self.lambda_client.get_policy(FunctionName=function_name)
            return json.loads(response['Policy'])
        except ClientError as e:
            print(f"Error: {e}")
            return {}
        
    def lambda_policy_compliant(self, policy_statment: dict) -> bool:
        if policy_statment['Effect'] == "Allow" and any([policy_statment['Principal'] == "*", policy_statment['Principal'] == "{ 'AWS': '*'}"]):
            return False
        elif policy_statment['Principal'] == "{'Service': 's3.amazonaws.com'}":
            if 'AWS:SourceAccount' not in policy_statment['Condition'].get('StringEquals', {}).keys():
                return False
        return True
    
    def multi_az_vpc_list(self) -> list[str]:
        vpc_list: list[str] = []
        try:
            vpc_response = self.ec2_client.describe_vpcs()
            for vpc_detail_response in vpc_response['Vpcs']:
                subnet_list: list[str] = []
                subnet_response = self.ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_detail_response['VpcId']]}])
                subnet_list.extend(_ for _ in subnet_response['Subnets'])
                while 'NextToken' in subnet_response:
                    subnet_response = self.ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_detail_response['VpcId']]}], NextToken=subnet_response['NextToken'])
                    subnet_list.extend(_ for _ in subnet_response['Subnets'])
                if len(list(_['AvailabilityZone'] for _ in subnet_list)) > 1:
                    vpc_list.append(vpc_detail_response['VpcId'])
            while 'NextToken' in vpc_response:
                vpc_response = self.ec2_client.describe_vpcs(NextToken=vpc_response['NextToken'])
                for vpc_detail_response in vpc_response['Vpcs']:
                    subnet_list: list[str] = [] # type: ignore
                    subnet_response = self.ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_detail_response['VpcId']]}])
                    subnet_list.extend(_ for _ in subnet_response['Subnets'])
                    while 'NextToken' in subnet_response:
                        subnet_response = self.ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_detail_response['VpcId']]}], NextToken=subnet_response['NextToken'])
                        subnet_list.extend(_ for _ in subnet_response['Subnets'])
                    if len(list(_['AvailabilityZone'] for _ in subnet_list)) > 1:
                        vpc_list.append(vpc_detail_response['VpcId'])
            return vpc_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def lambda_tag_compliant(self, function_arn: str) -> str:
        try:
            compliant_status = "passed"
            tag_response = self.lambda_client.list_tags(Resource=function_arn)
            tag_key_list = [_ for _ in tag_response['Tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
    
    @DecoratorClass.my_decorator
    def lambda_one(self) -> None:
        result_list = self.lambda_function_list()
        if not result_list:
            self.lambda_list.append(self.create_lambda_item(
                'Lambda.1',
                'Lambda function policies should prohibit public access',
                'not_found',
                'CRITICAL',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            function_policy = self.lambda_policy(response_detail['FunctionName'])
            if not all([self.lambda_policy_compliant(_) for _ in function_policy.get('Statement', [])]):
                self.lambda_list.append(self.create_lambda_item(
                    'Lambda.1',
                    'Lambda function policies should prohibit public access',
                    'failed',
                    'CRITICAL',
                    'not_available',
                    response_detail['FunctionArn']
                ))
            else:
                self.lambda_list.append(self.create_lambda_item(
                    'Lambda.1',
                    'Lambda function policies should prohibit public access',
                    'passed',
                    'CRITICAL',
                    'not_available',
                    response_detail['FunctionArn']
                ))

    @DecoratorClass.my_decorator
    def lambda_two(self) -> None:
        result_list = self.lambda_function_list()
        if not result_list:
            self.lambda_list.append(self.create_lambda_item(
                'Lambda.2',
                'Lambda functions should use supported runtimes',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['Runtime'] not in self.supported_run_time:
                self.lambda_list.append(self.create_lambda_item(
                    'Lambda.2',
                    'Lambda functions should use supported runtimes',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FunctionArn']
                ))
            else:
                self.lambda_list.append(self.create_lambda_item(
                    'Lambda.2',
                    'Lambda functions should use supported runtimes',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FunctionArn']
                ))

    @DecoratorClass.my_decorator
    def lambda_three(self) -> None:
        result_list = self.lambda_function_list()
        if not result_list:
            self.lambda_list.append(self.create_lambda_item(
                'Lambda.3',
                'Lambda functions should be in a VPC',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if 'VpcConfig' not in response_detail.keys():
                self.lambda_list.append(self.create_lambda_item(
                    'Lambda.3',
                    'Lambda functions should be in a VPC',
                    'failed',
                    'LOW',
                    'not_available',
                    response_detail['FunctionArn']
                ))
            else:
                self.lambda_list.append(self.create_lambda_item(
                    'Lambda.3',
                    'Lambda functions should be in a VPC',
                    'passed',
                    'LOW',
                    'not_available',
                    response_detail['FunctionArn']
                ))

    @DecoratorClass.my_decorator
    def lambda_five(self) -> None:
        result_list = self.lambda_function_list()
        multi_az_vpc_list = self.multi_az_vpc_list()
        if not result_list:
            self.lambda_list.append(self.create_lambda_item(
                'Lambda.5',
                'VPC Lambda functions should operate in multiple Availability Zones',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('VpcConfig', {}).get('VpcId') not in multi_az_vpc_list:
                self.lambda_list.append(self.create_lambda_item(
                    'Lambda.5',
                    'VPC Lambda functions should operate in multiple Availability Zones',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FunctionArn']
                ))
            else:
                self.lambda_list.append(self.create_lambda_item(
                    'Lambda.5',
                    'VPC Lambda functions should operate in multiple Availability Zones',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FunctionArn']
                ))

    @DecoratorClass.my_decorator
    def lambda_six(self) -> None:
        result_list = self.lambda_function_list()
        if not result_list:
            self.lambda_list.append(self.create_lambda_item(
                'Lambda.6',
                'Lambda functions should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.lambda_tag_compliant(response_detail['FunctionArn'])
            self.lambda_list.append(self.create_lambda_item(
                'Lambda.6',
                'Lambda functions should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['FunctionArn']
            ))