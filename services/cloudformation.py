'''
Class name CloudFormationComplianceChecker
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

class CloudFormationComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.cloudformation_client = boto3.client('cloudformation')
        self.cloudformation_list = compliance_check_list

    def create_service_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("CloudFormation", control_id, compliance, severity, auto_remediation):
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
    
    def describe_stack_list(self) -> list[dict]:
        stack_list: list[dict] = []
        try:
            response = self.cloudformation_client.describe_stacks()
            stack_list.extend(_ for _ in response['Stacks'])
            while 'NextToken' in response:
                response = self.cloudformation_client.describe_stacks(NextToken=response['NextToken'])
                stack_list.extend(_ for _ in response['Stacks'])
            return stack_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    @DecoratorClass.my_decorator
    def cloudformation_two(self) -> None:
        result_list = self.describe_stack_list()
        if not result_list:
            self.cloudformation_list.append(self.create_service_item(
                'CloudFormation.2',
                'CloudFormation stacks should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag['Key'] for tag in response_detail['Tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.cloudformation_list.append(self.create_service_item(
                'CloudFormation.2',
                'CloudFormation stacks should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['StackId']
            ))

class CrossAccountCloudFormationComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.cloudformation_client = UseCrossAccount().client('cloudformation')
        self.cloudformation_list = compliance_check_list

    def create_service_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("CloudFormation", control_id, compliance, severity, auto_remediation):
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
    
    def describe_stack_list(self) -> list[dict]:
        stack_list: list[dict] = []
        try:
            response = self.cloudformation_client.describe_stacks()
            stack_list.extend(_ for _ in response['Stacks'])
            while 'NextToken' in response:
                response = self.cloudformation_client.describe_stacks(NextToken=response['NextToken'])
                stack_list.extend(_ for _ in response['Stacks'])
            return stack_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    @DecoratorClass.my_decorator
    def cloudformation_two(self) -> None:
        result_list = self.describe_stack_list()
        if not result_list:
            self.cloudformation_list.append(self.create_service_item(
                'CloudFormation.2',
                'CloudFormation stacks should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag['Key'] for tag in response_detail['Tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.cloudformation_list.append(self.create_service_item(
                'CloudFormation.2',
                'CloudFormation stacks should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['StackId']
            ))