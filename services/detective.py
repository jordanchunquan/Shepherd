'''
Class name DetectiveComplianceChecker
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

class DetectiveComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.detective_client = boto3.client('detective')
        self.detective_list = compliance_check_list

    def create_detective_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("Detective", control_id, compliance, severity, auto_remediation):
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
    
    def detective_graph_list(self) -> list[dict]:
        detective_list: list[dict] = []
        try:
            response = self.detective_client.list_graphs()
            detective_list.extend(_ for _ in response['GraphList'])
            while 'NextToken' in response:
                response = self.detective_client.list_graphs(
                    NextToken=response['NextToken']
                )
                detective_list.extend(_ for _ in response['GraphList'])
            return detective_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def detective_tag_list(self, graph_arn:str) -> str:
        try:
            response = self.detective_client.list_tags_for_resource(ResourceArn=graph_arn)
            tag_key_list = [tag['Key'] for tag in response['Tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                return "failed"
            else:
                return "passed"
        except ClientError as e:
            print(f"Error: {e}")
            return ""
    
    @DecoratorClass.my_decorator
    def detective_one(self) -> None:
        result_list = self.detective_graph_list()
        if not result_list:
            self.detective_list.append(self.create_detective_item(
                'Detective.1',
                'Detective behavior graphs should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.detective_tag_list(response_detail['Arn'])
            self.detective_list.append(self.create_detective_item(
                'Detective.1',
                'Detective behavior graphs should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['Arn']
            ))

class CrossAccountDetectiveComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.detective_client = UseCrossAccount().client('detective')
        self.detective_list = compliance_check_list

    def create_detective_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("Detective", control_id, compliance, severity, auto_remediation):
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
    
    def detective_graph_list(self) -> list[dict]:
        detective_list: list[dict] = []
        try:
            response = self.detective_client.list_graphs()
            detective_list.extend(_ for _ in response['GraphList'])
            while 'NextToken' in response:
                response = self.detective_client.list_graphs(
                    NextToken=response['NextToken']
                )
                detective_list.extend(_ for _ in response['GraphList'])
            return detective_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def detective_tag_list(self, graph_arn:str) -> str:
        try:
            response = self.detective_client.list_tags_for_resource(ResourceArn=graph_arn)
            tag_key_list = [tag['Key'] for tag in response['Tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                return "failed"
            else:
                return "passed"
        except ClientError as e:
            print(f"Error: {e}")
            return ""
    
    @DecoratorClass.my_decorator
    def detective_one(self) -> None:
        result_list = self.detective_graph_list()
        if not result_list:
            self.detective_list.append(self.create_detective_item(
                'Detective.1',
                'Detective behavior graphs should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.detective_tag_list(response_detail['Arn'])
            self.detective_list.append(self.create_detective_item(
                'Detective.1',
                'Detective behavior graphs should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['Arn']
            ))