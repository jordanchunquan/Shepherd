'''
Class name CodeArtifactComplianceChecker
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

class CodeArtifactComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.codeartifact_client = boto3.client('codeartifact')
        self.codeartifact_list = compliance_check_list

    def create_codeartifact_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("CodeArtifact", control_id, compliance, severity, auto_remediation):
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
    
    def codeartifact_repository_list(self) -> list[dict]:
        repository_list: list[dict] = []
        try:
            response = self.codeartifact_client.list_repositories()
            repository_list.extend(_ for _ in response['repositories'])
            while 'nextToken' in response:
                response = self.codeartifact_client.list_repositories(nextToken=response['nextToken'])
                repository_list.extend(_ for _ in response['repositories'])
            return repository_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def codeartifact_repository_tag_list(self, repository_arn:str) -> str:
        try:
            compliant_status = "passed"
            response = self.codeartifact_client.list_tags_for_resource(
                resourceArn=repository_arn
            )
            tag_key_list = [tag['key'] for tag in response['tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
    
    @DecoratorClass.my_decorator
    def codeartifact_one(self) -> None:
        result_list = self.codeartifact_repository_list()
        if not result_list:
            self.codeartifact_list.append(self.create_codeartifact_item(
                'CodeArtifact.1',
                'CodeArtifact repositories should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.codeartifact_repository_tag_list(response_detail['arn'])
            self.codeartifact_list.append(self.create_codeartifact_item(
                'CodeArtifact.1',
                'CodeArtifact repositories should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['arn']
            ))

class CrossAccountCodeArtifactComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.codeartifact_client = UseCrossAccount().client('codeartifact')
        self.codeartifact_list = compliance_check_list

    def create_codeartifact_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("Service Name", control_id, compliance, severity, auto_remediation):
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
    
    def codeartifact_repository_list(self) -> list[dict]:
        repository_list: list[dict] = []
        try:
            response = self.codeartifact_client.list_repositories()
            repository_list.extend(_ for _ in response['repositories'])
            while 'nextToken' in response:
                response = self.codeartifact_client.list_repositories(nextToken=response['nextToken'])
                repository_list.extend(_ for _ in response['repositories'])
            return repository_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def codeartifact_repository_tag_list(self, repository_arn:str) -> str:
        try:
            compliant_status = "passed"
            response = self.codeartifact_client.list_tags_for_resource(
                resourceArn=repository_arn
            )
            tag_key_list = [tag['key'] for tag in response['tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
    
    @DecoratorClass.my_decorator
    def codeartifact_one(self) -> None:
        result_list = self.codeartifact_repository_list()
        if not result_list:
            self.codeartifact_list.append(self.create_codeartifact_item(
                'CodeArtifact.1',
                'CodeArtifact repositories should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.codeartifact_repository_tag_list(response_detail['arn'])
            self.codeartifact_list.append(self.create_codeartifact_item(
                'CodeArtifact.1',
                'CodeArtifact repositories should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['arn']
            ))