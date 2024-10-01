'''
Class name ECRComplianceChecker
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

class ECRComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.ecr_client = boto3.client('ecr')
        self.ecrpublic_client = boto3.client('ecr-public', region_name='us-east-1')
        self.ecr_list = compliance_check_list

    def create_ecr_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("ECR", control_id, compliance, severity, auto_remediation):
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
    
    def repository_list(self) -> list[dict]:
        ecr_list: list[dict] = []
        try:
            response = self.ecr_client.describe_repositories()
            ecr_list.extend(_ for _ in response['repositories'])
            while 'nextToken' in response:
                response = self.ecr_client.describe_repositories(nextToken=response['nextToken'])
                ecr_list.extend(_ for _ in response['repositories'])
            return ecr_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def lifecycle_list(self, repository_name: str) -> str:
        compliant_status = "passed"
        try:
            self.ecr_client.get_lifecycle_policy(repositoryName=repository_name)
            return compliant_status
        except ClientError as e:
            if e.response['Error']['Code'] == "LifecyclePolicyNotFoundException":
                compliant_status = "failed"
                return compliant_status
            else:
                print(f"Error: {e}")
                return ""
            
    def public_repository_list(self) -> list[dict]:
        ecr_list: list[dict] = []
        try:
            response = self.ecrpublic_client.describe_repositories()
            ecr_list.extend(_ for _ in response['repositories'])
            while 'nextToken' in response:
                response = self.ecrpublic_client.describe_repositories(nextToken=response['nextToken'])
                ecr_list.extend(_ for _ in response['repositories'])
            return ecr_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def public_repository_tag_list(self, public_repository_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.ecrpublic_client.list_tags_for_resource(resourceArn=public_repository_arn)
            tag_key_list = [tag['Key'] for tag in response['tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
    
    @DecoratorClass.my_decorator
    def ecr_one(self) -> None:
        result_list = self.repository_list()
        if not result_list:
            self.ecr_list.append(self.create_ecr_item(
                'ECR.1',
                'ECR private repositories should have image scanning configured',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if not response_detail['imageScanningConfiguration']['scanOnPush']:
                self.ecr_list.append(self.create_ecr_item(
                    'ECR.1',
                    'ECR private repositories should have image scanning configured',
                    'failed',
                    'HIGH',
                    'not_available',
                    response_detail['repositoryArn']
                ))
            self.ecr_list.append(self.create_ecr_item(
                'ECR.1',
                'ECR private repositories should have image scanning configured',
                'passed',
                'HIGH',
                'not_available',
                response_detail['repositoryArn']
            ))
    
    @DecoratorClass.my_decorator
    def ecr_two(self) -> None:
        result_list = self.repository_list()
        if not result_list:
            self.ecr_list.append(self.create_ecr_item(
                'ECR.2',
                'ECR private repositories should have tag immutability configured',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['imageTagMutability'] != "IMMUTABLE":
                self.ecr_list.append(self.create_ecr_item(
                    'ECR.2',
                    'ECR private repositories should have tag immutability configured',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['repositoryArn']
                ))
            self.ecr_list.append(self.create_ecr_item(
                'ECR.2',
                'ECR private repositories should have tag immutability configured',
                'passed',
                'MEDIUM',
                'not_available',
                response_detail['repositoryArn']
            ))
    
    @DecoratorClass.my_decorator
    def ecr_three(self) -> None:
        result_list = self.repository_list()
        if not result_list:
            self.ecr_list.append(self.create_ecr_item(
                'ECR.3',
                'ECR repositories should have at least one lifecycle policy configured',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            self.ecr_list.append(self.create_ecr_item(
                'ECR.3',
                'ECR repositories should have at least one lifecycle policy configured',
                self.lifecycle_list(response_detail['repositoryName']),
                'MEDIUM',
                'not_available',
                response_detail['repositoryArn']
            ))
    
    @DecoratorClass.my_decorator
    def ecr_four(self) -> None:
        result_list = self.public_repository_list()
        if not result_list:
            self.ecr_list.append(self.create_ecr_item(
                'ECR.4',
                'ECR public repositories should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.public_repository_tag_list(response_detail['repositoryArn'])
            self.ecr_list.append(self.create_ecr_item(
                'ECR.4',
                'ECR public repositories should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['repositoryArn']
            ))

class CrossAccountECRComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.ecr_client = UseCrossAccount().client('ecr')
        self.ecrpublic_client = UseCrossAccount().client('ecr-public', region_name='us-east-1')
        self.ecr_list = compliance_check_list

    def create_ecr_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("ECR", control_id, compliance, severity, auto_remediation):
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
    
    def repository_list(self) -> list[dict]:
        ecr_list: list[dict] = []
        try:
            response = self.ecr_client.describe_repositories()
            ecr_list.extend(_ for _ in response['repositories'])
            while 'nextToken' in response:
                response = self.ecr_client.describe_repositories(nextToken=response['nextToken'])
                ecr_list.extend(_ for _ in response['repositories'])
            return ecr_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def lifecycle_list(self, repository_name: str) -> str:
        compliant_status = "passed"
        try:
            self.ecr_client.get_lifecycle_policy(repositoryName=repository_name)
            return compliant_status
        except ClientError as e:
            if e.response['Error']['Code'] == "LifecyclePolicyNotFoundException":
                compliant_status = "failed"
                return compliant_status
            else:
                print(f"Error: {e}")
                return ""
            
    def public_repository_list(self) -> list[dict]:
        ecr_list: list[dict] = []
        try:
            response = self.ecrpublic_client.describe_repositories()
            ecr_list.extend(_ for _ in response['repositories'])
            while 'nextToken' in response:
                response = self.ecrpublic_client.describe_repositories(nextToken=response['nextToken'])
                ecr_list.extend(_ for _ in response['repositories'])
            return ecr_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def public_repository_tag_list(self, public_repository_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.ecrpublic_client.list_tags_for_resource(resourceArn=public_repository_arn)
            tag_key_list = [tag['Key'] for tag in response['tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
    
    @DecoratorClass.my_decorator
    def ecr_one(self) -> None:
        result_list = self.repository_list()
        if not result_list:
            self.ecr_list.append(self.create_ecr_item(
                'ECR.one',
                'ECR private repositories should have image scanning configured',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if not response_detail['imageScanningConfiguration']['scanOnPush']:
                self.ecr_list.append(self.create_ecr_item(
                    'ECR.one',
                    'ECR private repositories should have image scanning configured',
                    'failed',
                    'HIGH',
                    'not_available',
                    response_detail['repositoryArn']
                ))
            self.ecr_list.append(self.create_ecr_item(
                'ECR.one',
                'ECR private repositories should have image scanning configured',
                'passed',
                'HIGH',
                'not_available',
                response_detail['repositoryArn']
            ))
    
    @DecoratorClass.my_decorator
    def ecr_two(self) -> None:
        result_list = self.repository_list()
        if not result_list:
            self.ecr_list.append(self.create_ecr_item(
                'ECR.two',
                'ECR private repositories should have tag immutability configured',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['imageTagMutability'] != "IMMUTABLE":
                self.ecr_list.append(self.create_ecr_item(
                    'ECR.two',
                    'ECR private repositories should have tag immutability configured',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['repositoryArn']
                ))
            self.ecr_list.append(self.create_ecr_item(
                'ECR.two',
                'ECR private repositories should have tag immutability configured',
                'passed',
                'MEDIUM',
                'not_available',
                response_detail['repositoryArn']
            ))
    
    @DecoratorClass.my_decorator
    def ecr_three(self) -> None:
        result_list = self.repository_list()
        if not result_list:
            self.ecr_list.append(self.create_ecr_item(
                'ECR.three',
                'ECR repositories should have at least one lifecycle policy configured',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            self.ecr_list.append(self.create_ecr_item(
                'ECR.three',
                'ECR repositories should have at least one lifecycle policy configured',
                self.lifecycle_list(response_detail['repositoryName']),
                'MEDIUM',
                'not_available',
                response_detail['repositoryArn']
            ))
    
    @DecoratorClass.my_decorator
    def ecr_four(self) -> None:
        result_list = self.public_repository_list()
        if not result_list:
            self.ecr_list.append(self.create_ecr_item(
                'ECR.4',
                'ECR public repositories should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.public_repository_tag_list(response_detail['repositoryArn'])
            self.ecr_list.append(self.create_ecr_item(
                'ECR.4',
                'ECR public repositories should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['repositoryArn']
            ))