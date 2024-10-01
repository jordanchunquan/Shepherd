'''
Class name GlueComplianceChecker
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

class GlueComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.glue_client = boto3.client('glue')
        self.session_region = boto3.session.Session().region_name
        self.session_account = boto3.client('sts').get_caller_identity()['Account']
        self.glue_list = compliance_check_list

    def create_glue_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("Glue", control_id, compliance, severity, auto_remediation):
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
    
    def glue_job_list(self) -> list[str]:
        job_list: list[str] = []
        try:
            response = self.glue_client.list_jobs()
            job_list.extend(f"arn:aws:glue:{self.session_region}:{self.session_account}:job/{_}" for _ in response['JobNames'])
            while 'NextToken' in response:
                response = self.glue_client.list_jobs(NextToken=response['NextToken'])
                job_list.extend(f"arn:aws:glue:{self.session_region}:{self.session_account}:job/{_}" for _ in response['JobNames'])
            return job_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def glue_tag_compliance(self, glue_job_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.glue_client.get_tags(ResourceArn=glue_job_arn)
            tag_key_list = [tag['Key'] for tag in response['Tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
    
    @DecoratorClass.my_decorator
    def glue_one(self) -> None:
        result_list = self.glue_job_list()
        if not result_list:
            self.glue_list.append(self.create_glue_item(
                'Glue.1',
                'AWS Glue jobs should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliance_status = self.glue_tag_compliance(response_detail)
            self.glue_list.append(self.create_glue_item(
                'Glue.1',
                'AWS Glue jobs should be tagged',
                compliance_status,
                'LOW',
                'not_available',
                response_detail
            ))

class CrossAccountGlueComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.glue_client = UseCrossAccount().client('glue')
        self.session_region = UseCrossAccount().session_region_name
        self.session_account = UseCrossAccount().client('sts').get_caller_identity()['Account']
        self.glue_list = compliance_check_list

    def create_glue_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("Glue", control_id, compliance, severity, auto_remediation):
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
    
    def glue_job_list(self) -> list[str]:
        job_list: list[str] = []
        try:
            response = self.glue_client.list_jobs()
            job_list.extend(f"arn:aws:glue:{self.session_region}:{self.session_account}:job/{_}" for _ in response['JobNames'])
            while 'NextToken' in response:
                response = self.glue_client.list_jobs(NextToken=response['NextToken'])
                job_list.extend(f"arn:aws:glue:{self.session_region}:{self.session_account}:job/{_}" for _ in response['JobNames'])
            return job_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def glue_tag_compliance(self, glue_job_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.glue_client.get_tags(ResourceArn=glue_job_arn)
            tag_key_list = [tag['Key'] for tag in response['Tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
    
    @DecoratorClass.my_decorator
    def glue_one(self) -> None:
        result_list = self.glue_job_list()
        if not result_list:
            self.glue_list.append(self.create_glue_item(
                'Glue.1',
                'AWS Glue jobs should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliance_status = self.glue_tag_compliance(response_detail)
            self.glue_list.append(self.create_glue_item(
                'Glue.1',
                'AWS Glue jobs should be tagged',
                compliance_status,
                'LOW',
                'not_available',
                response_detail
            ))