'''
Class name GlobalAcceleratorComplianceChecker
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

class GlobalAcceleratorComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.globalaccelerator_client = boto3.client('globalaccelerator')
        self.globalaccelerator_list = compliance_check_list

    def create_globalaccelerator_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("GlobalAccelerator", control_id, compliance, severity, auto_remediation):
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
        
    def globalaccelerator_accelerator_list(self) -> list[dict]:
        accelerator_list: list[dict] = []
        try:
            response = self.globalaccelerator_client.list_accelerators()
            accelerator_list.extend(_ for _ in response['Accelerators'])
            while 'NextToken' in response:
                response = self.globalaccelerator_client.list_accelerators(NextToken=response['NextToken'])
                accelerator_list.extend(_ for _ in response['Accelerators'])
            return accelerator_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def globalaccelerator_tag_compliant(self, globalaccelerator_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.globalaccelerator_client.list_tags_for_resource(ResourceArn=globalaccelerator_arn)
            tag_key_list = [tag['Key'] for tag in response['Tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
    
    @DecoratorClass.my_decorator
    def globalaccelerator_one(self) -> None:
        result_list = self.globalaccelerator_accelerator_list()
        if not result_list:
            self.globalaccelerator_list.append(self.create_globalaccelerator_item(
                'GlobalAccelerator.1',
                'Global Accelerator accelerators should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.globalaccelerator_tag_compliant(response_detail['AcceleratorArn'])
            self.globalaccelerator_list.append(self.create_globalaccelerator_item(
                'GlobalAccelerator.1',
                'Global Accelerator accelerators should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['AcceleratorArn']
            ))

class CrossAccountGlobalAcceleratorComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.globalaccelerator_client = UseCrossAccount().client('globalaccelerator')
        self.globalaccelerator_list = compliance_check_list

    def create_globalaccelerator_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("GlobalAccelerator", control_id, compliance, severity, auto_remediation):
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
        
    def globalaccelerator_accelerator_list(self) -> list[dict]:
        accelerator_list: list[dict] = []
        try:
            response = self.globalaccelerator_client.list_accelerators()
            accelerator_list.extend(_ for _ in response['Accelerators'])
            while 'NextToken' in response:
                response = self.globalaccelerator_client.list_accelerators(NextToken=response['NextToken'])
                accelerator_list.extend(_ for _ in response['Accelerators'])
            return accelerator_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def globalaccelerator_tag_compliant(self, globalaccelerator_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.globalaccelerator_client.list_tags_for_resource(ResourceArn=globalaccelerator_arn)
            tag_key_list = [tag['Key'] for tag in response['Tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
    
    @DecoratorClass.my_decorator
    def globalaccelerator_one(self) -> None:
        result_list = self.globalaccelerator_accelerator_list()
        if not result_list:
            self.globalaccelerator_list.append(self.create_globalaccelerator_item(
                'GlobalAccelerator.1',
                'Global Accelerator accelerators should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.globalaccelerator_tag_compliant(response_detail['AcceleratorArn'])
            self.globalaccelerator_list.append(self.create_globalaccelerator_item(
                'GlobalAccelerator.1',
                'Global Accelerator accelerators should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['AcceleratorArn']
            ))