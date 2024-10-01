'''
Class name FSxComplianceChecker
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

class FSxComplianceChecker:
    def __init__(self) -> None:
        self.fsx_client = boto3.client('fsx')
        self.fsx_list = compliance_check_list

    def create_fsx_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("FSx", control_id, compliance, severity, auto_remediation):
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
        
    def fsx_file_system_list(self) -> list[dict]:
        file_system_list: list[dict] = []
        try:
            response = boto3.client('fsx').describe_file_systems()
            file_system_list.extend(_ for _ in response['FileSystems'])
            while 'NextToken' in response:
                response = boto3.client('fsx').describe_file_systems(NextToken=response['NextToken'])
                file_system_list.extend(_ for _ in response['FileSystems'])
            return file_system_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    @DecoratorClass.my_decorator
    def fsx_one(self) -> None:
        result_list = self.fsx_file_system_list()
        result_list = [_['OpenZFSConfiguration'] for _ in result_list if _['FileSystemType'] == "OPENZFS"]
        if not result_list:
            self.fsx_list.append(self.create_fsx_item(
                'FSx.1',
                'FSx for OpenZFS file systems should be configured to copy tags to backups and volumes',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if any([response_detail['CopyTagsToBackups'] != True, response_detail['CopyTagsToVolumes'] != True]):
                self.fsx_list.append(self.create_fsx_item(
                    'FSx.1',
                    'FSx for OpenZFS file systems should be configured to copy tags to backups and volumes',
                    'failed',
                    'LOW',
                    'available',
                    response_detail['FileSystemId']
                ))
            else:
                self.fsx_list.append(self.create_fsx_item(
                    'FSx.1',
                    'FSx for OpenZFS file systems should be configured to copy tags to backups and volumes',
                    'passed',
                    'LOW',
                    'available',
                    response_detail['FileSystemId']
                ))
    
    @DecoratorClass.my_decorator
    def fsx_two(self) -> None:
        result_list = self.fsx_file_system_list()
        result_list = [_['LustreConfiguration'] for _ in result_list if _['FileSystemType'] == "LUSTRE"]
        if not result_list:
            self.fsx_list.append(self.create_fsx_item(
                'FSx.2',
                'FSx for Lustre file systems should be configured to copy tags to backups',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['CopyTagsToBackups'] != True:
                self.fsx_list.append(self.create_fsx_item(
                    'FSx.2',
                    'FSx for Lustre file systems should be configured to copy tags to backups',
                    'failed',
                    'LOW',
                    'available',
                    response_detail['FileSystemId']
                ))
            else:
                self.fsx_list.append(self.create_fsx_item(
                    'FSx.2',
                    'FSx for Lustre file systems should be configured to copy tags to backups',
                    'passed',
                    'LOW',
                    'available',
                    response_detail['FileSystemId']
                ))

class CrossAccountFSxComplianceChecker:
    def __init__(self) -> None:
        self.fsx_client = UseCrossAccount().client('fsx')
        self.fsx_list = compliance_check_list

    def create_fsx_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("FSx", control_id, compliance, severity, auto_remediation):
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
        
    def fsx_file_system_list(self) -> list[dict]:
        file_system_list: list[dict] = []
        try:
            response = boto3.client('fsx').describe_file_systems()
            file_system_list.extend(_ for _ in response['FileSystems'])
            while 'NextToken' in response:
                response = boto3.client('fsx').describe_file_systems(NextToken=response['NextToken'])
                file_system_list.extend(_ for _ in response['FileSystems'])
            return file_system_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    @DecoratorClass.my_decorator
    def fsx_one(self) -> None:
        result_list = self.fsx_file_system_list()
        result_list = [_['OpenZFSConfiguration'] for _ in result_list if _['FileSystemType'] == "OPENZFS"]
        if not result_list:
            self.fsx_list.append(self.create_fsx_item(
                'FSx.1',
                'FSx for OpenZFS file systems should be configured to copy tags to backups and volumes',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if any([response_detail['CopyTagsToBackups'] != True, response_detail['CopyTagsToVolumes'] != True]):
                self.fsx_list.append(self.create_fsx_item(
                    'FSx.1',
                    'FSx for OpenZFS file systems should be configured to copy tags to backups and volumes',
                    'failed',
                    'LOW',
                    'available',
                    response_detail['FileSystemId']
                ))
            else:
                self.fsx_list.append(self.create_fsx_item(
                    'FSx.1',
                    'FSx for OpenZFS file systems should be configured to copy tags to backups and volumes',
                    'passed',
                    'LOW',
                    'available',
                    response_detail['FileSystemId']
                ))
    
    @DecoratorClass.my_decorator
    def fsx_two(self) -> None:
        result_list = self.fsx_file_system_list()
        result_list = [_['LustreConfiguration'] for _ in result_list if _['FileSystemType'] == "LUSTRE"]
        if not result_list:
            self.fsx_list.append(self.create_fsx_item(
                'FSx.2',
                'FSx for Lustre file systems should be configured to copy tags to backups',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['CopyTagsToBackups'] != True:
                self.fsx_list.append(self.create_fsx_item(
                    'FSx.2',
                    'FSx for Lustre file systems should be configured to copy tags to backups',
                    'failed',
                    'LOW',
                    'available',
                    response_detail['FileSystemId']
                ))
            else:
                self.fsx_list.append(self.create_fsx_item(
                    'FSx.2',
                    'FSx for Lustre file systems should be configured to copy tags to backups',
                    'passed',
                    'LOW',
                    'available',
                    response_detail['FileSystemId']
                ))