'''
Class name ServiceComplianceChecker
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

class MacieComplianceChecker:
    def __init__(self) -> None:
        self.macie_client = boto3.client('macie2')
        self.session_account = boto3.client('sts').get_caller_identity()['Account']
        self.macie_list = compliance_check_list

    def create_macie_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("Macie", control_id, compliance, severity, auto_remediation):
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
    
    def macie_status(self) -> str:
        try:
            compliant_status = "passed"
            response = self.macie_client.get_macie_session()
            if response['status'] != 'ENABLED':
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDeniedException':
                return "failed"
            else:
                print(f"Error: {e}")
                return ""

    def macie_configuration_status(self) -> str:
        try:
            compliant_status = "passed"
            response = self.macie_client.get_automated_discovery_configuration()
            if response['configuration']['automatedDiscoveryStatus'] != 'ENABLED':
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDeniedException':
                return "failed"
            else:
                print(f"Error: {e}")
                return ""
    
    @DecoratorClass.my_decorator
    def macie_one(self) -> None:
        compliant_status = self.macie_status()
        self.macie_list.append(self.create_macie_item(
            'Macie.1',
            'Amazon Macie should be enabled',
            compliant_status,
            'MEDIUM',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def macie_two(self) -> None:
        compliant_status = self.macie_configuration_status()
        self.macie_list.append(self.create_macie_item(
            'Macie.2',
            'Macie automated sensitive data discovery should be enabled',
            compliant_status,
            'HIGH',
            'not_available',
            self.session_account
        ))

class CrossAccountMacieComplianceChecker:
    def __init__(self) -> None:
        self.macie_client = UseCrossAccount().client('macie2')
        self.session_account = UseCrossAccount().client('sts').get_caller_identity()['Account']
        self.macie_list = compliance_check_list

    def create_macie_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("Macie", control_id, compliance, severity, auto_remediation):
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
    
    def macie_status(self) -> str:
        try:
            compliant_status = "passed"
            response = self.macie_client.get_macie_session()
            if response['status'] != 'ENABLED':
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDeniedException':
                return "failed"
            else:
                print(f"Error: {e}")
                return ""

    def macie_configuration_status(self) -> str:
        try:
            compliant_status = "passed"
            response = self.macie_client.get_automated_discovery_configuration()
            if response['configuration']['automatedDiscoveryStatus'] != 'ENABLED':
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDeniedException':
                return "failed"
            else:
                print(f"Error: {e}")
                return ""
    
    @DecoratorClass.my_decorator
    def macie_one(self) -> None:
        compliant_status = self.macie_status()
        self.macie_list.append(self.create_macie_item(
            'Macie.1',
            'Amazon Macie should be enabled',
            compliant_status,
            'MEDIUM',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def macie_two(self) -> None:
        compliant_status = self.macie_configuration_status()
        self.macie_list.append(self.create_macie_item(
            'Macie.2',
            'Macie automated sensitive data discovery should be enabled',
            compliant_status,
            'HIGH',
            'not_available',
            self.session_account
        ))