'''
Class name PCAComplianceChecker
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

class PCAComplianceChecker:
    def __init__(self) -> None:
        self.pca_client = boto3.client('acm-pca')
        self.pca_list = compliance_check_list # type: ignore

    def create_pca_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("PCA", control_id, compliance, severity, auto_remediation):
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
    
    def pca_ca_list(self) -> list[dict]:
        ca_list: list[dict] = []
        try:
            response = self.pca_client.list_certificate_authorities()
            ca_list.extend(_ for _ in response['CertificateAuthorities'])
            if 'NextToken' in response:
                response = self.pca_client.list_certificate_authorities(NextToken=response['NextToken'])
                ca_list.extend(_ for _ in response['CertificateAuthorities'])
            return ca_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    @DecoratorClass.my_decorator
    def pca_one(self) -> None:
        result_list = self.pca_ca_list()
        result_list = [_ for _ in result_list if _['Type'] == 'ROOT']
        if not result_list:
            self.pca_list.append(self.create_pca_item(
                'PCA.1',
                'AWS Private CA root certificate authority should be disabled',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['Status'] != 'DISABLED':
                self.pca_list.append(self.create_pca_item(
                    'PCA.1',
                    'AWS Private CA root certificate authority should be disabled',
                    'failed',
                    'LOW',
                    'available',
                    response_detail['Arn']
                ))
            else:
                self.pca_list.append(self.create_pca_item(
                    'PCA.1',
                    'AWS Private CA root certificate authority should be disabled',
                    'passed',
                    'LOW',
                    'available',
                    response_detail['Arn']
                ))

class CrossAccountPCAComplianceChecker:
    def __init__(self) -> None:
        self.pca_client = UseCrossAccount().client('acm-pca')
        self.pca_list = compliance_check_list # type: ignore

    def create_pca_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("PCA", control_id, compliance, severity, auto_remediation):
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
    
    def pca_ca_list(self) -> list[dict]:
        ca_list: list[dict] = []
        try:
            response = self.pca_client.list_certificate_authorities()
            ca_list.extend(_ for _ in response['CertificateAuthorities'])
            if 'NextToken' in response:
                response = self.pca_client.list_certificate_authorities(NextToken=response['NextToken'])
                ca_list.extend(_ for _ in response['CertificateAuthorities'])
            return ca_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    @DecoratorClass.my_decorator
    def pca_one(self) -> None:
        result_list = self.pca_ca_list()
        result_list = [_ for _ in result_list if _['Type'] == 'ROOT']
        if not result_list:
            self.pca_list.append(self.create_pca_item(
                'PCA.1',
                'AWS Private CA root certificate authority should be disabled',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['Status'] != 'DISABLED':
                self.pca_list.append(self.create_pca_item(
                    'PCA.1',
                    'AWS Private CA root certificate authority should be disabled',
                    'failed',
                    'LOW',
                    'available',
                    response_detail['Arn']
                ))
            else:
                self.pca_list.append(self.create_pca_item(
                    'PCA.1',
                    'AWS Private CA root certificate authority should be disabled',
                    'passed',
                    'LOW',
                    'available',
                    response_detail['Arn']
                ))