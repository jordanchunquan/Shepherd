'''
Class name ACMComplianceChecker
Create functions to check compliants and return as 
'control_id': security contorl id,
'control_title': security control title,
'compliance': passed, failed or not_found,
'severity': CRITICAL, HIGH, MEDIUM or LOW,
'auto_remediation': available or not_available,
'resource_id': account id, resource arn or not_found

Class name ACMAutoRemediation
Autoremediate ACM one by renewing non compliant certificate
Unable to autoremediate ACM two becuase it require approval from client to issue new certificate
'''

import boto3, pytz, datetime # type: ignore
from botocore.exceptions import ClientError # type: ignore
from utils.decorator_class import DecoratorClass # type: ignore
from utils.validate import ParameterValidation # type: ignore
from utils.cross_account import UseCrossAccount # type: ignore
from utils.global_data import compliance_check_list # type: ignore

class ACMComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.acm_client = boto3.client('acm')
        self.acm_list = compliance_check_list

    def create_acm_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("ACM", control_id, compliance, severity, auto_remediation):
            return {
                'control_id': control_id,
                'control_title': control_title,
                'compliance': compliance,
                'severity': severity,
                'auto_remediation': auto_remediation,
                'resource_id': resource_id
            }
        else:
            print(f"Error: Invalid parameter.")
            return {
                control_id: 'Invalid parameter',
                control_title: 'Invalid parameter',
                compliance: 'Invalid parameter',
                severity: 'Invalid parameter',
                auto_remediation: 'Invalid parameter',
                resource_id: 'Invalid parameter'
            }

    def certificate_list(self) -> list[dict]:
        acm_list: list[dict] = []
        try:
            response = self.acm_client.list_certificates()
            acm_list.extend(_ for _ in response['CertificateSummaryList'])
            while 'NextToken' in response:
                response = self.acm_client.list_certificates(NextToken=response['NextToken'])
                acm_list.extend(_ for _ in response['CertificateSummaryList'])
            response = boto3.client('acm', region_name="us-east-1").list_certificates()
            acm_list.extend(_ for _ in response['CertificateSummaryList'])
            while 'NextToken' in response:
                response = boto3.client('acm', region_name="us-east-1").list_certificates(NextToken=response['NextToken'])
                acm_list.extend(_ for _ in response['CertificateSummaryList'])
            return acm_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    def certificate_tag_list(self, certificate_arn:str) -> str:
        try:
            compliant_status = "passed"
            response = self.acm_client.list_tags_for_certificate(CertificateArn=certificate_arn)
            tag_key_list = [tag['Key'] for tag in response['Tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""

    @DecoratorClass.my_decorator
    def acm_one(self) -> None:
        result_list = self.certificate_list()
        if not result_list:
            self.acm_list.append(self.create_acm_item(
                'ACM.1',
                'Imported and ACM-issued certificates should be renewed after a specified time period',
                'not_found',
                'MEDIUM',
                'available',
                'not_found'
            ))
        for _ in result_list:
            if (_['NotAfter'] - datetime.datetime.now(pytz.timezone('Asia/Kuala_Lumpur'))).days <= 30:
                self.acm_list.append(self.create_acm_item(
                    'ACM.1',
                    'Imported and ACM-issued certificates should be renewed after a specified time period',
                    'failed',
                    'MEDIUM',
                    'available',
                    _['CertificateArn']
                ))
            else:
                self.acm_list.append(self.create_acm_item(
                    'ACM.1',
                    'Imported and ACM-issued certificates should be renewed after a specified time period',
                    'passed',
                    'MEDIUM',
                    'available',
                    _['CertificateArn']
                ))

    @DecoratorClass.my_decorator
    def acm_two(self) -> None:
        result_list = self.certificate_list()
        if not result_list:
            self.acm_list.append(self.create_acm_item(
                'ACM.2',
                'RSA certificates managed by ACM should use a key length of at least 2,048 bits',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for _ in result_list:
            if _['KeyAlgorithm'] == "RSA_1024":
                self.acm_list.append(self.create_acm_item(
                    'ACM.2',
                    'RSA certificates managed by ACM should use a key length of at least 2,048 bits',
                    'failed',
                    'HIGH',
                    'not_available',
                    _['CertificateArn']
                ))
            else:
                self.acm_list.append(self.create_acm_item(
                    'ACM.2',
                    'RSA certificates managed by ACM should use a key length of at least 2,048 bits',
                    'passed',
                    'HIGH',
                    'not_available',
                    _['CertificateArn']
                ))

    @DecoratorClass.my_decorator
    def acm_three(self) -> None:
        result_list = self.certificate_list()
        if not result_list:
            self.acm_list.append(self.create_acm_item(
                'ACM.3',
                'ACM certificates should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.certificate_tag_list(response_detail['CertificateArn'])
            self.acm_list.append(self.create_acm_item(
                'ACM.3',
                'ACM certificates should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['CertificateArn']
            ))

class ACMAutoRemediation:
    def __init__(self) -> None:
        self.acm_client = boto3.client('acm')
        self.certificate_list = ACMComplianceChecker().certificate_list()
        self.remediate_acm_one()

    def remediate_acm_one(self) -> None:
        result_list = self.certificate_list
        for _ in result_list:
            if (_['NotAfter'] - datetime.datetime.now(pytz.timezone('Asia/Kuala_Lumpur'))).days <= 30:
                try:
                    self.acm_client.renew_certificate(CertificateArn=_['CertificateArn'])
                    print(f"Auto remediated for ACM.1: {_['CertificateArn']}")
                except ClientError as e:
                    print(f"Error: {e}")

class CrossAccountACMComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.acm_client = UseCrossAccount().client('acm')
        self.acm_list = compliance_check_list

    def create_acm_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("ACM", control_id, compliance, severity, auto_remediation):
            return {
                'control_id': control_id,
                'control_title': control_title,
                'compliance': compliance,
                'severity': severity,
                'auto_remediation': auto_remediation,
                'resource_id': resource_id
            }
        else:
            print(f"Error: Invalid parameter.")
            return {
                control_id: 'Invalid parameter',
                control_title: 'Invalid parameter',
                compliance: 'Invalid parameter',
                severity: 'Invalid parameter',
                auto_remediation: 'Invalid parameter',
                resource_id: 'Invalid parameter'
            }

    def certificate_list(self) -> list[dict]:
        acm_list: list[dict] = []
        try:
            response = self.acm_client.list_certificates()
            acm_list.extend(_ for _ in response['CertificateSummaryList'])
            while 'NextToken' in response:
                response = self.acm_client.list_certificates(NextToken=response['NextToken'])
                acm_list.extend(_ for _ in response['CertificateSummaryList'])
            response = boto3.client('acm', region_name="us-east-1").list_certificates()
            acm_list.extend(_ for _ in response['CertificateSummaryList'])
            while 'NextToken' in response:
                response = boto3.client('acm', region_name="us-east-1").list_certificates(NextToken=response['NextToken'])
                acm_list.extend(_ for _ in response['CertificateSummaryList'])
            return acm_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    def certificate_tag_list(self, certificate_arn:str) -> str:
        try:
            compliant_status = "passed"
            response = self.acm_client.list_tags_for_certificate(CertificateArn=certificate_arn)
            tag_key_list = [tag['Key'] for tag in response['Tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""

    @DecoratorClass.my_decorator
    def acm_one(self) -> None:
        result_list = self.certificate_list()
        if not result_list:
            self.acm_list.append(self.create_acm_item(
                'ACM.1',
                'Imported and ACM-issued certificates should be renewed after a specified time period',
                'not_found',
                'MEDIUM',
                'available',
                'not_found'
            ))
        for _ in result_list:
            if (_['NotAfter'] - datetime.datetime.now(pytz.timezone('Asia/Kuala_Lumpur'))).days <= 30:
                self.acm_list.append(self.create_acm_item(
                    'ACM.1',
                    'Imported and ACM-issued certificates should be renewed after a specified time period',
                    'failed',
                    'MEDIUM',
                    'available',
                    _['CertificateArn']
                ))
            else:
                self.acm_list.append(self.create_acm_item(
                    'ACM.1',
                    'Imported and ACM-issued certificates should be renewed after a specified time period',
                    'passed',
                    'MEDIUM',
                    'available',
                    _['CertificateArn']
                ))

    @DecoratorClass.my_decorator
    def acm_two(self) -> None:
        result_list = self.certificate_list()
        if not result_list:
            self.acm_list.append(self.create_acm_item(
                'ACM.2',
                'RSA certificates managed by ACM should use a key length of at least 2,048 bits',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for _ in result_list:
            if _['KeyAlgorithm'] == "RSA_1024":
                self.acm_list.append(self.create_acm_item(
                    'ACM.2',
                    'RSA certificates managed by ACM should use a key length of at least 2,048 bits',
                    'failed',
                    'HIGH',
                    'not_available',
                    _['CertificateArn']
                ))
            else:
                self.acm_list.append(self.create_acm_item(
                    'ACM.2',
                    'RSA certificates managed by ACM should use a key length of at least 2,048 bits',
                    'passed',
                    'HIGH',
                    'not_available',
                    _['CertificateArn']
                ))

    @DecoratorClass.my_decorator
    def acm_three(self) -> None:
        result_list = self.certificate_list()
        if not result_list:
            self.acm_list.append(self.create_acm_item(
                'ACM.3',
                'ACM certificates should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.certificate_tag_list(response_detail['CertificateArn'])
            self.acm_list.append(self.create_acm_item(
                'ACM.3',
                'ACM certificates should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['CertificateArn']
            ))

class CrossAccountACMAutoRemediation:
    def __init__(self) -> None:
        self.acm_client = UseCrossAccount().client("acm")
        self.certificate_list = CrossAccountACMComplianceChecker().certificate_list()
        self.remediate_acm_one()

    def remediate_acm_one(self) -> None:
        result_list = self.certificate_list
        for _ in result_list:
            if (_['NotAfter'] - datetime.datetime.now(pytz.timezone('Asia/Kuala_Lumpur'))).days <= 30:
                try:
                    self.acm_client.renew_certificate(CertificateArn=_['CertificateArn'])
                    print(f"Auto remediated for ACM.1: {_['CertificateArn']}")
                except ClientError as e:
                    print(f"Error: {e}")