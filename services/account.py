'''
Class name AccountComplianceChecker
Create functions to check compliants and return as 
'control_id': security contorl id,
'control_title': security control title,
'compliance': passed, failed or not_found,
'severity': CRITICAL, HIGH, MEDIUM or LOW,
'auto_remediation': available or not_available,
'resource_id': account id, resource arn or not_found

Autoremediate Account one by adding security contact after gathered information
Unable to autoremediate Account two becuase it require approval from client to add account in organization
'''

import boto3 # type: ignore
from botocore.exceptions import ClientError # type: ignore
from utils.decorator_class import DecoratorClass # type: ignore
from utils.validate import ParameterValidation # type: ignore
from utils.cross_account import UseCrossAccount # type: ignore
from utils.global_data import compliance_check_list # type: ignore

class AccountComplianceChecker:
    def __init__(self) -> None:
        self.sts_client = boto3.client('sts')
        self.account_client = boto3.client('account')
        self.organization_client = boto3.client('organizations')
        self.session_account = self.sts_client.get_caller_identity().get('Account')
        self.account_list = compliance_check_list

    def create_account_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str) -> dict:
        if ParameterValidation().validate_parameter("Account", control_id, compliance, severity, auto_remediation):
            return {
                'control_id': control_id,
                'control_title': control_title,
                'compliance': compliance,
                'severity': severity,
                'auto_remediation': auto_remediation,
                'resource_id': self.session_account
            }
        else:
            return {
                control_id: 'Invalid parameter',
                control_title: 'Invalid parameter',
                compliance: 'Invalid parameter',
                severity: 'Invalid parameter',
                auto_remediation: 'Invalid parameter',
                self.session_account: 'Invalid parameter'
            }

    @DecoratorClass.my_decorator
    def account_one(self) -> None:
        try:
            self.account_client.get_alternate_contact(AlternateContactType='SECURITY')
            self.account_list.append(self.create_account_item(
                'Account.1',
                'Security contact information should be provided for an AWS account',
                'passed',
                'MEDIUM',
                'available'
            ))
        except ClientError as e:
            if e.response['Error']['Code'] == "ResourceNotFoundException":
                self.account_list.append(self.create_account_item(
                    'Account.1',
                    'Security contact information should be provided for an AWS account',
                    'failed',
                    'MEDIUM',
                    'available'
                ))
            else:
                print(f"Error: {e}")

    @DecoratorClass.my_decorator
    def account_two(self) -> None:
        try:
            self.organization_client.describe_organization()
            self.account_list.append(self.create_account_item(
                'Account.2',
                'AWS account should be part of an AWS Organizations organization',
                'passed',
                'HIGH',
                'not_available'
            ))
        except ClientError as e:
            if e.response['Error']['Code'] == "AWSOrganizationsNotInUseException":
                self.account_list.append(self.create_account_item(
                    'Account.2',
                    'AWS account should be part of an AWS Organizations organization',
                    'failed',
                    'HIGH',
                    'not_available'
                ))
            else:
                print(f"Error: {e}")

class CrossAccountAccountComplianceChecker:
    def __init__(self) -> None:
        self.sts_client = UseCrossAccount().client('sts')
        self.account_client = UseCrossAccount().client('account')
        self.organization_client = UseCrossAccount().client('organizations')
        self.session_account = self.sts_client.get_caller_identity().get('Account')
        self.account_list = compliance_check_list

    def create_account_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str) -> dict:
        if ParameterValidation().validate_parameter("Account", control_id, compliance, severity, auto_remediation):
            return {
                'control_id': control_id,
                'control_title': control_title,
                'compliance': compliance,
                'severity': severity,
                'auto_remediation': auto_remediation,
                'resource_id': self.session_account
            }
        else:
            return {
                control_id: 'Invalid parameter',
                control_title: 'Invalid parameter',
                compliance: 'Invalid parameter',
                severity: 'Invalid parameter',
                auto_remediation: 'Invalid parameter',
                self.session_account: 'Invalid parameter'
            }

    @DecoratorClass.my_decorator
    def account_one(self) -> None:
        try:
            self.account_client.get_alternate_contact(AlternateContactType='SECURITY')
            self.account_list.append(self.create_account_item(
                'Account.1',
                'Security contact information should be provided for an AWS account',
                'passed',
                'MEDIUM',
                'available'
            ))
        except ClientError as e:
            if e.response['Error']['Code'] == "ResourceNotFoundException":
                self.account_list.append(self.create_account_item(
                    'Account.1',
                    'Security contact information should be provided for an AWS account',
                    'failed',
                    'MEDIUM',
                    'available'
                ))
            else:
                print(f"Error: {e}")

    @DecoratorClass.my_decorator
    def account_two(self) -> None:
        try:
            self.organization_client.describe_organization()
            self.account_list.append(self.create_account_item(
                'Account.2',
                'AWS account should be part of an AWS Organizations organization',
                'passed',
                'HIGH',
                'not_available'
            ))
        except ClientError as e:
            if e.response['Error']['Code'] == "AWSOrganizationsNotInUseException":
                self.account_list.append(self.create_account_item(
                    'Account.2',
                    'AWS account should be part of an AWS Organizations organization',
                    'failed',
                    'HIGH',
                    'not_available'
                ))
            else:
                print(f"Error: {e}")