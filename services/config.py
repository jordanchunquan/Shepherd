'''
Class name ConfigComplianceChecker
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

class ConfigComplianceChecker:
    def __init__(self) -> None:
        self.config_client = boto3.client('config')
        self.session_account = boto3.client('sts').get_caller_identity().get('Account')
        self.config_list = compliance_check_list

    def create_config_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str) -> dict:
        if ParameterValidation().validate_parameter("Config", control_id, compliance, severity, auto_remediation):
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
    def config_one(self) -> None:
        try:
            response = self.config_client.describe_configuration_recorders()
            if not response.get('ConfigurationRecorders'):
                self.config_list.append(self.create_config_item(
                    'Config.1',
                    'AWS Config should be enabled and use the service-linked role for resource recording',
                    'failed',
                    'MEDIUM',
                    'not_available'
                ))
            else:
                self.config_list.append(self.create_config_item(
                    'Config.1',
                    'AWS Config should be enabled and use the service-linked role for resource recording',
                    'passed',
                    'MEDIUM',
                    'not_available'
                ))
        except ClientError as e:
            print(f"Error: {e}")

class ConfigAutoRemediation:
    def __init__(self) -> None:
        self.sts_client = boto3.client('sts')
        self.session_account = self.sts_client.get_caller_identity().get('Account')
        self.config_client = boto3.client('config')
        self.recorder_name = 'my-config-recorder'
        self.delivery_channel_name = 'my-delivery-channel'
        self.bucket_name = 'XXXXXXXXXXXXXXXX'
        self.s3_key_prefix = 'config-snapshots'
        self.role_arn = f"arn:aws:iam::{self.session_account}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
        self.remediate_config_one()

    def edit_config_recorder(self) -> None:
        try:
            self.config_client.put_configuration_recorder(
                ConfigurationRecorder={
                    'name': self.recorder_name,
                    'roleARN': self.role_arn,
                    'recordingGroup': {
                        'allSupported': True,
                        'includeGlobalResourceTypes': True
                    }
                }
            )
        except ClientError as e:
            print(f"Error: {e}")


    def edit_config_delivery_channel(self) -> None:
        try:
            self.config_client.put_delivery_channel(
                DeliveryChannel={
                    'name': self.delivery_channel_name,
                    's3BucketName': self.bucket_name,
                    's3KeyPrefix': self.s3_key_prefix
                }
            )
        except ClientError as e:
            print(f"Error: {e}")

    def start_config_recorder(self) -> None:
        try:
            self.config_client.start_configuration_recorder(
                ConfigurationRecorderName=self.recorder_name
            )
        except ClientError as e:
            print(f"Error: {e}")
            
    def remediate_config_one(self) -> None:
        self.edit_config_recorder()
        self.edit_config_delivery_channel()
        self.start_config_recorder()

class CrossAccountConfigComplianceChecker:
    def __init__(self) -> None:
        self.config_client = UseCrossAccount().client('config')
        self.session_account = UseCrossAccount().client('sts').get_caller_identity().get('Account')
        self.config_list = compliance_check_list

    def create_config_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str) -> dict:
        if ParameterValidation().validate_parameter("Config", control_id, compliance, severity, auto_remediation):
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
    def config_one(self) -> None:
        try:
            response = self.config_client.describe_configuration_recorders()
            if not response.get('ConfigurationRecorders'):
                self.config_list.append(self.create_config_item(
                    'Config.1',
                    'AWS Config should be enabled and use the service-linked role for resource recording',
                    'failed',
                    'MEDIUM',
                    'not_available'
                ))
            else:
                self.config_list.append(self.create_config_item(
                    'Config.1',
                    'AWS Config should be enabled and use the service-linked role for resource recording',
                    'passed',
                    'MEDIUM',
                    'not_available'
                ))
        except ClientError as e:
            print(f"Error: {e}")

class CrossAccountConfigAutoRemediation:
    def __init__(self) -> None:
        self.sts_client = UseCrossAccount().client('sts')
        self.session_account = self.sts_client.get_caller_identity().get('Account')
        self.config_client = UseCrossAccount().client('config')
        self.recorder_name = 'my-config-recorder'
        self.delivery_channel_name = 'my-delivery-channel'
        self.bucket_name = 'XXXXXXXXXXXXXXXX'
        self.s3_key_prefix = 'config-snapshots'
        self.role_arn = f"arn:aws:iam::{self.session_account}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
        self.remediate_config_one()

    def edit_config_recorder(self) -> None:
        try:
            self.config_client.put_configuration_recorder(
                ConfigurationRecorder={
                    'name': self.recorder_name,
                    'roleARN': self.role_arn,
                    'recordingGroup': {
                        'allSupported': True,
                        'includeGlobalResourceTypes': True
                    }
                }
            )
        except ClientError as e:
            print(f"Error: {e}")


    def edit_config_delivery_channel(self) -> None:
        try:
            self.config_client.put_delivery_channel(
                DeliveryChannel={
                    'name': self.delivery_channel_name,
                    's3BucketName': self.bucket_name,
                    's3KeyPrefix': self.s3_key_prefix
                }
            )
        except ClientError as e:
            print(f"Error: {e}")

    def start_config_recorder(self) -> None:
        try:
            self.config_client.start_configuration_recorder(
                ConfigurationRecorderName=self.recorder_name
            )
        except ClientError as e:
            print(f"Error: {e}")
            
    def remediate_config_one(self) -> None:
        self.edit_config_recorder()
        self.edit_config_delivery_channel()
        self.start_config_recorder()