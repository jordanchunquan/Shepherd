'''
Class name KinesisComplianceChecker
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

class KinesisComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.kinesis_client = boto3.client('kinesis')
        self.kinesis_list = compliance_check_list

    def create_kinesis_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("Kinesis", control_id, compliance, severity, auto_remediation):
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
    
    def kinesis_stream_list(self) -> list[dict]:
        stream_list: list[dict] = []
        try:
            response = self.kinesis_client.list_streams()
            stream_list.extend(_ for _ in response['StreamSummaries'])
            while 'NextToken' in response:
                response = self.kinesis_client.list_streams(NextToken=response['NextToken'])
                stream_list.extend(_ for _ in response['StreamSummaries'])
            return stream_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def kinesis_describe_stream_list(self) -> list[dict]:
        result_list = self.kinesis_stream_list()
        stream_list: list[dict] = []
        for response_detail in result_list:
            try:
                response = self.kinesis_client.describe_stream_summary(
                    StreamName=response_detail['StreamName'],
                    StreamARN=response_detail['StreamARN']
                )
                stream_list.append(response['StreamDescriptionSummary'])
            except ClientError as e:
                print(f"Error: {e}")
                return []
        return stream_list
    
    def kinesis_stream_tag_list(self, stream_name:str, stream_arn:str) -> str:
        try:
            compliant_status = "passed"
            response = self.kinesis_client.list_tags_for_stream(
                StreamName=stream_name,
                StreamARN=stream_arn
            )
            tag_key_list = [tag['Key'] for tag in response['Tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
    
    @DecoratorClass.my_decorator
    def kinesis_one(self) -> None:
        result_list = self.kinesis_describe_stream_list()
        if not result_list:
            self.kinesis_list.append(self.create_kinesis_item(
                'Kinesis.1',
                'Kinesis streams should be encrypted at rest',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['EncryptionType'] == "NONE":
                self.kinesis_list.append(self.create_kinesis_item(
                    'Kinesis.1',
                    'Kinesis streams should be encrypted at rest',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['StreamARN']
                ))
            else:
                self.kinesis_list.append(self.create_kinesis_item(
                    'Kinesis.1',
                    'Kinesis streams should be encrypted at rest',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['StreamARN']
                ))
    
    @DecoratorClass.my_decorator
    def kinesis_two(self) -> None:
        result_list = self.kinesis_stream_list()
        if not result_list:
            self.kinesis_list.append(self.create_kinesis_item(
                'Kinesis.2',
                'Kinesis streams should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.kinesis_stream_tag_list(response_detail['StreamName'], response_detail['StreamARN'])
            self.kinesis_list.append(self.create_kinesis_item(
                'Kinesis.2',
                'Kinesis streams should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['StreamARN']
            ))

class CrossAccountKinesisComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.kinesis_client = UseCrossAccount().client('kinesis')
        self.kinesis_list = compliance_check_list

    def create_kinesis_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("Kinesis", control_id, compliance, severity, auto_remediation):
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
    
    def kinesis_stream_list(self) -> list[dict]:
        stream_list: list[dict] = []
        try:
            response = self.kinesis_client.list_streams()
            stream_list.extend(_ for _ in response['StreamSummaries'])
            while 'NextToken' in response:
                response = self.kinesis_client.list_streams(NextToken=response['NextToken'])
                stream_list.extend(_ for _ in response['StreamSummaries'])
            return stream_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def kinesis_describe_stream_list(self) -> list[dict]:
        result_list = self.kinesis_stream_list()
        stream_list: list[dict] = []
        for response_detail in result_list:
            try:
                response = self.kinesis_client.describe_stream_summary(
                    StreamName=response_detail['StreamName'],
                    StreamARN=response_detail['StreamARN']
                )
                stream_list.append(response['StreamDescriptionSummary'])
            except ClientError as e:
                print(f"Error: {e}")
                return []
        return stream_list
    
    def kinesis_stream_tag_list(self, stream_name:str, stream_arn:str) -> str:
        try:
            compliant_status = "passed"
            response = self.kinesis_client.list_tags_for_stream(
                StreamName=stream_name,
                StreamARN=stream_arn
            )
            tag_key_list = [tag['Key'] for tag in response['Tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
    
    @DecoratorClass.my_decorator
    def kinesis_one(self) -> None:
        result_list = self.kinesis_describe_stream_list()
        if not result_list:
            self.kinesis_list.append(self.create_kinesis_item(
                'Kinesis.1',
                'Kinesis streams should be encrypted at rest',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['EncryptionType'] == "NONE":
                self.kinesis_list.append(self.create_kinesis_item(
                    'Kinesis.1',
                    'Kinesis streams should be encrypted at rest',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['StreamARN']
                ))
            else:
                self.kinesis_list.append(self.create_kinesis_item(
                    'Kinesis.1',
                    'Kinesis streams should be encrypted at rest',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['StreamARN']
                ))
    
    @DecoratorClass.my_decorator
    def kinesis_two(self) -> None:
        result_list = self.kinesis_stream_list()
        if not result_list:
            self.kinesis_list.append(self.create_kinesis_item(
                'Kinesis.2',
                'Kinesis streams should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.kinesis_stream_tag_list(response_detail['StreamName'], response_detail['StreamARN'])
            self.kinesis_list.append(self.create_kinesis_item(
                'Kinesis.2',
                'Kinesis streams should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['StreamARN']
            ))