'''
Class name DataFirehoseComplianceChecker
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

class DataFirehoseComplianceChecker:
    def __init__(self) -> None:
        self.firehose_client = boto3.client('firehose')
        self.datafirehose_list = compliance_check_list

    def create_datafirehose_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("DataFirehose", control_id, compliance, severity, auto_remediation):
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
    
    def datafirehose_stream_list(self) -> list[dict]:
        try:
            response = self.firehose_client.list_delivery_streams()
            return response['DeliveryStreamNames']
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def datafirehose_describe_stream_list(self) -> list[dict]:
        result_list = self.datafirehose_stream_list()
        stream_list: list[dict] = []
        for response_detail in result_list:
            try:
                response = self.firehose_client.describe_stream_summary(
                    DeliveryStreamName=response_detail
                )
                stream_list.append(response['DeliveryStreamDescription'])
            except ClientError as e:
                print(f"Error: {e}")
                return []
        return stream_list
    
    @DecoratorClass.my_decorator
    def datafirehose_one(self) -> None:
        result_list = self.datafirehose_describe_stream_list()
        if not result_list:
            self.datafirehose_list.append(self.create_datafirehose_item(
                'DataFirehose.1',
                'Firehose delivery streams should be encrypted at rest',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if "DeliveryStreamEncryptionConfiguration" in response_detail:
                if response_detail['DeliveryStreamEncryptionConfiguration']['Status'] != "ENABLED":
                    compliant_status = "failed"
            else:
                compliant_status = "failed"
            self.datafirehose_list.append(self.create_datafirehose_item(
                'DataFirehose.1',
                'Firehose delivery streams should be encrypted at rest',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['StreamARN']
            ))

class CrossAccountDataFirehoseComplianceChecker:
    def __init__(self) -> None:
        self.firehose_client = UseCrossAccount().client('firehose')
        self.datafirehose_list = compliance_check_list

    def create_datafirehose_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("DataFirehose", control_id, compliance, severity, auto_remediation):
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
    
    def datafirehose_stream_list(self) -> list[dict]:
        try:
            response = self.firehose_client.list_delivery_streams()
            return response['DeliveryStreamNames']
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def datafirehose_describe_stream_list(self) -> list[dict]:
        result_list = self.datafirehose_stream_list()
        stream_list: list[dict] = []
        for response_detail in result_list:
            try:
                response = self.firehose_client.describe_stream_summary(
                    DeliveryStreamName=response_detail
                )
                stream_list.append(response['DeliveryStreamDescription'])
            except ClientError as e:
                print(f"Error: {e}")
                return []
        return stream_list
    
    @DecoratorClass.my_decorator
    def datafirehose_one(self) -> None:
        result_list = self.datafirehose_describe_stream_list()
        if not result_list:
            self.datafirehose_list.append(self.create_datafirehose_item(
                'DataFirehose.1',
                'Firehose delivery streams should be encrypted at rest',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if "DeliveryStreamEncryptionConfiguration" in response_detail:
                if response_detail['DeliveryStreamEncryptionConfiguration']['Status'] != "ENABLED":
                    compliant_status = "failed"
            else:
                compliant_status = "failed"
            self.datafirehose_list.append(self.create_datafirehose_item(
                'DataFirehose.1',
                'Firehose delivery streams should be encrypted at rest',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['StreamARN']
            ))