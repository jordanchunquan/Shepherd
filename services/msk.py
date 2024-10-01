'''
Class name MSKComplianceChecker
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

class MSKComplianceChecker:
    def __init__(self) -> None:
        self.kafka_client = boto3.client('kafka')
        self.msk_list = compliance_check_list

    def create_msk_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("MSK", control_id, compliance, severity, auto_remediation):
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
    
    def kafka_cluster_list(self) -> list[dict]:
        cluster_list: list[dict] = []
        try:
            response = self.kafka_client.list_clusters()
            cluster_list.extend(_ for _ in response['ClusterInfoList'])
            while 'NextToken' in response:
                response = self.kafka_client.list_clusters(NextToken=response['NextToken'])
                cluster_list.extend(_ for _ in response['ClusterInfoList'])
            return cluster_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    @DecoratorClass.my_decorator
    def msk_one(self) -> None:
        result_list = self.kafka_cluster_list()
        if not result_list:
            self.msk_list.append(self.create_msk_item(
                'MSK.1',
                'MSK clusters should be encrypted in transit among broker nodes',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('EncryptionInfo', {}).get('EncryptionInTransit', {}).get('ClientBroker', None) == None:
                self.msk_list.append(self.create_msk_item(
                    'MSK.1',
                    'MSK clusters should be encrypted in transit among broker nodes',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ClusterArn']
                ))
            else:
                self.msk_list.append(self.create_msk_item(
                    'MSK.1',
                    'MSK clusters should be encrypted in transit among broker nodes',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ClusterArn']
                ))

    @DecoratorClass.my_decorator
    def msk_two(self) -> None:
        result_list = self.kafka_cluster_list()
        if not result_list:
            self.msk_list.append(self.create_msk_item(
                'MSK.2',
                'MSK clusters should have enhanced monitoring configured',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('EnhancedMonitoring', None) in [ None, "DEFAULT", "PER_BROKER" ]:
                self.msk_list.append(self.create_msk_item(
                    'MSK.2',
                    'MSK clusters should have enhanced monitoring configured',
                    'failed',
                    'LOW',
                    'not_available',
                    response_detail['ClusterArn']
                ))
            else:
                self.msk_list.append(self.create_msk_item(
                    'MSK.2',
                    'MSK clusters should have enhanced monitoring configured',
                    'passed',
                    'LOW',
                    'not_available',
                    response_detail['ClusterArn']
                ))

class CrossAccountMSKComplianceChecker:
    def __init__(self) -> None:
        self.kafka_client = UseCrossAccount().client('kafka')
        self.msk_list = compliance_check_list

    def create_msk_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("MSK", control_id, compliance, severity, auto_remediation):
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
    
    def kafka_cluster_list(self) -> list[dict]:
        cluster_list: list[dict] = []
        try:
            response = self.kafka_client.list_clusters()
            cluster_list.extend(_ for _ in response['ClusterInfoList'])
            while 'NextToken' in response:
                response = self.kafka_client.list_clusters(NextToken=response['NextToken'])
                cluster_list.extend(_ for _ in response['ClusterInfoList'])
            return cluster_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    @DecoratorClass.my_decorator
    def msk_one(self) -> None:
        result_list = self.kafka_cluster_list()
        if not result_list:
            self.msk_list.append(self.create_msk_item(
                'MSK.1',
                'MSK clusters should be encrypted in transit among broker nodes',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('EncryptionInfo', {}).get('EncryptionInTransit', {}).get('ClientBroker', None) == None:
                self.msk_list.append(self.create_msk_item(
                    'MSK.1',
                    'MSK clusters should be encrypted in transit among broker nodes',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ClusterArn']
                ))
            else:
                self.msk_list.append(self.create_msk_item(
                    'MSK.1',
                    'MSK clusters should be encrypted in transit among broker nodes',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ClusterArn']
                ))

    @DecoratorClass.my_decorator
    def msk_two(self) -> None:
        result_list = self.kafka_cluster_list()
        if not result_list:
            self.msk_list.append(self.create_msk_item(
                'MSK.2',
                'MSK clusters should have enhanced monitoring configured',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('EnhancedMonitoring', None) in [ None, "DEFAULT", "PER_BROKER" ]:
                self.msk_list.append(self.create_msk_item(
                    'MSK.2',
                    'MSK clusters should have enhanced monitoring configured',
                    'failed',
                    'LOW',
                    'not_available',
                    response_detail['ClusterArn']
                ))
            else:
                self.msk_list.append(self.create_msk_item(
                    'MSK.2',
                    'MSK clusters should have enhanced monitoring configured',
                    'passed',
                    'LOW',
                    'not_available',
                    response_detail['ClusterArn']
                ))