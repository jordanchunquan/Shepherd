'''
Class name MQComplianceChecker
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

class MQComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.mq_client = boto3.client('mq')
        self.mq_list = compliance_check_list

    def create_mq_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("MQ", control_id, compliance, severity, auto_remediation):
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
    
    def mq_broker_list(self) -> list[dict]:
        broker_list: list[dict] = []
        try:
            broker_response = self.mq_client.list_brokers()
            for broker in broker_response['BrokerSummaries']:
                response = self.mq_client.describe_broker(BrokerId=broker['BrokerId'])
                broker_list.append(response)
            while 'NextToken' in broker_response:
                broker_response = self.mq_client.list_brokers(NextToken=broker_response['NextToken'])
                for broker in broker_response['BrokerSummaries']:
                    response = self.mq_client.describe_broker(BrokerId=broker['BrokerId'])
                    broker_list.append(response)
            return broker_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def mq_tag_compliant(self, broker_id: str) -> str:
        try:
            compliant_status = "passed"
            response = self.mq_client.list_tags(ResourceArn=broker_id)
            tag_key_list = [tag['Key'] for tag in response['Tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
    
    @DecoratorClass.my_decorator
    def mq_two(self) -> None:
        result_list = self.mq_broker_list()
        if not result_list:
            self.mq_list.append(self.create_mq_item(
                'MQ.2',
                'ActiveMQ brokers should stream audit logs to CloudWatch',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('Logs', {}).get('Audit') != True:
                self.mq_list.append(self.create_mq_item(
                    'MQ.2',
                    'ActiveMQ brokers should stream audit logs to CloudWatch',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['BrokerArn']
                ))
            else:
                self.mq_list.append(self.create_mq_item(
                    'MQ.2',
                    'ActiveMQ brokers should stream audit logs to CloudWatch',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['BrokerArn']
                ))

    @DecoratorClass.my_decorator
    def mq_three(self) -> None:
        result_list = self.mq_broker_list()
        if not result_list:
            self.mq_list.append(self.create_mq_item(
                'MQ.3',
                'Amazon MQ brokers should have automatic minor version upgrade enabled',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('AutoMinorVersionUpgrade') != True:
                self.mq_list.append(self.create_mq_item(
                    'MQ.3',
                    'Amazon MQ brokers should have automatic minor version upgrade enabled',
                    'failed',
                    'LOW',
                    'not_available',
                    response_detail['BrokerArn']
                ))
            else:
                self.mq_list.append(self.create_mq_item(
                    'MQ.3',
                    'Amazon MQ brokers should have automatic minor version upgrade enabled',
                    'passed',
                    'LOW',
                    'not_available',
                    response_detail['BrokerArn']
                ))

    @DecoratorClass.my_decorator
    def mq_four(self) -> None:
        result_list = self.mq_broker_list()
        if not result_list:
            self.mq_list.append(self.create_mq_item(
                'MQ.4',
                'Amazon MQ brokers should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            complaint_status = self.mq_tag_compliant(response_detail['BrokerArn'])
            self.mq_list.append(self.create_mq_item(
                'MQ.4',
                'Amazon MQ brokers should be tagged',
                complaint_status,
                'LOW',
                'not_available',
                response_detail['BrokerArn']
            ))

    @DecoratorClass.my_decorator
    def mq_five(self) -> None:
        result_list = self.mq_broker_list()
        if not result_list:
            self.mq_list.append(self.create_mq_item(
                'MQ.5',
                'ActiveMQ brokers should use active/standby deployment mode',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('DeploymentMode') not in [ "ACTIVE_STANDBY_MULTI_AZ", "CLUSTER_MULTI_AZ" ]:
                self.mq_list.append(self.create_mq_item(
                    'MQ.5',
                    'ActiveMQ brokers should use active/standby deployment mode',
                    'failed',
                    'LOW',
                    'not_available',
                    response_detail['BrokerArn']
                ))
            else:
                self.mq_list.append(self.create_mq_item(
                    'MQ.5',
                    'ActiveMQ brokers should use active/standby deployment mode',
                    'passed',
                    'LOW',
                    'not_available',
                    response_detail['BrokerArn']
                ))

    @DecoratorClass.my_decorator
    def mq_six(self) -> None:
        result_list = self.mq_broker_list()
        if not result_list:
            self.mq_list.append(self.create_mq_item(
                'MQ.6',
                'RabbitMQ brokers should use cluster deployment mode',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('DeploymentMode') not in [ "ACTIVE_STANDBY_MULTI_AZ", "CLUSTER_MULTI_AZ" ]:
                self.mq_list.append(self.create_mq_item(
                    'MQ.6',
                    'RabbitMQ brokers should use cluster deployment mode',
                    'failed',
                    'LOW',
                    'not_available',
                    response_detail['BrokerArn']
                ))
            else:
                self.mq_list.append(self.create_mq_item(
                    'MQ.6',
                    'RabbitMQ brokers should use cluster deployment mode',
                    'passed',
                    'LOW',
                    'not_available',
                    response_detail['BrokerArn']
                ))

class CrossAccountMQComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.mq_client = UseCrossAccount().client('mq')
        self.mq_list = compliance_check_list

    def create_mq_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("MQ", control_id, compliance, severity, auto_remediation):
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
    
    def mq_broker_list(self) -> list[dict]:
        broker_list: list[dict] = []
        try:
            broker_response = self.mq_client.list_brokers()
            for broker in broker_response['BrokerSummaries']:
                response = self.mq_client.describe_broker(BrokerId=broker['BrokerId'])
                broker_list.append(response)
            while 'NextToken' in broker_response:
                broker_response = self.mq_client.list_brokers(NextToken=broker_response['NextToken'])
                for broker in broker_response['BrokerSummaries']:
                    response = self.mq_client.describe_broker(BrokerId=broker['BrokerId'])
                    broker_list.append(response)
            return broker_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def mq_tag_compliant(self, broker_id: str) -> str:
        try:
            compliant_status = "passed"
            response = self.mq_client.list_tags(ResourceArn=broker_id)
            tag_key_list = [tag['Key'] for tag in response['Tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
    
    @DecoratorClass.my_decorator
    def mq_two(self) -> None:
        result_list = self.mq_broker_list()
        if not result_list:
            self.mq_list.append(self.create_mq_item(
                'MQ.2',
                'ActiveMQ brokers should stream audit logs to CloudWatch',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('Logs', {}).get('Audit') != True:
                self.mq_list.append(self.create_mq_item(
                    'MQ.2',
                    'ActiveMQ brokers should stream audit logs to CloudWatch',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['BrokerArn']
                ))
            else:
                self.mq_list.append(self.create_mq_item(
                    'MQ.2',
                    'ActiveMQ brokers should stream audit logs to CloudWatch',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['BrokerArn']
                ))

    @DecoratorClass.my_decorator
    def mq_three(self) -> None:
        result_list = self.mq_broker_list()
        if not result_list:
            self.mq_list.append(self.create_mq_item(
                'MQ.3',
                'Amazon MQ brokers should have automatic minor version upgrade enabled',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('AutoMinorVersionUpgrade') != True:
                self.mq_list.append(self.create_mq_item(
                    'MQ.3',
                    'Amazon MQ brokers should have automatic minor version upgrade enabled',
                    'failed',
                    'LOW',
                    'not_available',
                    response_detail['BrokerArn']
                ))
            else:
                self.mq_list.append(self.create_mq_item(
                    'MQ.3',
                    'Amazon MQ brokers should have automatic minor version upgrade enabled',
                    'passed',
                    'LOW',
                    'not_available',
                    response_detail['BrokerArn']
                ))

    @DecoratorClass.my_decorator
    def mq_four(self) -> None:
        result_list = self.mq_broker_list()
        if not result_list:
            self.mq_list.append(self.create_mq_item(
                'MQ.4',
                'Amazon MQ brokers should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            complaint_status = self.mq_tag_compliant(response_detail['BrokerArn'])
            self.mq_list.append(self.create_mq_item(
                'MQ.4',
                'Amazon MQ brokers should be tagged',
                complaint_status,
                'LOW',
                'not_available',
                response_detail['BrokerArn']
            ))

    @DecoratorClass.my_decorator
    def mq_five(self) -> None:
        result_list = self.mq_broker_list()
        if not result_list:
            self.mq_list.append(self.create_mq_item(
                'MQ.5',
                'ActiveMQ brokers should use active/standby deployment mode',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('DeploymentMode') not in [ "ACTIVE_STANDBY_MULTI_AZ", "CLUSTER_MULTI_AZ" ]:
                self.mq_list.append(self.create_mq_item(
                    'MQ.5',
                    'ActiveMQ brokers should use active/standby deployment mode',
                    'failed',
                    'LOW',
                    'not_available',
                    response_detail['BrokerArn']
                ))
            else:
                self.mq_list.append(self.create_mq_item(
                    'MQ.5',
                    'ActiveMQ brokers should use active/standby deployment mode',
                    'passed',
                    'LOW',
                    'not_available',
                    response_detail['BrokerArn']
                ))

    @DecoratorClass.my_decorator
    def mq_six(self) -> None:
        result_list = self.mq_broker_list()
        if not result_list:
            self.mq_list.append(self.create_mq_item(
                'MQ.6',
                'RabbitMQ brokers should use cluster deployment mode',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('DeploymentMode') not in [ "ACTIVE_STANDBY_MULTI_AZ", "CLUSTER_MULTI_AZ" ]:
                self.mq_list.append(self.create_mq_item(
                    'MQ.6',
                    'RabbitMQ brokers should use cluster deployment mode',
                    'failed',
                    'LOW',
                    'not_available',
                    response_detail['BrokerArn']
                ))
            else:
                self.mq_list.append(self.create_mq_item(
                    'MQ.6',
                    'RabbitMQ brokers should use cluster deployment mode',
                    'passed',
                    'LOW',
                    'not_available',
                    response_detail['BrokerArn']
                ))