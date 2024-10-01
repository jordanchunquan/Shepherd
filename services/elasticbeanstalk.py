'''
Class name ElasticBeanstalkComplianceChecker
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

class ElasticBeanstalkComplianceChecker:
    def __init__(self) -> None:
        self.elastic_beanstalk_client = boto3.client('elasticbeanstalk')
        self.elasticbeanstalk_list = compliance_check_list

    def create_elasticbeanstalk_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("ElasticBeanstalk", control_id, compliance, severity, auto_remediation):
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
    
    def elasticbeanstalk_environment_list(self) -> list[dict]:
        environment_list: list[dict] = []
        try:
            response = self.elastic_beanstalk_client.describe_environments()
            environment_list.extend(_ for _ in response['Environments'])
            while 'NextToken' in response:
                response = self.elastic_beanstalk_client.describe_environments(NextToken=response['NextToken'])
                environment_list.extend(_ for _ in response['Environments'])
            return environment_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def elasticbeanstalk_health_report_configuration_setting(self, application_name: str, environment_name: str) -> str:
        try:
            compliant_status = "passed"
            response = self.elastic_beanstalk_client.describe_configuration_settings(ApplicationName=application_name, EnvironmentName=environment_name)
            for response_detail in response['ConfigurationSettings']:
                if not any([_['OptionName'] == 'SystemType' and _['Namespace'] == 'aws:elasticbeanstalk:healthreporting' for _ in response_detail['OptionSettings']]):
                    compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
    
    def elasticbeanstalk_managed_action_list(self, environment_name: str) -> str:
        try:
            compliant_status = "passed"
            managed_action_list: list[dict] = []
            response = self.elastic_beanstalk_client.describe_environment_managed_actions(EnvironmentName=environment_name)
            managed_action_list.extend(_['ActionType'] for _ in response['ManagedActions'])
            while 'NextToken' in response:
                response = self.elastic_beanstalk_client.describe_environment_managed_actions(EnvironmentName=environment_name, NextToken=response['NextToken'])
                managed_action_list.extend(_['ActionType'] for _ in response['ManagedActions'])
            if "PlatformUpdate" not in managed_action_list:
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        
    def elasticbeanstalk_stream_log_configuration_setting(self, application_name: str, environment_name: str) -> str:
        try:
            compliant_status = "passed"
            response = self.elastic_beanstalk_client.describe_configuration_settings(ApplicationName=application_name, EnvironmentName=environment_name)
            for response_detail in response['ConfigurationSettings']:
                if not any([_['OptionName'] == 'ProxyLogGroup' and _['Namespace'] == 'aws:elasticbeanstalk:proxy' for _ in response_detail['OptionSettings']]):
                    compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
    
    @DecoratorClass.my_decorator
    def elasticbeanstalk_one(self) -> None:
        result_list = self.elasticbeanstalk_environment_list()
        if not result_list:
            self.elasticbeanstalk_list.append(self.create_elasticbeanstalk_item(
                'ElasticBeanstalk.1',
                'Elastic Beanstalk environments should have enhanced health reporting enabled',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.elasticbeanstalk_health_report_configuration_setting(response_detail['ApplicationName'], response_detail['EnvironmentName'])
            self.elasticbeanstalk_list.append(self.create_elasticbeanstalk_item(
                'ElasticBeanstalk.1',
                'Elastic Beanstalk environments should have enhanced health reporting enabled',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['EnvironmentId']
            ))
    
    @DecoratorClass.my_decorator
    def elasticbeanstalk_two(self) -> None:
        result_list = self.elasticbeanstalk_environment_list()
        if not result_list:
            self.elasticbeanstalk_list.append(self.create_elasticbeanstalk_item(
                'ElasticBeanstalk.2',
                'Elastic Beanstalk managed platform updates should be enabled',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.elasticbeanstalk_managed_action_list(response_detail['EnvironmentName'])
            self.elasticbeanstalk_list.append(self.create_elasticbeanstalk_item(
                'ElasticBeanstalk.2',
                'Elastic Beanstalk managed platform updates should be enabled',
                compliant_status,
                'HIGH',
                'not_available',
                response_detail['EnvironmentId']
            ))
    
    @DecoratorClass.my_decorator
    def elasticbeanstalk_three(self) -> None:
        result_list = self.elasticbeanstalk_environment_list()
        if not result_list:
            self.elasticbeanstalk_list.append(self.create_elasticbeanstalk_item(
                'ElasticBeanstalk.3',
                'Elastic Beanstalk should stream logs to CloudWatch',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.elasticbeanstalk_stream_log_configuration_setting(response_detail['ApplicationName'], response_detail['EnvironmentName'])
            self.elasticbeanstalk_list.append(self.create_elasticbeanstalk_item(
                'ElasticBeanstalk.3',
                'Elastic Beanstalk should stream logs to CloudWatch',
                compliant_status,
                'HIGH',
                'not_available',
                response_detail['EnvironmentId']
            ))

class CrossAccountElasticBeanstalkComplianceChecker:
    def __init__(self) -> None:
        self.elastic_beanstalk_client = UseCrossAccount().client('elasticbeanstalk')
        self.elasticbeanstalk_list = compliance_check_list

    def create_elasticbeanstalk_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("ElasticBeanstalk", control_id, compliance, severity, auto_remediation):
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
    
    def elasticbeanstalk_environment_list(self) -> list[dict]:
        environment_list: list[dict] = []
        try:
            response = self.elastic_beanstalk_client.describe_environments()
            environment_list.extend(_ for _ in response['Environments'])
            while 'NextToken' in response:
                response = self.elastic_beanstalk_client.describe_environments(NextToken=response['NextToken'])
                environment_list.extend(_ for _ in response['Environments'])
            return environment_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def elasticbeanstalk_health_report_configuration_setting(self, application_name: str, environment_name: str) -> str:
        try:
            compliant_status = "passed"
            response = self.elastic_beanstalk_client.describe_configuration_settings(ApplicationName=application_name, EnvironmentName=environment_name)
            for response_detail in response['ConfigurationSettings']:
                if not any([_['OptionName'] == 'SystemType' and _['Namespace'] == 'aws:elasticbeanstalk:healthreporting' for _ in response_detail['OptionSettings']]):
                    compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
    
    def elasticbeanstalk_managed_action_list(self, environment_name: str) -> str:
        try:
            compliant_status = "passed"
            managed_action_list: list[dict] = []
            response = self.elastic_beanstalk_client.describe_environment_managed_actions(EnvironmentName=environment_name)
            managed_action_list.extend(_['ActionType'] for _ in response['ManagedActions'])
            while 'NextToken' in response:
                response = self.elastic_beanstalk_client.describe_environment_managed_actions(EnvironmentName=environment_name, NextToken=response['NextToken'])
                managed_action_list.extend(_['ActionType'] for _ in response['ManagedActions'])
            if "PlatformUpdate" not in managed_action_list:
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        
    def elasticbeanstalk_stream_log_configuration_setting(self, application_name: str, environment_name: str) -> str:
        try:
            compliant_status = "passed"
            response = self.elastic_beanstalk_client.describe_configuration_settings(ApplicationName=application_name, EnvironmentName=environment_name)
            for response_detail in response['ConfigurationSettings']:
                if not any([_['OptionName'] == 'ProxyLogGroup' and _['Namespace'] == 'aws:elasticbeanstalk:proxy' for _ in response_detail['OptionSettings']]):
                    compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
    
    @DecoratorClass.my_decorator
    def elasticbeanstalk_one(self) -> None:
        result_list = self.elasticbeanstalk_environment_list()
        if not result_list:
            self.elasticbeanstalk_list.append(self.create_elasticbeanstalk_item(
                'ElasticBeanstalk.1',
                'Elastic Beanstalk environments should have enhanced health reporting enabled',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.elasticbeanstalk_health_report_configuration_setting(response_detail['ApplicationName'], response_detail['EnvironmentName'])
            self.elasticbeanstalk_list.append(self.create_elasticbeanstalk_item(
                'ElasticBeanstalk.1',
                'Elastic Beanstalk environments should have enhanced health reporting enabled',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['EnvironmentId']
            ))
    
    @DecoratorClass.my_decorator
    def elasticbeanstalk_two(self) -> None:
        result_list = self.elasticbeanstalk_environment_list()
        if not result_list:
            self.elasticbeanstalk_list.append(self.create_elasticbeanstalk_item(
                'ElasticBeanstalk.2',
                'Elastic Beanstalk managed platform updates should be enabled',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.elasticbeanstalk_managed_action_list(response_detail['EnvironmentName'])
            self.elasticbeanstalk_list.append(self.create_elasticbeanstalk_item(
                'ElasticBeanstalk.2',
                'Elastic Beanstalk managed platform updates should be enabled',
                compliant_status,
                'HIGH',
                'not_available',
                response_detail['EnvironmentId']
            ))
    
    @DecoratorClass.my_decorator
    def elasticbeanstalk_three(self) -> None:
        result_list = self.elasticbeanstalk_environment_list()
        if not result_list:
            self.elasticbeanstalk_list.append(self.create_elasticbeanstalk_item(
                'ElasticBeanstalk.3',
                'Elastic Beanstalk should stream logs to CloudWatch',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.elasticbeanstalk_stream_log_configuration_setting(response_detail['ApplicationName'], response_detail['EnvironmentName'])
            self.elasticbeanstalk_list.append(self.create_elasticbeanstalk_item(
                'ElasticBeanstalk.3',
                'Elastic Beanstalk should stream logs to CloudWatch',
                compliant_status,
                'HIGH',
                'not_available',
                response_detail['EnvironmentId']
            ))