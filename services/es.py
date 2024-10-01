'''
Class name ESComplianceChecker
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

class ESComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.es_client = boto3.client('es')
        self.ec2_client = boto3.client('ec2')
        self.es_list = compliance_check_list
        self.latest_policy = "Policy-Min-TLS-1-2-PFS-2023-10"

    def create_es_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("ES", control_id, compliance, severity, auto_remediation):
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
    
    def domain_name_list(self) -> list[dict]:
        domain_list: list[dict] = []
        try:
            response = self.es_client.list_domain_names()
            domain_list.extend(_ for _ in response['DomainNames'])
            return domain_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def describe_domain_list(self) -> list[dict]:
        domain_list: list[dict] = []
        result_list = self.domain_name_list()
        result_list = [_['DomainName'] for _ in result_list]
        try:
            response = self.es_client.describe_elasticsearch_domains(DomainNames=result_list)
            domain_list.extend(_ for _ in response['DomainStatusList'])
            return domain_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def public_subnet_list(self) -> list[dict]:
        subnet_list: list[dict] = []
        public_subnet_list: list[dict] = []
        try:
            response = self.ec2_client.describe_route_tables()
            subnet_list.extend(_ for _ in response['RouteTables'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_route_tables(NextToken=response['NextToken'])
                subnet_list.extend(_ for _ in response['RouteTables'])
            for response_detail in subnet_list:
                if any([_['GatewayId'].startswith('igw-') for _ in response_detail['Routes']]):
                    public_subnet_list.append(response_detail)
            return public_subnet_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def es_tag_list(self, es_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.es_client.list_tags(ARN=es_arn)
            tag_key_list = [_['Key'] for _ in response['TagList']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
    
    @DecoratorClass.my_decorator
    def es_one(self) -> None:
        result_list = self.describe_domain_list()
        if not result_list:
            self.es_list.append(self.create_es_item(
                'ES.1',
                'Elasticsearch domains should have encryption at-rest enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('EncryptionAtRestOptions', {}).get('Enabled') != True:
                self.es_list.append(self.create_es_item(
                    'ES.1',
                    'Elasticsearch domains should have encryption at-rest enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))
            else:
                self.es_list.append(self.create_es_item(
                    'ES.1',
                    'Elasticsearch domains should have encryption at-rest enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))
    
    @DecoratorClass.my_decorator
    def es_two(self) -> None:
        result_list = self.describe_domain_list()
        public_subnet_list = self.public_subnet_list()
        if not result_list:
            self.es_list.append(self.create_es_item(
                'ES.2',
                'Elasticsearch domains should not be publicly accessible',
                'not_found',
                'CRITICAL',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if set(response_detail.get('VPCOptions', {}).get('SubnetIds')) & set([_['RouteTableId'] for _ in public_subnet_list]):
                self.es_list.append(self.create_es_item(
                    'ES.2',
                    'Elasticsearch domains should not be publicly accessible',
                    'failed',
                    'CRITICAL',
                    'not_available',
                    response_detail['ARN']
                ))
            else:
                self.es_list.append(self.create_es_item(
                    'ES.2',
                    'Elasticsearch domains should not be publicly accessible',
                    'passed',
                    'CRITICAL',
                    'not_available',
                    response_detail['ARN']
                ))
    
    @DecoratorClass.my_decorator
    def es_three(self) -> None:
        result_list = self.describe_domain_list()
        if not result_list:
            self.es_list.append(self.create_es_item(
                'ES.3',
                'Elasticsearch domains should encrypt data sent between nodes',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('NodeToNodeEncryptionOptions', {}).get('Enabled') != True:
                self.es_list.append(self.create_es_item(
                    'ES.3',
                    'Elasticsearch domains should encrypt data sent between nodes',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))
            else:
                self.es_list.append(self.create_es_item(
                    'ES.3',
                    'Elasticsearch domains should encrypt data sent between nodes',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))

    @DecoratorClass.my_decorator
    def es_four(self) -> None:
        result_list = self.describe_domain_list()
        if not result_list:
            self.es_list.append(self.create_es_item(
                'ES.4',
                'Elasticsearch domain error logging to CloudWatch Logs should be enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('LogPublishingOptions', {}).get('ES_APPLICATION_LOGS', {}).get('CloudWatchLogsLogGroupArn') == None:
                self.es_list.append(self.create_es_item(
                    'ES.4',
                    'Elasticsearch domain error logging to CloudWatch Logs should be enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))
            else:
                self.es_list.append(self.create_es_item(
                    'ES.4',
                    'Elasticsearch domain error logging to CloudWatch Logs should be enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))

    @DecoratorClass.my_decorator
    def es_five(self) -> None:
        result_list = self.describe_domain_list()
        if not result_list:
            self.es_list.append(self.create_es_item(
                'ES.5',
                'Elasticsearch domains should have audit logging enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('LogPublishingOptions', {}).get('AUDIT_LOGS', {}).get('CloudWatchLogsLogGroupArn') == None:
                self.es_list.append(self.create_es_item(
                    'ES.5',
                    'Elasticsearch domains should have audit logging enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))
            else:
                self.es_list.append(self.create_es_item(
                    'ES.5',
                    'Elasticsearch domains should have audit logging enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))

    @DecoratorClass.my_decorator
    def es_six(self) -> None:
        result_list = self.describe_domain_list()
        if not result_list:
            self.es_list.append(self.create_es_item(
                'ES.6',
                'Elasticsearch domains should have at least three data nodes',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('ElasticsearchClusterConfig', {}).get('InstanceCount') < 3:
                self.es_list.append(self.create_es_item(
                    'ES.6',
                    'Elasticsearch domains should have at least three data nodes',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))
            else:
                self.es_list.append(self.create_es_item(
                    'ES.6',
                    'Elasticsearch domains should have at least three data nodes',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))

    @DecoratorClass.my_decorator
    def es_seven(self) -> None:
        result_list = self.describe_domain_list()
        if not result_list:
            self.es_list.append(self.create_es_item(
                'ES.7',
                'Elasticsearch domains should be configured with at least three dedicated master nodes',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('ElasticsearchClusterConfig', {}).get('DedicatedMasterCount') < 3:
                self.es_list.append(self.create_es_item(
                    'ES.7',
                    'Elasticsearch domains should be configured with at least three dedicated master nodes',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))
            else:
                self.es_list.append(self.create_es_item(
                    'ES.7',
                    'Elasticsearch domains should be configured with at least three dedicated master nodes',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))

    @DecoratorClass.my_decorator
    def es_eight(self) -> None:
        result_list = self.describe_domain_list()
        if not result_list:
            self.es_list.append(self.create_es_item(
                'ES.8',
                'Connections to Elasticsearch domains should be encrypted using the latest TLS security policy',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('DomainEndpointOptions', {}).get('TLSSecurityPolicy') != self.latest_policy:
                self.es_list.append(self.create_es_item(
                    'ES.8',
                    'Connections to Elasticsearch domains should be encrypted using the latest TLS security policy',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))
            else:
                self.es_list.append(self.create_es_item(
                    'ES.8',
                    'Connections to Elasticsearch domains should be encrypted using the latest TLS security policy',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))

    @DecoratorClass.my_decorator
    def es_nine(self) -> None:
        result_list = self.describe_domain_list()
        if not result_list:
            self.es_list.append(self.create_es_item(
                'ES.9',
                'Elasticsearch domains should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.es_tag_list(response_detail['ARN'])
            self.es_list.append(self.create_es_item(
                'ES.9',
                'Elasticsearch domains should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['ARN']
            ))

class CrossAccountESComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.es_client = UseCrossAccount().client('es')
        self.ec2_client = UseCrossAccount().client('ec2')
        self.es_list = compliance_check_list
        self.latest_policy = "Policy-Min-TLS-1-2-PFS-2023-10"

    def create_es_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("ES", control_id, compliance, severity, auto_remediation):
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
    
    def domain_name_list(self) -> list[dict]:
        domain_list: list[dict] = []
        try:
            response = self.es_client.list_domain_names()
            domain_list.extend(_ for _ in response['DomainNames'])
            return domain_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def describe_domain_list(self) -> list[dict]:
        domain_list: list[dict] = []
        result_list = self.domain_name_list()
        result_list = [_['DomainName'] for _ in result_list]
        try:
            response = self.es_client.describe_elasticsearch_domains(DomainNames=result_list)
            domain_list.extend(_ for _ in response['DomainStatusList'])
            return domain_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def public_subnet_list(self) -> list[dict]:
        subnet_list: list[dict] = []
        public_subnet_list: list[dict] = []
        try:
            response = self.ec2_client.describe_route_tables()
            subnet_list.extend(_ for _ in response['RouteTables'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_route_tables(NextToken=response['NextToken'])
                subnet_list.extend(_ for _ in response['RouteTables'])
            for response_detail in subnet_list:
                if any([_['GatewayId'].startswith('igw-') for _ in response_detail['Routes']]):
                    public_subnet_list.append(response_detail)
            return public_subnet_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def es_tag_list(self, es_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.es_client.list_tags(ARN=es_arn)
            tag_key_list = [_['Key'] for _ in response['TagList']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
    
    @DecoratorClass.my_decorator
    def es_one(self) -> None:
        result_list = self.describe_domain_list()
        if not result_list:
            self.es_list.append(self.create_es_item(
                'ES.1',
                'Elasticsearch domains should have encryption at-rest enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('EncryptionAtRestOptions', {}).get('Enabled') != True:
                self.es_list.append(self.create_es_item(
                    'ES.1',
                    'Elasticsearch domains should have encryption at-rest enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))
            else:
                self.es_list.append(self.create_es_item(
                    'ES.1',
                    'Elasticsearch domains should have encryption at-rest enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))
    
    @DecoratorClass.my_decorator
    def es_two(self) -> None:
        result_list = self.describe_domain_list()
        public_subnet_list = self.public_subnet_list()
        if not result_list:
            self.es_list.append(self.create_es_item(
                'ES.2',
                'Elasticsearch domains should not be publicly accessible',
                'not_found',
                'CRITICAL',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if set(response_detail.get('VPCOptions', {}).get('SubnetIds')) & set([_['RouteTableId'] for _ in public_subnet_list]):
                self.es_list.append(self.create_es_item(
                    'ES.2',
                    'Elasticsearch domains should not be publicly accessible',
                    'failed',
                    'CRITICAL',
                    'not_available',
                    response_detail['ARN']
                ))
            else:
                self.es_list.append(self.create_es_item(
                    'ES.2',
                    'Elasticsearch domains should not be publicly accessible',
                    'passed',
                    'CRITICAL',
                    'not_available',
                    response_detail['ARN']
                ))
    
    @DecoratorClass.my_decorator
    def es_three(self) -> None:
        result_list = self.describe_domain_list()
        if not result_list:
            self.es_list.append(self.create_es_item(
                'ES.3',
                'Elasticsearch domains should encrypt data sent between nodes',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('NodeToNodeEncryptionOptions', {}).get('Enabled') != True:
                self.es_list.append(self.create_es_item(
                    'ES.3',
                    'Elasticsearch domains should encrypt data sent between nodes',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))
            else:
                self.es_list.append(self.create_es_item(
                    'ES.3',
                    'Elasticsearch domains should encrypt data sent between nodes',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))

    @DecoratorClass.my_decorator
    def es_four(self) -> None:
        result_list = self.describe_domain_list()
        if not result_list:
            self.es_list.append(self.create_es_item(
                'ES.4',
                'Elasticsearch domain error logging to CloudWatch Logs should be enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('LogPublishingOptions', {}).get('ES_APPLICATION_LOGS', {}).get('CloudWatchLogsLogGroupArn') == None:
                self.es_list.append(self.create_es_item(
                    'ES.4',
                    'Elasticsearch domain error logging to CloudWatch Logs should be enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))
            else:
                self.es_list.append(self.create_es_item(
                    'ES.4',
                    'Elasticsearch domain error logging to CloudWatch Logs should be enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))

    @DecoratorClass.my_decorator
    def es_five(self) -> None:
        result_list = self.describe_domain_list()
        if not result_list:
            self.es_list.append(self.create_es_item(
                'ES.5',
                'Elasticsearch domains should have audit logging enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('LogPublishingOptions', {}).get('AUDIT_LOGS', {}).get('CloudWatchLogsLogGroupArn') == None:
                self.es_list.append(self.create_es_item(
                    'ES.5',
                    'Elasticsearch domains should have audit logging enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))
            else:
                self.es_list.append(self.create_es_item(
                    'ES.5',
                    'Elasticsearch domains should have audit logging enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))

    @DecoratorClass.my_decorator
    def es_six(self) -> None:
        result_list = self.describe_domain_list()
        if not result_list:
            self.es_list.append(self.create_es_item(
                'ES.6',
                'Elasticsearch domains should have at least three data nodes',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('ElasticsearchClusterConfig', {}).get('InstanceCount') < 3:
                self.es_list.append(self.create_es_item(
                    'ES.6',
                    'Elasticsearch domains should have at least three data nodes',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))
            else:
                self.es_list.append(self.create_es_item(
                    'ES.6',
                    'Elasticsearch domains should have at least three data nodes',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))

    @DecoratorClass.my_decorator
    def es_seven(self) -> None:
        result_list = self.describe_domain_list()
        if not result_list:
            self.es_list.append(self.create_es_item(
                'ES.7',
                'Elasticsearch domains should be configured with at least three dedicated master nodes',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('ElasticsearchClusterConfig', {}).get('DedicatedMasterCount') < 3:
                self.es_list.append(self.create_es_item(
                    'ES.7',
                    'Elasticsearch domains should be configured with at least three dedicated master nodes',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))
            else:
                self.es_list.append(self.create_es_item(
                    'ES.7',
                    'Elasticsearch domains should be configured with at least three dedicated master nodes',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))

    @DecoratorClass.my_decorator
    def es_eight(self) -> None:
        result_list = self.describe_domain_list()
        if not result_list:
            self.es_list.append(self.create_es_item(
                'ES.8',
                'Connections to Elasticsearch domains should be encrypted using the latest TLS security policy',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('DomainEndpointOptions', {}).get('TLSSecurityPolicy') != self.latest_policy:
                self.es_list.append(self.create_es_item(
                    'ES.8',
                    'Connections to Elasticsearch domains should be encrypted using the latest TLS security policy',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))
            else:
                self.es_list.append(self.create_es_item(
                    'ES.8',
                    'Connections to Elasticsearch domains should be encrypted using the latest TLS security policy',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))

    @DecoratorClass.my_decorator
    def es_nine(self) -> None:
        result_list = self.describe_domain_list()
        if not result_list:
            self.es_list.append(self.create_es_item(
                'ES.9',
                'Elasticsearch domains should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.es_tag_list(response_detail['ARN'])
            self.es_list.append(self.create_es_item(
                'ES.9',
                'Elasticsearch domains should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['ARN']
            ))