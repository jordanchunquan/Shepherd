'''
Class name DMSComplianceChecker
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

class DMSComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.dms_client = boto3.client('dms')
        self.session_account = boto3.client('sts').get_caller_identity().get('Account')
        self.dms_list = compliance_check_list

    def create_dms_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("DMS", control_id, compliance, severity, auto_remediation):
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
    
    def dms_instance_list(self) -> list[dict]:
        dms_list: list[dict] = []
        try:
            response = self.dms_client.describe_replication_instances()
            dms_list.extend(_ for _ in response['ReplicationInstances'])
            while 'Marker' in response:
                response = self.dms_client.describe_replication_instances(Marker=response['Marker'])
                dms_list.extend(_ for _ in response['ReplicationInstances'])
        except ClientError as e:
            print(f"Error: {e}")
        return dms_list
    
    def dms_task_list(self) -> list[dict]:
        dms_list: list[dict] = []
        try:
            response = self.dms_client.describe_replication_tasks()
            dms_list.extend(_ for _ in response['ReplicationTasks'])
            while 'Marker' in response:
                response = self.dms_client.describe_replication_tasks(Marker=response['Marker'])
                dms_list.extend(_ for _ in response['ReplicationTasks'])
        except ClientError as e:
            print(f"Error: {e}")
        return dms_list
    
    def logging_enabled_task_list(self) -> list[str]:
        dms_list: list[str] = []
        result_list = self.dms_instance_list()
        for response in result_list:
            instance_arn = response['ReplicationInstanceArn']
            try:
                log_response = self.dms_client.describe_replication_instance_task_logs(
                    ReplicationInstanceArn=instance_arn
                )
                for _ in log_response['ReplicationInstanceTaskLogs']:
                    dms_list.append(_['ReplicationTaskArn'])
                while 'Marker' in log_response:
                    log_response = self.dms_client.describe_replication_instance_task_logs(
                        ReplicationInstanceArn=instance_arn,
                        Marker=log_response['Marker']
                    )
                    for _ in log_response['ReplicationInstanceTaskLogs']:
                        dms_list.append(_['ReplicationTaskArn'])
            except ClientError as e:
                print(f"Error: {e}")
        return dms_list
    
    def dms_endpoint_list(self) -> list[dict]:
        dms_list: list[dict] = []
        try:
            response = self.dms_client.describe_endpoints()
            dms_list.extend(_ for _ in response['Endpoints'])
            while 'Marker' in response:
                response = self.dms_client.describe_endpoints(Marker=response['Marker'])
                dms_list.extend(_ for _ in response['Endpoints'])
        except ClientError as e:
            print(f"Error: {e}")
        return dms_list
    
    def dms_certificate_list(self) -> list[dict]:
        certificate_list: list[dict] = []
        try:
            response = self.dms_client.describe_certificates()
            certificate_list.extend(_ for _ in response['Certificates'])
            while 'Marker' in response:
                response = self.dms_client.describe_certificates(Marker=response['Marker'])
                certificate_list.extend(_ for _ in response['Certificates'])
        except ClientError as e:
            print(f"Error: {e}")
        return certificate_list
    
    def dms_event_subscription_list(self) -> list[dict]:
        event_subscription_list: list[dict] = []
        try:
            response = self.dms_client.describe_event_subscriptions()
            event_subscription_list.extend(_ for _ in response['EventSubscriptionsList'])
            while 'Marker' in response:
                response = self.dms_client.describe_event_subscriptions(Marker=response['Marker'])
                event_subscription_list.extend(_ for _ in response['EventSubscriptionsList'])
        except ClientError as e:
            print(f"Error: {e}")
        return event_subscription_list
    
    def dms_replication_instance_list(self) -> list[dict]:
        replication_instance_list: list[dict] = []
        try:
            response = self.dms_client.describe_replication_instances()
            replication_instance_list.extend(_ for _ in response['ReplicationInstances'])
            while 'Marker' in response:
                response = self.dms_client.describe_replication_instances(Marker=response['Marker'])
                replication_instance_list.extend(_ for _ in response['ReplicationInstances'])
        except ClientError as e:
            print(f"Error: {e}")
        return replication_instance_list
    
    def dms_replication_subnet_group_list(self) -> list[dict]:
        replication_subnet_group_list: list[dict] = []
        try:
            response = self.dms_client.describe_replication_subnet_groups()
            replication_subnet_group_list.extend(_ for _ in response['ReplicationSubnetGroups'])
            while 'Marker' in response:
                response = self.dms_client.describe_replication_subnet_groups(Marker=response['Marker'])
                replication_subnet_group_list.extend(_ for _ in response['ReplicationSubnetGroups'])
        except ClientError as e:
            print(f"Error: {e}")
        return replication_subnet_group_list
    
    def dms_neptune_database_endpoint_list(self) -> list[dict]:
        result_list = self.dms_endpoint_list()
        return [_ for _ in result_list if _['EngineName'] == 'neptune']
    
    def dms_mongodb_database_endpoint_list(self) -> list[dict]:
        result_list = self.dms_endpoint_list()
        return [_ for _ in result_list if _['EngineName'] == 'mongodb']
    
    def dms_redis_database_endpoint_list(self) -> list[dict]:
        result_list = self.dms_endpoint_list()
        return [_ for _ in result_list if _['EngineName'] == 'redshift']
    
    def dms_tag_list(self, dms_resourse_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.dms_client.list_tags_for_resource(
                ResourceArn=dms_resourse_arn
            )
            tag_key_list = [tag['Key'] for tag in response['TagList']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""

    @DecoratorClass.my_decorator
    def dms_one(self) -> None:
        result_list = self.dms_instance_list()
        if not result_list:
            self.dms_list.append(self.create_dms_item(
                'DMS.1',
                'Database Migration Service replication instances should not be public',
                'not_found',
                'CRITICAL',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if response['PubliclyAccessible'] == True:
                self.dms_list.append(self.create_dms_item(
                    'DMS.1',
                    'Database Migration Service replication instances should not be public',
                    'failed',
                    'CRITICAL',
                    'not_available',
                    response['ReplicationInstanceArn']
                ))
            else:
                self.dms_list.append(self.create_dms_item(
                    'DMS.1',
                    'Database Migration Service replication instances should not be public',
                    'passed',
                    'CRITICAL',
                    'not_available',
                    response['ReplicationInstanceArn']
                ))

    @DecoratorClass.my_decorator
    def dms_two(self) -> None:
        result_list = self.dms_certificate_list()
        if not result_list:
            self.dms_list.append(self.create_dms_item(
                'DMS.2',
                'DMS certificates should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            compliant_status = self.dms_tag_list(response['CertificateArn'])
            self.dms_list.append(self.create_dms_item(
                'DMS.2',
                'DMS certificates should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response['CertificateArn']
            ))

    @DecoratorClass.my_decorator
    def dms_three(self) -> None:
        result_list = self.dms_event_subscription_list()
        if not result_list:
            self.dms_list.append(self.create_dms_item(
                'DMS.3',
                'DMS event subscriptions should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            compliant_status = self.dms_tag_list(response['CustSubscriptionId'])
            self.dms_list.append(self.create_dms_item(
                'DMS.3',
                'DMS event subscriptions should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response['CustSubscriptionId']
            ))

    @DecoratorClass.my_decorator
    def dms_four(self) -> None:
        result_list = self.dms_replication_instance_list()
        if not result_list:
            self.dms_list.append(self.create_dms_item(
                'DMS.4',
                'DMS replication instances should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            compliant_status = self.dms_tag_list(response['ReplicationInstanceArn'])
            self.dms_list.append(self.create_dms_item(
                'DMS.4',
                'DMS replication instances should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response['ReplicationInstanceArn']
            ))

    @DecoratorClass.my_decorator
    def dms_five(self) -> None:
        result_list = self.dms_replication_instance_list()
        if not result_list:
            self.dms_list.append(self.create_dms_item(
                'DMS.5',
                'DMS replication subnet groups should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            compliant_status = self.dms_tag_list(response['ReplicationSubnetGroupIdentifier'])
            self.dms_list.append(self.create_dms_item(
                'DMS.5',
                'DMS replication subnet groups should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response['ReplicationSubnetGroupIdentifier']
            ))

    @DecoratorClass.my_decorator
    def dms_six(self) -> None:
        result_list = self.dms_instance_list()
        if not result_list:
            self.dms_list.append(self.create_dms_item(
                'DMS.6',
                'DMS replication instances should have automatic minor version upgrade enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if response['AutoMinorVersionUpgrade'] != True:
                self.dms_list.append(self.create_dms_item(
                    'DMS.6',
                    'DMS replication instances should have automatic minor version upgrade enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response['ReplicationInstanceArn']
                ))
            else:
                self.dms_list.append(self.create_dms_item(
                    'DMS.6',
                    'DMS replication instances should have automatic minor version upgrade enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response['ReplicationInstanceArn']
                ))

    @DecoratorClass.my_decorator
    def dms_seven(self) -> None:
        logging_enabled_task_list = self.logging_enabled_task_list()
        result_list = self.dms_task_list()
        if not result_list:
            self.dms_list.append(self.create_dms_item(
                'DMS.7',
                'DMS replication tasks for the target database should have logging enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if response['ReplicationTaskArn'] not in logging_enabled_task_list:
                self.dms_list.append(self.create_dms_item(
                    'DMS.7',
                    'DMS replication tasks for the target database should have logging enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response['TargetEndpointArn']
                ))
            else:
                self.dms_list.append(self.create_dms_item(
                    'DMS.7',
                    'DMS replication tasks for the target database should have logging enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response['TargetEndpointArn']
                ))

    @DecoratorClass.my_decorator
    def dms_eight(self) -> None:
        logging_enabled_task_list = self.logging_enabled_task_list()
        result_list = self.dms_task_list()
        if not result_list:
            self.dms_list.append(self.create_dms_item(
                'DMS.8',
                'DMS replication tasks for the source database should have logging enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if response['ReplicationTaskArn'] not in logging_enabled_task_list:
                self.dms_list.append(self.create_dms_item(
                    'DMS.8',
                    'DMS replication tasks for the source database should have logging enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response['SourceEndpointArn']
                ))
            else:
                self.dms_list.append(self.create_dms_item(
                    'DMS.8',
                    'DMS replication tasks for the source database should have logging enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response['SourceEndpointArn']
                ))

    @DecoratorClass.my_decorator
    def dms_nine(self) -> None:
        result_list = self.dms_endpoint_list()
        if not result_list:
            self.dms_list.append(self.create_dms_item(
                'DMS.9',
                'DMS endpoints should use SSL',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if response['SslMode'] == 'none':
                self.dms_list.append(self.create_dms_item(
                    'DMS.9',
                    'DMS endpoints should use SSL',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response['EndpointArn']
                ))
            else:
                self.dms_list.append(self.create_dms_item(
                    'DMS.9',
                    'DMS endpoints should use SSL',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response['EndpointArn']
                ))

    @DecoratorClass.my_decorator
    def dms_ten(self) -> None:
        result_list = self.dms_neptune_database_endpoint_list()
        if not result_list:
            self.dms_list.append(self.create_dms_item(
                'DMS.10',
                'DMS endpoints for Neptune databases should have IAM authorization enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if response.get('NeptuneSettings', {}).get('IAMAuthEnabled') != True:
                self.dms_list.append(self.create_dms_item(
                    'DMS.10',
                    'DMS endpoints for Neptune databases should have IAM authorization enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response['EndpointArn']
                ))
            else:
                self.dms_list.append(self.create_dms_item(
                    'DMS.10',
                    'DMS endpoints for Neptune databases should have IAM authorization enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response['EndpointArn']
                ))

    @DecoratorClass.my_decorator
    def dms_eleven(self) -> None:
        result_list = self.dms_mongodb_database_endpoint_list()
        if not result_list:
            self.dms_list.append(self.create_dms_item(
                'DMS.11',
                'DMS endpoints for MongoDB should have an authentication mechanism enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if all([response.get('MongoDbSettings', {}).get('AuthMechanism') != "mongodb_cr", \
                response.get('MongoDbSettings', {}).get('AuthMechanism') != "scram_sha_1"]):
                self.dms_list.append(self.create_dms_item(
                    'DMS.11',
                    'DMS endpoints for MongoDB should have an authentication mechanism enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response['EndpointArn']
                ))
            else:
                self.dms_list.append(self.create_dms_item(
                    'DMS.11',
                    'DMS endpoints for MongoDB should have an authentication mechanism enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response['EndpointArn']
                ))

    @DecoratorClass.my_decorator
    def dms_twelve(self) -> None:
        result_list = self.dms_redis_database_endpoint_list()
        if not result_list:
            self.dms_list.append(self.create_dms_item(
                'DMS.12',
                'DMS endpoints for Redis should have TLS enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if all([response.get('RedshiftSettings', {}).get('EncryptionMode') != "sse-s3", \
                response.get('RedshiftSettings', {}).get('EncryptionMode') != "sse-kms"]):
                self.dms_list.append(self.create_dms_item(
                    'DMS.12',
                    'DMS endpoints for Redis should have TLS enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response['EndpointArn']
                ))
            else:
                self.dms_list.append(self.create_dms_item(
                    'DMS.12',
                    'DMS endpoints for Redis should have TLS enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response['EndpointArn']
                ))

class CrossAccountDMSComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.dms_client = UseCrossAccount().client('dms')
        self.session_account = UseCrossAccount().client('sts').get_caller_identity().get('Account')
        self.dms_list = compliance_check_list

    def create_dms_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("DMS", control_id, compliance, severity, auto_remediation):
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
    
    def dms_instance_list(self) -> list[dict]:
        dms_list: list[dict] = []
        try:
            response = self.dms_client.describe_replication_instances()
            dms_list.extend(_ for _ in response['ReplicationInstances'])
            while 'Marker' in response:
                response = self.dms_client.describe_replication_instances(Marker=response['Marker'])
                dms_list.extend(_ for _ in response['ReplicationInstances'])
        except ClientError as e:
            print(f"Error: {e}")
        return dms_list
    
    def dms_task_list(self) -> list[dict]:
        dms_list: list[dict] = []
        try:
            response = self.dms_client.describe_replication_tasks()
            dms_list.extend(_ for _ in response['ReplicationTasks'])
            while 'Marker' in response:
                response = self.dms_client.describe_replication_tasks(Marker=response['Marker'])
                dms_list.extend(_ for _ in response['ReplicationTasks'])
        except ClientError as e:
            print(f"Error: {e}")
        return dms_list
    
    def logging_enabled_task_list(self) -> list[str]:
        dms_list: list[str] = []
        result_list = self.dms_instance_list()
        for response in result_list:
            instance_arn = response['ReplicationInstanceArn']
            try:
                log_response = self.dms_client.describe_replication_instance_task_logs(
                    ReplicationInstanceArn=instance_arn
                )
                for _ in log_response['ReplicationInstanceTaskLogs']:
                    dms_list.append(_['ReplicationTaskArn'])
                while 'Marker' in log_response:
                    log_response = self.dms_client.describe_replication_instance_task_logs(
                        ReplicationInstanceArn=instance_arn,
                        Marker=log_response['Marker']
                    )
                    for _ in log_response['ReplicationInstanceTaskLogs']:
                        dms_list.append(_['ReplicationTaskArn'])
            except ClientError as e:
                print(f"Error: {e}")
        return dms_list
    
    def dms_endpoint_list(self) -> list[dict]:
        dms_list: list[dict] = []
        try:
            response = self.dms_client.describe_endpoints()
            dms_list.extend(_ for _ in response['Endpoints'])
            while 'Marker' in response:
                response = self.dms_client.describe_endpoints(Marker=response['Marker'])
                dms_list.extend(_ for _ in response['Endpoints'])
        except ClientError as e:
            print(f"Error: {e}")
        return dms_list
    
    def dms_certificate_list(self) -> list[dict]:
        certificate_list: list[dict] = []
        try:
            response = self.dms_client.describe_certificates()
            certificate_list.extend(_ for _ in response['Certificates'])
            while 'Marker' in response:
                response = self.dms_client.describe_certificates(Marker=response['Marker'])
                certificate_list.extend(_ for _ in response['Certificates'])
        except ClientError as e:
            print(f"Error: {e}")
        return certificate_list
    
    def dms_event_subscription_list(self) -> list[dict]:
        event_subscription_list: list[dict] = []
        try:
            response = self.dms_client.describe_event_subscriptions()
            event_subscription_list.extend(_ for _ in response['EventSubscriptionsList'])
            while 'Marker' in response:
                response = self.dms_client.describe_event_subscriptions(Marker=response['Marker'])
                event_subscription_list.extend(_ for _ in response['EventSubscriptionsList'])
        except ClientError as e:
            print(f"Error: {e}")
        return event_subscription_list
    
    def dms_replication_instance_list(self) -> list[dict]:
        replication_instance_list: list[dict] = []
        try:
            response = self.dms_client.describe_replication_instances()
            replication_instance_list.extend(_ for _ in response['ReplicationInstances'])
            while 'Marker' in response:
                response = self.dms_client.describe_replication_instances(Marker=response['Marker'])
                replication_instance_list.extend(_ for _ in response['ReplicationInstances'])
        except ClientError as e:
            print(f"Error: {e}")
        return replication_instance_list
    
    def dms_replication_subnet_group_list(self) -> list[dict]:
        replication_subnet_group_list: list[dict] = []
        try:
            response = self.dms_client.describe_replication_subnet_groups()
            replication_subnet_group_list.extend(_ for _ in response['ReplicationSubnetGroups'])
            while 'Marker' in response:
                response = self.dms_client.describe_replication_subnet_groups(Marker=response['Marker'])
                replication_subnet_group_list.extend(_ for _ in response['ReplicationSubnetGroups'])
        except ClientError as e:
            print(f"Error: {e}")
        return replication_subnet_group_list
    
    def dms_neptune_database_endpoint_list(self) -> list[dict]:
        result_list = self.dms_endpoint_list()
        return [_ for _ in result_list if _['EngineName'] == 'neptune']
    
    def dms_mongodb_database_endpoint_list(self) -> list[dict]:
        result_list = self.dms_endpoint_list()
        return [_ for _ in result_list if _['EngineName'] == 'mongodb']
    
    def dms_redis_database_endpoint_list(self) -> list[dict]:
        result_list = self.dms_endpoint_list()
        return [_ for _ in result_list if _['EngineName'] == 'redshift']
    
    def dms_tag_list(self, dms_resourse_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.dms_client.list_tags_for_resource(
                ResourceArn=dms_resourse_arn
            )
            tag_key_list = [tag['Key'] for tag in response['TagList']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""

    @DecoratorClass.my_decorator
    def dms_one(self) -> None:
        result_list = self.dms_instance_list()
        if not result_list:
            self.dms_list.append(self.create_dms_item(
                'DMS.1',
                'Database Migration Service replication instances should not be public',
                'not_found',
                'CRITICAL',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if response['PubliclyAccessible'] == True:
                self.dms_list.append(self.create_dms_item(
                    'DMS.1',
                    'Database Migration Service replication instances should not be public',
                    'failed',
                    'CRITICAL',
                    'not_available',
                    response['ReplicationInstanceArn']
                ))
            else:
                self.dms_list.append(self.create_dms_item(
                    'DMS.1',
                    'Database Migration Service replication instances should not be public',
                    'passed',
                    'CRITICAL',
                    'not_available',
                    response['ReplicationInstanceArn']
                ))

    @DecoratorClass.my_decorator
    def dms_two(self) -> None:
        result_list = self.dms_certificate_list()
        if not result_list:
            self.dms_list.append(self.create_dms_item(
                'DMS.2',
                'DMS certificates should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            compliant_status = self.dms_tag_list(response['CertificateArn'])
            self.dms_list.append(self.create_dms_item(
                'DMS.2',
                'DMS certificates should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response['CertificateArn']
            ))

    @DecoratorClass.my_decorator
    def dms_three(self) -> None:
        result_list = self.dms_event_subscription_list()
        if not result_list:
            self.dms_list.append(self.create_dms_item(
                'DMS.3',
                'DMS event subscriptions should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            compliant_status = self.dms_tag_list(response['CustSubscriptionId'])
            self.dms_list.append(self.create_dms_item(
                'DMS.3',
                'DMS event subscriptions should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response['CustSubscriptionId']
            ))

    @DecoratorClass.my_decorator
    def dms_four(self) -> None:
        result_list = self.dms_replication_instance_list()
        if not result_list:
            self.dms_list.append(self.create_dms_item(
                'DMS.4',
                'DMS replication instances should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            compliant_status = self.dms_tag_list(response['ReplicationInstanceArn'])
            self.dms_list.append(self.create_dms_item(
                'DMS.4',
                'DMS replication instances should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response['ReplicationInstanceArn']
            ))

    @DecoratorClass.my_decorator
    def dms_five(self) -> None:
        result_list = self.dms_replication_instance_list()
        if not result_list:
            self.dms_list.append(self.create_dms_item(
                'DMS.5',
                'DMS replication subnet groups should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            compliant_status = self.dms_tag_list(response['ReplicationSubnetGroupIdentifier'])
            self.dms_list.append(self.create_dms_item(
                'DMS.5',
                'DMS replication subnet groups should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response['ReplicationSubnetGroupIdentifier']
            ))

    @DecoratorClass.my_decorator
    def dms_six(self) -> None:
        result_list = self.dms_instance_list()
        if not result_list:
            self.dms_list.append(self.create_dms_item(
                'DMS.6',
                'DMS replication instances should have automatic minor version upgrade enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if response['AutoMinorVersionUpgrade'] != True:
                self.dms_list.append(self.create_dms_item(
                    'DMS.6',
                    'DMS replication instances should have automatic minor version upgrade enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response['ReplicationInstanceArn']
                ))
            else:
                self.dms_list.append(self.create_dms_item(
                    'DMS.6',
                    'DMS replication instances should have automatic minor version upgrade enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response['ReplicationInstanceArn']
                ))

    @DecoratorClass.my_decorator
    def dms_seven(self) -> None:
        logging_enabled_task_list = self.logging_enabled_task_list()
        result_list = self.dms_task_list()
        if not result_list:
            self.dms_list.append(self.create_dms_item(
                'DMS.7',
                'DMS replication tasks for the target database should have logging enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if response['ReplicationTaskArn'] not in logging_enabled_task_list:
                self.dms_list.append(self.create_dms_item(
                    'DMS.7',
                    'DMS replication tasks for the target database should have logging enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response['TargetEndpointArn']
                ))
            else:
                self.dms_list.append(self.create_dms_item(
                    'DMS.7',
                    'DMS replication tasks for the target database should have logging enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response['TargetEndpointArn']
                ))

    @DecoratorClass.my_decorator
    def dms_eight(self) -> None:
        logging_enabled_task_list = self.logging_enabled_task_list()
        result_list = self.dms_task_list()
        if not result_list:
            self.dms_list.append(self.create_dms_item(
                'DMS.8',
                'DMS replication tasks for the source database should have logging enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if response['ReplicationTaskArn'] not in logging_enabled_task_list:
                self.dms_list.append(self.create_dms_item(
                    'DMS.8',
                    'DMS replication tasks for the source database should have logging enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response['SourceEndpointArn']
                ))
            else:
                self.dms_list.append(self.create_dms_item(
                    'DMS.8',
                    'DMS replication tasks for the source database should have logging enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response['SourceEndpointArn']
                ))

    @DecoratorClass.my_decorator
    def dms_nine(self) -> None:
        result_list = self.dms_endpoint_list()
        if not result_list:
            self.dms_list.append(self.create_dms_item(
                'DMS.9',
                'DMS endpoints should use SSL',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if response['SslMode'] == 'none':
                self.dms_list.append(self.create_dms_item(
                    'DMS.9',
                    'DMS endpoints should use SSL',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response['EndpointArn']
                ))
            else:
                self.dms_list.append(self.create_dms_item(
                    'DMS.9',
                    'DMS endpoints should use SSL',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response['EndpointArn']
                ))

    @DecoratorClass.my_decorator
    def dms_ten(self) -> None:
        result_list = self.dms_neptune_database_endpoint_list()
        if not result_list:
            self.dms_list.append(self.create_dms_item(
                'DMS.10',
                'DMS endpoints for Neptune databases should have IAM authorization enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if response.get('NeptuneSettings', {}).get('IAMAuthEnabled') != True:
                self.dms_list.append(self.create_dms_item(
                    'DMS.10',
                    'DMS endpoints for Neptune databases should have IAM authorization enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response['EndpointArn']
                ))
            else:
                self.dms_list.append(self.create_dms_item(
                    'DMS.10',
                    'DMS endpoints for Neptune databases should have IAM authorization enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response['EndpointArn']
                ))

    @DecoratorClass.my_decorator
    def dms_eleven(self) -> None:
        result_list = self.dms_mongodb_database_endpoint_list()
        if not result_list:
            self.dms_list.append(self.create_dms_item(
                'DMS.11',
                'DMS endpoints for MongoDB should have an authentication mechanism enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if all([response.get('MongoDbSettings', {}).get('AuthMechanism') != "mongodb_cr", \
                response.get('MongoDbSettings', {}).get('AuthMechanism') != "scram_sha_1"]):
                self.dms_list.append(self.create_dms_item(
                    'DMS.11',
                    'DMS endpoints for MongoDB should have an authentication mechanism enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response['EndpointArn']
                ))
            else:
                self.dms_list.append(self.create_dms_item(
                    'DMS.11',
                    'DMS endpoints for MongoDB should have an authentication mechanism enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response['EndpointArn']
                ))

    @DecoratorClass.my_decorator
    def dms_twelve(self) -> None:
        result_list = self.dms_redis_database_endpoint_list()
        if not result_list:
            self.dms_list.append(self.create_dms_item(
                'DMS.12',
                'DMS endpoints for Redis should have TLS enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if all([response.get('RedshiftSettings', {}).get('EncryptionMode') != "sse-s3", \
                response.get('RedshiftSettings', {}).get('EncryptionMode') != "sse-kms"]):
                self.dms_list.append(self.create_dms_item(
                    'DMS.12',
                    'DMS endpoints for Redis should have TLS enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response['EndpointArn']
                ))
            else:
                self.dms_list.append(self.create_dms_item(
                    'DMS.12',
                    'DMS endpoints for Redis should have TLS enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response['EndpointArn']
                ))