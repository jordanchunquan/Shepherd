'''
Class name DynamoDBComplianceChecker
Create functions to check compliants and return as 
'control_id': security contorl id,
'control_title': security control title,
'compliance': passed, failed or not_found,
'severity': CRITICAL, HIGH, MEDIUM or LOW,
'auto_remediation': available or not_available,
'resource_id': account id, resource arn or not_found
'''

import re, boto3 # type: ignore
from botocore.exceptions import ClientError # type: ignore
from utils.decorator_class import DecoratorClass # type: ignore
from utils.validate import ParameterValidation # type: ignore
from utils.cross_account import UseCrossAccount # type: ignore
from utils.global_data import compliance_check_list # type: ignore

class DynamoDBComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.dynamodb_client = boto3.client('dynamodb')
        self.dax_client = boto3.client('dax')
        self.application_autoscaling_client = boto3.client('application-autoscaling')
        self.backup_client = boto3.client('backup')
        self.dynamodb_list = compliance_check_list

    def create_dynamodb_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("DynamoDB", control_id, compliance, severity, auto_remediation):
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
    
    def dynamo_db_list(self) -> list[dict]:
        dynamodb_list: list[dict] = []
        try:
            response = self.dynamodb_client.list_tables()
            for _ in response['TableNames']:
                detail_response = self.dynamodb_client.describe_table(TableName=_)
                dynamodb_list.append(detail_response['Table'])
            while 'LastEvaluatedTableName' in response:
                response = self.dynamodb_client.list_tables(ExclusiveStartTableName=response['LastEvaluatedTableName'])
                for _ in response['TableNames']:
                    detail_response = self.dynamodb_client.describe_table(TableName=_)
                    dynamodb_list.append(detail_response['Table'])
            return dynamodb_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def dynamo_db_cluster_list(self) -> list[dict]:
        dynamodb_list: list[dict] = []
        try:
            response = self.dax_client.describe_clusters()
            dynamodb_list.extend(_ for _ in response['Clusters'])
            while 'NextToken' in response:
                response = self.dax_client.describe_clusters(NextToken=response['NextToken'])
                dynamodb_list.extend(_ for _ in response['Clusters'])
            return dynamodb_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def auto_scaling_list(self) -> list[str]:
        autoscaling_list: list[str] = []
        try:
            response = self.application_autoscaling_client.describe_scalable_targets(ServiceNamespace="dynamodb")
            autoscaling_list.extend(_['ResourceId'] for _ in response['ScalableTargets'])
            while 'NextToken' in response:
                response = self.application_autoscaling_client.describe_scalable_targets(ServiceNamespace="dynamodb", \
                                                                                            NextToken=response['NextToken'])
                autoscaling_list.extend(_['ResourceId'] for _ in response['ScalableTargets'])
            autoscaling_list = [_.replace('table/', "") for _ in autoscaling_list if re.match(r'table/([A-Za-z0-9_]+)', _)]
            return autoscaling_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def dynamodb_pitr_list(self) -> list[str]:
        result_list = self.dynamo_db_list()
        dynamodb_list: list[str] = []
        try:
            for table_response in result_list:
                response = self.dynamodb_client.describe_continuous_backups(TableName=table_response['TableName'])
                if response['ContinuousBackupsDescription']['PointInTimeRecoveryDescription']['PointInTimeRecoveryStatus'] == 'ENABLED':
                    dynamodb_list.append(table_response['TableArn'])
            return dynamodb_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    def backup_list(self) -> list[str]:
        next_token = None # type:ignore
        protected_resource_list: list[str] = []
        while True:
            try:
                response_iterator = self.backup_client.get_paginator('list_protected_resources').paginate(
                    PaginationConfig={
                        'StartingToken': next_token
                        }
                    )
                for page in response_iterator:
                    result_list = page['Results']
                    protected_resource_list.extend(_['ResourceArn'] for _ in result_list if _['ResourceType'] == "DynamoDB")
                    if 'NextToken' in page:
                        next_token = page['NextToken']
                    else:
                        return protected_resource_list
            except ClientError as e:
                print(f"Error: {e}")
                return []
            
    def dynamodb_tag_list(self, dynamedb_resource_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.dynamodb_client.list_tags_of_resource(
                ResourceArn=dynamedb_resource_arn
            )
            tag_key_list = [tag['Key'] for tag in response['Tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
    
    @DecoratorClass.my_decorator
    def dynamodb_one(self) -> None:
        autoscaling_list = self.auto_scaling_list()
        result_list = self.dynamo_db_list()
        if not result_list:
            self.dynamodb_list.append(self.create_dynamodb_item(
                'DynamoDB.1',
                'DynamoDB tables should automatically scale capacity with demand',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if 'BillingModeSummary' not in response_detail:
                if response_detail['TableName'] not in autoscaling_list:
                    self.dynamodb_list.append(self.create_dynamodb_item(
                        'DynamoDB.1',
                        'DynamoDB tables should automatically scale capacity with demand',
                        'failed',
                        'MEDIUM',
                        'not_available',
                        response_detail['TableArn']
                    ))
            self.dynamodb_list.append(self.create_dynamodb_item(
                'DynamoDB.1',
                'DynamoDB tables should automatically scale capacity with demand',
                'passed',
                'MEDIUM',
                'not_available',
                response_detail['TableArn']
            ))

    @DecoratorClass.my_decorator
    def dynamodb_two(self) -> None:
        pitr_list = self.dynamodb_pitr_list()
        result_list = self.dynamo_db_list()
        if not result_list:
            self.dynamodb_list.append(self.create_dynamodb_item(
                'DynamoDB.2',
                'DynamoDB tables should have point-in-time recovery enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['TableArn'] not in pitr_list:
                self.dynamodb_list.append(self.create_dynamodb_item(
                    'DynamoDB.2',
                    'DynamoDB tables should have point-in-time recovery enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['TableArn']
                ))
            else:
                self.dynamodb_list.append(self.create_dynamodb_item(
                    'DynamoDB.2',
                    'DynamoDB tables should have point-in-time recovery enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['TableArn']
                ))

    @DecoratorClass.my_decorator
    def dynamodb_three(self) -> None:
        result_list = self.dynamo_db_cluster_list()
        if not result_list:
            self.dynamodb_list.append(self.create_dynamodb_item(
                'DynamoDB.3',
                'DynamoDB Accelerator (DAX) clusters should be encrypted at rest',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if any([response_detail['SSEDescription'] != "ENABLED", response_detail['ClusterEndpointEncryptionType'] == "None"]):
                self.dynamodb_list.append(self.create_dynamodb_item(
                    'DynamoDB.3',
                    'DynamoDB Accelerator (DAX) clusters should be encrypted at rest',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ClusterArn']
                ))
            else:
                self.dynamodb_list.append(self.create_dynamodb_item(
                    'DynamoDB.3',
                    'DynamoDB Accelerator (DAX) clusters should be encrypted at rest',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ClusterArn']
                ))

    @DecoratorClass.my_decorator
    def dynamodb_four(self) -> None:
        backup_list = self.backup_list()
        result_list = self.dynamo_db_list()
        if not result_list:
            self.dynamodb_list.append(self.create_dynamodb_item(
                'DynamoDB.4',
                'DynamoDB tables should be present in a backup plan',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['TableArn'] not in backup_list:
                self.dynamodb_list.append(self.create_dynamodb_item(
                    'DynamoDB.4',
                    'DynamoDB tables should be present in a backup plan',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['TableArn']
                ))
            else:
                self.dynamodb_list.append(self.create_dynamodb_item(
                    'DynamoDB.4',
                    'DynamoDB tables should be present in a backup plan',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['TableArn']
                ))

    @DecoratorClass.my_decorator
    def dynamodb_five(self) -> None:
        result_list = self.dynamo_db_list()
        if not result_list:
            self.dynamodb_list.append(self.create_dynamodb_item(
                'DynamoDB.5',
                'DynamoDB tables should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliance_status = self.dynamodb_tag_list(response_detail['TableArn'])
            self.dynamodb_list.append(self.create_dynamodb_item(
                'DynamoDB.5',
                'DynamoDB tables should be tagged',
                compliance_status,
                'LOW',
                'not_available',
                response_detail['TableArn']
            ))

    @DecoratorClass.my_decorator
    def dynamodb_six(self) -> None:
        result_list = self.dynamo_db_list()
        if not result_list:
            self.dynamodb_list.append(self.create_dynamodb_item(
                'DynamoDB.6',
                'DynamoDB tables should have deletion protection enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['DeletionProtectionEnabled'] == False:
                self.dynamodb_list.append(self.create_dynamodb_item(
                    'DynamoDB.6',
                    'DynamoDB tables should have deletion protection enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['TableArn']
                ))
            else:
                self.dynamodb_list.append(self.create_dynamodb_item(
                    'DynamoDB.6',
                    'DynamoDB tables should have deletion protection enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['TableArn']
                ))

    @DecoratorClass.my_decorator
    def dynamodb_seven(self) -> None:
        result_list = self.dynamo_db_cluster_list()
        if not result_list:
            self.dynamodb_list.append(self.create_dynamodb_item(
                'DynamoDB.7',
                'DynamoDB Accelerator clusters should be encrypted in transit',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['ClusterEndpointEncryptionType'] != "TLS":
                self.dynamodb_list.append(self.create_dynamodb_item(
                    'DynamoDB.7',
                    'DynamoDB Accelerator clusters should be encrypted in transit',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ClusterArn']
                ))
            else:
                self.dynamodb_list.append(self.create_dynamodb_item(
                    'DynamoDB.7',
                    'DynamoDB Accelerator clusters should be encrypted in transit',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ClusterArn']
                ))

class CrossAccountDynamoDBComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.dynamodb_client = UseCrossAccount().client('dynamodb')
        self.dax_client = UseCrossAccount().client('dax')
        self.application_autoscaling_client = UseCrossAccount().client('application-autoscaling')
        self.backup_client = UseCrossAccount().client('backup')
        self.dynamodb_list = compliance_check_list

    def create_dynamodb_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("DynamoDB", control_id, compliance, severity, auto_remediation):
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
    
    def dynamo_db_list(self) -> list[dict]:
        dynamodb_list: list[dict] = []
        try:
            response = self.dynamodb_client.list_tables()
            for _ in response['TableNames']:
                detail_response = self.dynamodb_client.describe_table(TableName=_)
                dynamodb_list.append(detail_response['Table'])
            while 'LastEvaluatedTableName' in response:
                response = self.dynamodb_client.list_tables(ExclusiveStartTableName=response['LastEvaluatedTableName'])
                for _ in response['TableNames']:
                    detail_response = self.dynamodb_client.describe_table(TableName=_)
                    dynamodb_list.append(detail_response['Table'])
            return dynamodb_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def dynamo_db_cluster_list(self) -> list[dict]:
        dynamodb_list: list[dict] = []
        try:
            response = self.dax_client.describe_clusters()
            dynamodb_list.extend(_ for _ in response['Clusters'])
            while 'NextToken' in response:
                response = self.dax_client.describe_clusters(NextToken=response['NextToken'])
                dynamodb_list.extend(_ for _ in response['Clusters'])
            return dynamodb_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def auto_scaling_list(self) -> list[str]:
        autoscaling_list: list[str] = []
        try:
            response = self.application_autoscaling_client.describe_scalable_targets(ServiceNamespace="dynamodb")
            autoscaling_list.extend(_['ResourceId'] for _ in response['ScalableTargets'])
            while 'NextToken' in response:
                response = self.application_autoscaling_client.describe_scalable_targets(ServiceNamespace="dynamodb", \
                                                                                            NextToken=response['NextToken'])
                autoscaling_list.extend(_['ResourceId'] for _ in response['ScalableTargets'])
            autoscaling_list = [_.replace('table/', "") for _ in autoscaling_list if re.match(r'table/([A-Za-z0-9_]+)', _)]
            return autoscaling_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def dynamodb_pitr_list(self) -> list[str]:
        result_list = self.dynamo_db_list()
        dynamodb_list: list[str] = []
        try:
            for table_response in result_list:
                response = self.dynamodb_client.describe_continuous_backups(TableName=table_response['TableName'])
                if response['ContinuousBackupsDescription']['PointInTimeRecoveryDescription']['PointInTimeRecoveryStatus'] == 'ENABLED':
                    dynamodb_list.append(table_response['TableArn'])
            return dynamodb_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    def backup_list(self) -> list[str]:
        next_token = None # type:ignore
        protected_resource_list: list[str] = []
        while True:
            try:
                response_iterator = self.backup_client.get_paginator('list_protected_resources').paginate(
                    PaginationConfig={
                        'StartingToken': next_token
                        }
                    )
                for page in response_iterator:
                    result_list = page['Results']
                    protected_resource_list.extend(_['ResourceArn'] for _ in result_list if _['ResourceType'] == "DynamoDB")
                    if 'NextToken' in page:
                        next_token = page['NextToken']
                    else:
                        return protected_resource_list
            except ClientError as e:
                print(f"Error: {e}")
                return []
            
    def dynamodb_tag_list(self, dynamedb_resource_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.dynamodb_client.list_tags_of_resource(
                ResourceArn=dynamedb_resource_arn
            )
            tag_key_list = [tag['Key'] for tag in response['Tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
    
    @DecoratorClass.my_decorator
    def dynamodb_one(self) -> None:
        autoscaling_list = self.auto_scaling_list()
        result_list = self.dynamo_db_list()
        if not result_list:
            self.dynamodb_list.append(self.create_dynamodb_item(
                'DynamoDB.1',
                'DynamoDB tables should automatically scale capacity with demand',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if 'BillingModeSummary' not in response_detail:
                if response_detail['TableName'] not in autoscaling_list:
                    self.dynamodb_list.append(self.create_dynamodb_item(
                        'DynamoDB.1',
                        'DynamoDB tables should automatically scale capacity with demand',
                        'failed',
                        'MEDIUM',
                        'not_available',
                        response_detail['TableArn']
                    ))
            self.dynamodb_list.append(self.create_dynamodb_item(
                'DynamoDB.1',
                'DynamoDB tables should automatically scale capacity with demand',
                'passed',
                'MEDIUM',
                'not_available',
                response_detail['TableArn']
            ))

    @DecoratorClass.my_decorator
    def dynamodb_two(self) -> None:
        pitr_list = self.dynamodb_pitr_list()
        result_list = self.dynamo_db_list()
        if not result_list:
            self.dynamodb_list.append(self.create_dynamodb_item(
                'DynamoDB.2',
                'DynamoDB tables should have point-in-time recovery enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['TableArn'] not in pitr_list:
                self.dynamodb_list.append(self.create_dynamodb_item(
                    'DynamoDB.2',
                    'DynamoDB tables should have point-in-time recovery enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['TableArn']
                ))
            else:
                self.dynamodb_list.append(self.create_dynamodb_item(
                    'DynamoDB.2',
                    'DynamoDB tables should have point-in-time recovery enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['TableArn']
                ))

    @DecoratorClass.my_decorator
    def dynamodb_three(self) -> None:
        result_list = self.dynamo_db_cluster_list()
        if not result_list:
            self.dynamodb_list.append(self.create_dynamodb_item(
                'DynamoDB.3',
                'DynamoDB Accelerator (DAX) clusters should be encrypted at rest',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if any([response_detail['SSEDescription'] != "ENABLED", response_detail['ClusterEndpointEncryptionType'] == "None"]):
                self.dynamodb_list.append(self.create_dynamodb_item(
                    'DynamoDB.3',
                    'DynamoDB Accelerator (DAX) clusters should be encrypted at rest',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ClusterArn']
                ))
            else:
                self.dynamodb_list.append(self.create_dynamodb_item(
                    'DynamoDB.3',
                    'DynamoDB Accelerator (DAX) clusters should be encrypted at rest',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ClusterArn']
                ))

    @DecoratorClass.my_decorator
    def dynamodb_four(self) -> None:
        backup_list = self.backup_list()
        result_list = self.dynamo_db_list()
        if not result_list:
            self.dynamodb_list.append(self.create_dynamodb_item(
                'DynamoDB.4',
                'DynamoDB tables should be present in a backup plan',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['TableArn'] not in backup_list:
                self.dynamodb_list.append(self.create_dynamodb_item(
                    'DynamoDB.4',
                    'DynamoDB tables should be present in a backup plan',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['TableArn']
                ))
            else:
                self.dynamodb_list.append(self.create_dynamodb_item(
                    'DynamoDB.4',
                    'DynamoDB tables should be present in a backup plan',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['TableArn']
                ))

    @DecoratorClass.my_decorator
    def dynamodb_five(self) -> None:
        result_list = self.dynamo_db_list()
        if not result_list:
            self.dynamodb_list.append(self.create_dynamodb_item(
                'DynamoDB.5',
                'DynamoDB tables should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliance_status = self.dynamodb_tag_list(response_detail['TableArn'])
            self.dynamodb_list.append(self.create_dynamodb_item(
                'DynamoDB.5',
                'DynamoDB tables should be tagged',
                compliance_status,
                'LOW',
                'not_available',
                response_detail['TableArn']
            ))

    @DecoratorClass.my_decorator
    def dynamodb_six(self) -> None:
        result_list = self.dynamo_db_list()
        if not result_list:
            self.dynamodb_list.append(self.create_dynamodb_item(
                'DynamoDB.6',
                'DynamoDB tables should have deletion protection enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['DeletionProtectionEnabled'] == False:
                self.dynamodb_list.append(self.create_dynamodb_item(
                    'DynamoDB.6',
                    'DynamoDB tables should have deletion protection enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['TableArn']
                ))
            else:
                self.dynamodb_list.append(self.create_dynamodb_item(
                    'DynamoDB.6',
                    'DynamoDB tables should have deletion protection enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['TableArn']
                ))

    @DecoratorClass.my_decorator
    def dynamodb_seven(self) -> None:
        result_list = self.dynamo_db_cluster_list()
        if not result_list:
            self.dynamodb_list.append(self.create_dynamodb_item(
                'DynamoDB.7',
                'DynamoDB Accelerator clusters should be encrypted in transit',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['ClusterEndpointEncryptionType'] != "TLS":
                self.dynamodb_list.append(self.create_dynamodb_item(
                    'DynamoDB.7',
                    'DynamoDB Accelerator clusters should be encrypted in transit',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ClusterArn']
                ))
            else:
                self.dynamodb_list.append(self.create_dynamodb_item(
                    'DynamoDB.7',
                    'DynamoDB Accelerator clusters should be encrypted in transit',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ClusterArn']
                ))