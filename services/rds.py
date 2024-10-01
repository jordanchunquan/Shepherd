'''
Class name RDSComplianceChecker
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
from itertools import count, takewhile
from decimal import Decimal

class RDSComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.compliant_monitoring_interval = [1, 5, 10, 15, 30, 60]
        self.db_publish_log = {
            'Engine': [
                'oracle',
                'postgresql',
                'mysql',
                'mariadb',
                'sqlserver',
                'aurora',
                'aurora-mysql',
                'aurora-postgresql'
                ],
            'EnabledCloudwatchLogsExports': [
                [
                    'alert',
                    'audit',
                    'trace',
                    'listener'
                ],
                [
                    'postgresql',
                    'upgrade'
                ],
                [
                    'audit',
                    'error',
                    'general',
                    'slowquery'
                ],
                [
                    'audit',
                    'error',
                    'general',
                    'slowquery'
                ],
                [
                    'error',
                    'agent'
                ],
                [
                    'audit',
                    'error',
                    'general',
                    'slowquery'
                ],
                [
                    'audit',
                    'error',
                    'general',
                    'slowquery'
                ],
                [
                    'postgresql',
                    'upgrade'
                ]
            ]
        }
        self.backup_retention_period = [_ for _ in range(7, 36)]
        self.backtrack_window = [float(x) if x % 1 != 0 else int(x) for x in takewhile(lambda x: x < Decimal('72'), count(Decimal('0.1'), Decimal('0.1')))]
        self.rds_client = boto3.client('rds')
        self.rds_list = compliance_check_list

    def create_rds_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("RDS", control_id, compliance, severity, auto_remediation):
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
        
    def rds_cluster_snapshot_list(self) -> list[dict]:
        db_cluster_snapshot_arn_list: list[dict] = []
        try:
            response = self.rds_client.describe_db_cluster_snapshots()
            db_cluster_snapshot_arn_list.extend(_ for _ in response['DBClusterSnapshots'])
            while 'Marker' in response:
                response = self.rds_client.describe_db_cluster_snapshots(Marker=response['Marker'])
                db_cluster_snapshot_arn_list.extend(_ for _ in response['DBClusterSnapshots'])
            return db_cluster_snapshot_arn_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def rds_snapshot_list(self) -> list[dict]:
        db_snapshot_arn_list: list[dict] = []
        try:
            response = self.rds_client.describe_db_snapshots()
            db_snapshot_arn_list.extend(_ for _ in response['DBSnapshots'])
            while 'Marker' in response:
                response = self.rds_client.describe_db_snapshots(Marker=response['Marker'])
                db_snapshot_arn_list.extend(_ for _ in response['DBSnapshots'])
            return db_snapshot_arn_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def rds_cluster_snapshot_public_list(self) -> list[dict]:
        db_cluster_snapshot_arn_list: list[dict] = []
        try:
            response = self.rds_client.describe_db_cluster_snapshots(SnapshotType='public')
            db_cluster_snapshot_arn_list.extend(_ for _ in response['DBClusterSnapshots'])
            while 'Marker' in response:
                response = self.rds_client.describe_db_cluster_snapshots(SnapshotType='public', Marker=response['Marker'])
                db_cluster_snapshot_arn_list.extend(_ for _ in response['DBClusterSnapshots'])
            return db_cluster_snapshot_arn_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def rds_snapshot_public_list(self) -> list[dict]:
        db_snapshot_arn_list: list[dict] = []
        try:
            response = self.rds_client.describe_db_snapshots(SnapshotType='public')
            db_snapshot_arn_list.extend(_ for _ in response['DBSnapshots'])
            while 'Marker' in response:
                response = self.rds_client.describe_db_snapshots(SnapshotType='public', Marker=response['Marker'])
                db_snapshot_arn_list.extend(_ for _ in response['DBSnapshots'])
            return db_snapshot_arn_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    def describe_db_instance_list(self) -> list[dict]:
        db_instance_list: list[dict] = []
        try:
            response = self.rds_client.describe_db_instances()
            db_instance_list.extend(_ for _ in response['DBInstances'])
            while 'Marker' in response:
                response = self.rds_client.describe_db_instances(Marker=response['Marker'])
                db_instance_list.extend(_ for _ in response['DBInstances'])
            return db_instance_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def describe_db_cluster_list(self) -> list[dict]:
        db_cluster_arn_list: list[dict] = []
        try:
            response = self.rds_client.describe_db_clusters()
            db_cluster_arn_list.extend(_['DBClusterArn'] for _ in response['DBClusters'])
            while 'Marker' in response:
                response = self.rds_client.describe_db_clusters(Marker=response['Marker'])
                db_cluster_arn_list.extend(_['DBClusterArn'] for _ in response['DBClusters'])
            return db_cluster_arn_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def db_cluster_tag_list(self, db_cluster_arn:str) -> str:
        try:
            compliant_status = "passed"
            response = self.rds_client.list_tags_for_resource(
                ResourceName=db_cluster_arn
            )
            tag_key_list = [tag['Key'] for tag in response['TagList']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
    
    @DecoratorClass.my_decorator
    def rds_one(self) -> None:
        cluster_result_list = [_['DBClusterSnapshotArn'] for _ in self.rds_cluster_snapshot_list()]
        snapshot_result_list = [_['DBSnapshotArn'] for _ in self.rds_snapshot_list()]
        cluster_public_result_list = [_['DBClusterSnapshotArn'] for _ in self.rds_cluster_snapshot_public_list()]
        snapshot_public_result_list = [_['DBSnapshotArn'] for _ in self.rds_snapshot_public_list()]
        if not cluster_result_list and not snapshot_result_list:
            self.rds_list.append(self.create_rds_item(
                'RDS.1',
                'RDS snapshot should be private',
                'not_found',
                'CRITICAL',
                'not_available',
                'not_found'
            ))
        for response_detail in cluster_result_list:
            if response_detail in cluster_public_result_list:
                self.rds_list.append(self.create_rds_item(
                    'RDS.1',
                    'RDS snapshot should be private',
                    'failed',
                    'CRITICAL',
                    'not_available',
                    response_detail
                ))
            else:
                self.rds_list.append(self.create_rds_item(
                    'RDS.1',
                    'RDS snapshot should be private',
                    'passed',
                    'CRITICAL',
                    'not_available',
                    response_detail
                ))
        for response_detail in snapshot_result_list:
            if response_detail in snapshot_public_result_list:
                self.rds_list.append(self.create_rds_item(
                    'RDS.1',
                    'RDS snapshot should be private',
                    'failed',
                    'CRITICAL',
                    'not_available',
                    response_detail
                ))
            else:
                self.rds_list.append(self.create_rds_item(
                    'RDS.1',
                    'RDS snapshot should be private',
                    'passed',
                    'CRITICAL',
                    'not_available',
                    response_detail
                ))
    
    @DecoratorClass.my_decorator
    def rds_two(self) -> None:
        result_list = self.describe_db_instance_list()
        if not result_list:
            self.rds_list.append(self.create_rds_item(
                'RDS.2',
                'RDS DB Instances should prohibit public access, as determined by the PubliclyAccessible AWS Configuration',
                'not_found',
                'CRITICAL',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('PubliclyAccessible', False):
                self.rds_list.append(self.create_rds_item(
                    'RDS.2',
                    'RDS DB Instances should prohibit public access, as determined by the PubliclyAccessible AWS Configuration',
                    'failed',
                    'CRITICAL',
                    'not_available',
                    response_detail['DBInstanceArn']
                ))
            else:
                self.rds_list.append(self.create_rds_item(
                    'RDS.2',
                    'RDS DB Instances should prohibit public access, as determined by the PubliclyAccessible AWS Configuration',
                    'passed',
                    'CRITICAL',
                    'not_available',
                    response_detail['DBInstanceArn']
                ))
    
    @DecoratorClass.my_decorator
    def rds_three(self) -> None:
        result_list = self.describe_db_instance_list()
        if not result_list:
            self.rds_list.append(self.create_rds_item(
                'RDS.3',
                'RDS DB instances should have encryption at-rest enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if not response_detail.get('StorageEncrypted', False):
                self.rds_list.append(self.create_rds_item(
                    'RDS.3',
                    'RDS DB instances should have encryption at-rest enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBInstanceArn']
                ))
            else:
                self.rds_list.append(self.create_rds_item(
                    'RDS.3',
                    'RDS DB instances should have encryption at-rest enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBInstanceArn']
                ))
    
    @DecoratorClass.my_decorator
    def rds_four(self) -> None:
        cluster_result_list = [_['DBClusterSnapshotArn'] for _ in self.rds_cluster_snapshot_list()]
        snapshot_result_list = [_['DBSnapshotArn'] for _ in self.rds_snapshot_list()]
        if not cluster_result_list and not snapshot_result_list:
            self.rds_list.append(self.create_rds_item(
                'RDS.4',
                'RDS cluster snapshots and database snapshots should be encrypted at rest',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in cluster_result_list:
            if not response_detail.get('Encrypted', False):
                self.rds_list.append(self.create_rds_item(
                    'RDS.4',
                    'RDS cluster snapshots and database snapshots should be encrypted at rest',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail
                ))
            else:
                self.rds_list.append(self.create_rds_item(
                    'RDS.4',
                    'RDS cluster snapshots and database snapshots should be encrypted at rest',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail
                ))
    
    @DecoratorClass.my_decorator
    def rds_five(self) -> None:
        result_list = self.describe_db_instance_list()
        if not result_list:
            self.rds_list.append(self.create_rds_item(
                'RDS.5',
                'RDS DB instances should be configured with multiple Availability Zones',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('MultiAZ', False):
                self.rds_list.append(self.create_rds_item(
                    'RDS.5',
                    'RDS DB instances should be configured with multiple Availability Zones',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBInstanceArn']
                ))
            else:
                self.rds_list.append(self.create_rds_item(
                    'RDS.5',
                    'RDS DB instances should be configured with multiple Availability Zones',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBInstanceArn']
                ))
    
    @DecoratorClass.my_decorator
    def rds_six(self) -> None:
        parameter = self.compliant_monitoring_interval
        result_list = self.describe_db_instance_list()
        if not result_list:
            self.rds_list.append(self.create_rds_item(
                'RDS.6',
                'Enhanced monitoring should be configured for RDS DB instances',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('MonitoringInterval', 0) not in parameter:
                self.rds_list.append(self.create_rds_item(
                    'RDS.6',
                    'Enhanced monitoring should be configured for RDS DB instances',
                    'failed',
                    'LOW',
                    'not_available',
                    response_detail['DBInstanceArn']
                ))
            else:
                self.rds_list.append(self.create_rds_item(
                    'RDS.6',
                    'Enhanced monitoring should be configured for RDS DB instances',
                    'passed',
                    'LOW',
                    'not_available',
                    response_detail['DBInstanceArn']
                ))
    
    @DecoratorClass.my_decorator
    def rds_seven(self) -> None:
        result_list = self.describe_db_cluster_list()
        if not result_list:
            self.rds_list.append(self.create_rds_item(
                'RDS.7',
                'RDS clusters should have deletion protection enabled',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if not response_detail.get('DeletionProtection', False):
                self.rds_list.append(self.create_rds_item(
                    'RDS.7',
                    'RDS clusters should have deletion protection enabled',
                    'failed',
                    'LOW',
                    'not_available',
                    response_detail['DBClusterArn']
                ))
            else:
                self.rds_list.append(self.create_rds_item(
                    'RDS.7',
                    'RDS clusters should have deletion protection enabled',
                    'passed',
                    'LOW',
                    'not_available',
                    response_detail['DBClusterArn']
                ))
    
    @DecoratorClass.my_decorator
    def rds_eight(self) -> None:
        result_list = self.describe_db_instance_list()
        if not result_list:
            self.rds_list.append(self.create_rds_item(
                'RDS.8',
                'RDS DB instances should have deletion protection enabled',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if not response_detail.get('DeletionProtection', False):
                self.rds_list.append(self.create_rds_item(
                    'RDS.8',
                    'RDS DB instances should have deletion protection enabled',
                    'failed',
                    'LOW',
                    'not_available',
                    response_detail['DBInstanceArn']
                ))
            else:
                self.rds_list.append(self.create_rds_item(
                    'RDS.8',
                    'RDS DB instances should have deletion protection enabled',
                    'passed',
                    'LOW',
                    'not_available',
                    response_detail['DBInstanceArn']
                ))
    
    @DecoratorClass.my_decorator
    def rds_nine(self) -> None:
        parameter = self.db_publish_log
        result_list = self.describe_db_instance_list()
        if not result_list:
            self.rds_list.append(self.create_rds_item(
                'RDS.9',
                'RDS DB instances should publish logs to CloudWatch Logs',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            for key, value in parameter.items():
                if response_detail.get('Engine') == key:
                    response_log_list = response_detail.get('EnabledCloudwatchLogsExports', [])
                    if list(set(value) - set(response_log_list)):
                        self.rds_list.append(self.create_rds_item(
                            'RDS.9',
                            'RDS DB instances should publish logs to CloudWatch Logs',
                            'failed',
                            'MEDIUM',
                            'not_available',
                            response_detail['DBInstanceArn']
                        ))
                    else:
                        self.rds_list.append(self.create_rds_item(
                            'RDS.9',
                            'RDS DB instances should publish logs to CloudWatch Logs',
                            'passed',
                            'MEDIUM',
                            'not_available',
                            response_detail['DBInstanceArn']
                        ))
    
    @DecoratorClass.my_decorator
    def rds_ten(self) -> None:
        result_list = self.describe_db_instance_list()
        if not result_list:
            self.rds_list.append(self.create_rds_item(
                'RDS.10',
                'IAM authentication should be configured for RDS instances',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if not response_detail.get('IAMDatabaseAuthenticationEnabled', False):
                self.rds_list.append(self.create_rds_item(
                    'RDS.10',
                    'IAM authentication should be configured for RDS instances',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBInstanceArn']
                ))
            else:
                self.rds_list.append(self.create_rds_item(
                    'RDS.10',
                    'IAM authentication should be configured for RDS instances',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBInstanceArn']
                ))
    
    @DecoratorClass.my_decorator
    def rds_eleven(self) -> None:
        retention_parameter = self.backup_retention_period
        result_list = [_ for _ in self.describe_db_instance_list() if _.get('ReplicaMode', '') != "open-read-only"]
        if not result_list:
            self.rds_list.append(self.create_rds_item(
                'RDS.11',
                'RDS instances should have automatic backups enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if not response_detail.get('BackupRetentionPeriod', 0) in retention_parameter:
                self.rds_list.append(self.create_rds_item(
                    'RDS.11',
                    'RDS instances should have automatic backups enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBInstanceArn']
                ))
            else:
                self.rds_list.append(self.create_rds_item(
                    'RDS.11',
                    'RDS instances should have automatic backups enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBInstanceArn']
                ))
    
    @DecoratorClass.my_decorator
    def rds_twelve(self) -> None:
        result_list = self.describe_db_cluster_list()
        if not result_list:
            self.rds_list.append(self.create_rds_item(
                'RDS.12',
                'IAM authentication should be configured for RDS clusters',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if not response_detail.get('IAMDatabaseAuthenticationEnabled', False):
                self.rds_list.append(self.create_rds_item(
                    'RDS.12',
                    'IAM authentication should be configured for RDS clusters',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))
            else:
                self.rds_list.append(self.create_rds_item(
                    'RDS.12',
                    'IAM authentication should be configured for RDS clusters',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))
    
    @DecoratorClass.my_decorator
    def rds_thirteen(self) -> None:
        result_list = self.describe_db_instance_list()
        if not result_list:
            self.rds_list.append(self.create_rds_item(
                'RDS.13',
                'RDS automatic minor version upgrades should be enabled',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if not response_detail.get('AutoMinorVersionUpgrade', False):
                self.rds_list.append(self.create_rds_item(
                    'RDS.13',
                    'RDS automatic minor version upgrades should be enabled',
                    'failed',
                    'HIGH',
                    'not_available',
                    response_detail['DBInstanceArn']
                ))
            else:
                self.rds_list.append(self.create_rds_item(
                    'RDS.13',
                    'RDS automatic minor version upgrades should be enabled',
                    'passed',
                    'HIGH',
                    'not_available',
                    response_detail['DBInstanceArn']
                ))
    
    @DecoratorClass.my_decorator
    def rds_fourteen(self) -> None:
        parameter = self.backtrack_window
        result_list = self.describe_db_cluster_list()
        if not result_list:
            self.rds_list.append(self.create_rds_item(
                'RDS.14',
                'Amazon Aurora clusters should have backtracking enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if not response_detail.get('BacktrackWindow', 0) in parameter:
                self.rds_list.append(self.create_rds_item(
                    'RDS.14',
                    'Amazon Aurora clusters should have backtracking enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))
            else:
                self.rds_list.append(self.create_rds_item(
                    'RDS.14',
                    'Amazon Aurora clusters should have backtracking enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))
    
    @DecoratorClass.my_decorator
    def rds_fifteen(self) -> None:
        result_list = self.describe_db_cluster_list()
        if not result_list:
            self.rds_list.append(self.create_rds_item(
                'RDS.15',
                'RDS DB clusters should be configured for multiple Availability Zones',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if not response_detail.get('MultiAZ', False):
                self.rds_list.append(self.create_rds_item(
                    'RDS.15',
                    'RDS DB clusters should be configured for multiple Availability Zones',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))
            else:
                self.rds_list.append(self.create_rds_item(
                    'RDS.15',
                    'RDS DB clusters should be configured for multiple Availability Zones',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))
    
    @DecoratorClass.my_decorator
    def rds_sixteen(self) -> None:
        result_list = self.describe_db_cluster_list()
        if not result_list:
            self.rds_list.append(self.create_rds_item(
                'RDS.16',
                'RDS DB clusters should be configured to copy tags to snapshots',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if not response_detail.get('CopyTagsToSnapshot', False):
                self.rds_list.append(self.create_rds_item(
                    'RDS.16',
                    'RDS DB clusters should be configured to copy tags to snapshots',
                    'failed',
                    'LOW',
                    'not_available',
                    response_detail['DBClusterArn']
                ))
            else:
                self.rds_list.append(self.create_rds_item(
                    'RDS.16',
                    'RDS DB clusters should be configured to copy tags to snapshots',
                    'passed',
                    'LOW',
                    'not_available',
                    response_detail['DBClusterArn']
                ))
    
    @DecoratorClass.my_decorator
    def rds_seventeen(self) -> None:
        result_list = self.describe_db_instance_list()
        if not result_list:
            self.rds_list.append(self.create_rds_item(
                'RDS.17',
                'RDS DB instances should be configured to copy tags to snapshots',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if not response_detail.get('CopyTagsToSnapshot', False):
                self.rds_list.append(self.create_rds_item(
                    'RDS.17',
                    'RDS DB instances should be configured to copy tags to snapshots',
                    'failed',
                    'LOW',
                    'not_available',
                    response_detail['DBInstanceArn']
                ))
            else:
                self.rds_list.append(self.create_rds_item(
                    'RDS.17',
                    'RDS DB instances should be configured to copy tags to snapshots',
                    'passed',
                    'LOW',
                    'not_available',
                    response_detail['DBInstanceArn']
                ))

    @DecoratorClass.my_decorator
    def rds_twentyeight(self) -> None:
        result_list = self.describe_db_cluster_list()
        if not result_list:
            self.rds_list.append(self.create_rds_item(
                'RDS.28',
                'RDS DB clusters should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.db_cluster_tag_list(response_detail['DBClusterArn'])
            self.rds_list.append(self.create_rds_item(
                'RDS.28',
                'RDS DB clusters should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['DBClusterArn']
            ))

    def get_compliance_results(self) -> list[dict]:
        return self.rds_list