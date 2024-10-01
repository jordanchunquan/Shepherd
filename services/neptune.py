'''
Class name NeptuneComplianceChecker
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

class NeptuneComplianceChecker:
    def __init__(self) -> None:
        self.neptune_client = boto3.client('neptune')
        self.neptune_list = compliance_check_list # type: ignore

    def create_neptune_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("Neptune", control_id, compliance, severity, auto_remediation):
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
    
    def neptune_db_cluster_list(self) -> list[dict]:
        dbcluster_list: list[dict] = []
        try:
            response = self.neptune_client.describe_db_clusters()
            dbcluster_list.extend(_ for _ in response['DBClusters'])
            while 'Marker' in response:
                response = self.neptune_client.describe_db_clusters(Marker=response['Marker'])
                dbcluster_list.extend(_ for _ in response['DBClusters'])
            return dbcluster_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def neptune_db_cluster_snapshot_list(self) -> list[dict]:
        dbcluster_snapshot_list: list[dict] = []
        try:
            response = self.neptune_client.describe_db_cluster_snapshots()
            dbcluster_snapshot_list.extend(_ for _ in response['DBClusterSnapshots'])
            while 'Marker' in response:
                response = self.neptune_client.describe_db_cluster_snapshots(Marker=response['Marker'])
                dbcluster_snapshot_list.extend(_ for _ in response['DBClusterSnapshots'])
            return dbcluster_snapshot_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def neptune_db_cluster_snapshot_public_compliant(self, dbcluster_snapshot_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.neptune_client.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=dbcluster_snapshot_arn)
            for detail_resposne in response['DBClusterSnapshots']['DBClusterSnapshotAttributes']:
                if detail_resposne['AttributeName'] == 'restore':
                    if 'all' in detail_resposne['AttributeValues']:
                        compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
    
    @DecoratorClass.my_decorator
    def neptune_one(self) -> None:
        result_list = self.neptune_db_cluster_list()
        if not result_list:
            self.neptune_list.append(self.create_neptune_item(
                'Neptune.1',
                'Neptune DB clusters should be encrypted at rest',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('StorageEncrypted') != True:
                self.neptune_list.append(self.create_neptune_item(
                    'Neptune.1',
                    'Neptune DB clusters should be encrypted at rest',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))
            else:
                self.neptune_list.append(self.create_neptune_item(
                    'Neptune.1',
                    'Neptune DB clusters should be encrypted at rest',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))

    @DecoratorClass.my_decorator
    def neptune_two(self) -> None:
        result_list = self.neptune_db_cluster_list()
        if not result_list:
            self.neptune_list.append(self.create_neptune_item(
                'Neptune.2',
                'Neptune DB clusters should publish audit logs to CloudWatch Logs',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if "audit" not in response_detail.get('EnabledCloudwatchLogsExports', []):
                self.neptune_list.append(self.create_neptune_item(
                    'Neptune.2',
                    'Neptune DB clusters should publish audit logs to CloudWatch Logs',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))
            else:
                self.neptune_list.append(self.create_neptune_item(
                    'Neptune.2',
                    'Neptune DB clusters should publish audit logs to CloudWatch Logs',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))

    @DecoratorClass.my_decorator
    def neptune_three(self) -> None:
        result_list = self.neptune_db_cluster_snapshot_list()
        if not result_list:
            self.neptune_list.append(self.create_neptune_item(
                'Neptune.3',
                'Neptune DB cluster snapshots should not be public',
                'not_found',
                'CRITICAL',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.neptune_db_cluster_snapshot_public_compliant(response_detail['DBClusterSnapshotArn'])
            self.neptune_list.append(self.create_neptune_item(
                'Neptune.3',
                'Neptune DB cluster snapshots should not be public',
                compliant_status,
                'CRITICAL',
                'not_available',
                response_detail['DBClusterSnapshotArn']
            ))

    @DecoratorClass.my_decorator
    def neptune_four(self) -> None:
        result_list = self.neptune_db_cluster_list()
        if not result_list:
            self.neptune_list.append(self.create_neptune_item(
                'Neptune.4',
                'Neptune DB clusters should have deletion protection enabled',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('DeletionProtection') != True:
                self.neptune_list.append(self.create_neptune_item(
                    'Neptune.4',
                    'Neptune DB clusters should have deletion protection enabled',
                    'failed',
                    'LOW',
                    'not_available',
                    response_detail['DBClusterArn']
                ))
            else:
                self.neptune_list.append(self.create_neptune_item(
                    'Neptune.4',
                    'Neptune DB clusters should have deletion protection enabled',
                    'passed',
                    'LOW',
                    'not_available',
                    response_detail['DBClusterArn']
                ))

    @DecoratorClass.my_decorator
    def neptune_five(self) -> None:
        result_list = self.neptune_db_cluster_list()
        if not result_list:
            self.neptune_list.append(self.create_neptune_item(
                'Neptune.5',
                'Neptune DB clusters should have automated backups enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if not isinstance(response_detail.get('BackupRetentionPeriod'), int) or \
                response_detail.get('BackupRetentionPeriod') not in range(7, 36):
                self.neptune_list.append(self.create_neptune_item(
                    'Neptune.5',
                    'Neptune DB clusters should have automated backups enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))
            else:
                self.neptune_list.append(self.create_neptune_item(
                    'Neptune.5',
                    'Neptune DB clusters should have automated backups enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))

    @DecoratorClass.my_decorator
    def neptune_six(self) -> None:
        result_list = self.neptune_db_cluster_snapshot_list()
        if not result_list:
            self.neptune_list.append(self.create_neptune_item(
                'Neptune.6',
                'Neptune DB cluster snapshots should be encrypted at rest',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('StorageEncrypted') != True:
                self.neptune_list.append(self.create_neptune_item(
                    'Neptune.6',
                    'Neptune DB cluster snapshots should be encrypted at rest',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterSnapshotArn']
                ))
            else:
                self.neptune_list.append(self.create_neptune_item(
                    'Neptune.6',
                    'Neptune DB cluster snapshots should be encrypted at rest',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterSnapshotArn']
                ))

    @DecoratorClass.my_decorator
    def neptune_seven(self) -> None:
        result_list = self.neptune_db_cluster_list()
        if not result_list:
            self.neptune_list.append(self.create_neptune_item(
                'Neptune.7',
                'Neptune DB clusters should have IAM database authentication enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('IAMDatabaseAuthenticationEnabled') != True:
                self.neptune_list.append(self.create_neptune_item(
                    'Neptune.7',
                    'Neptune DB clusters should have IAM database authentication enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))
            else:
                self.neptune_list.append(self.create_neptune_item(
                    'Neptune.7',
                    'Neptune DB clusters should have IAM database authentication enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))

    @DecoratorClass.my_decorator
    def neptune_eight(self) -> None:
        result_list = self.neptune_db_cluster_list()
        if not result_list:
            self.neptune_list.append(self.create_neptune_item(
                'Neptune.8',
                'Neptune DB clusters should be configured to copy tags to snapshots',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('CopyTagsToSnapshot') != True:
                self.neptune_list.append(self.create_neptune_item(
                    'Neptune.8',
                    'Neptune DB clusters should be configured to copy tags to snapshots',
                    'failed',
                    'LOW',
                    'not_available',
                    response_detail['DBClusterArn']
                ))
            else:
                self.neptune_list.append(self.create_neptune_item(
                    'Neptune.8',
                    'Neptune DB clusters should be configured to copy tags to snapshots',
                    'passed',
                    'LOW',
                    'not_available',
                    response_detail['DBClusterArn']
                ))

    @DecoratorClass.my_decorator
    def neptune_nine(self) -> None:
        result_list = self.neptune_db_cluster_list()
        if not result_list:
            self.neptune_list.append(self.create_neptune_item(
                'Neptune.9',
                'Neptune DB clusters should be deployed across multiple Availability Zones',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('MultiAZ') != True:
                self.neptune_list.append(self.create_neptune_item(
                    'Neptune.9',
                    'Neptune DB clusters should be deployed across multiple Availability Zones',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))
            else:
                self.neptune_list.append(self.create_neptune_item(
                    'Neptune.9',
                    'Neptune DB clusters should be deployed across multiple Availability Zones',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))

class CrossAccountNeptuneComplianceChecker:
    def __init__(self) -> None:
        self.neptune_client = UseCrossAccount().client('neptune')
        self.neptune_list = compliance_check_list # type: ignore

    def create_neptune_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("Neptune", control_id, compliance, severity, auto_remediation):
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
    
    def neptune_db_cluster_list(self) -> list[dict]:
        dbcluster_list: list[dict] = []
        try:
            response = self.neptune_client.describe_db_clusters()
            dbcluster_list.extend(_ for _ in response['DBClusters'])
            while 'Marker' in response:
                response = self.neptune_client.describe_db_clusters(Marker=response['Marker'])
                dbcluster_list.extend(_ for _ in response['DBClusters'])
            return dbcluster_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def neptune_db_cluster_snapshot_list(self) -> list[dict]:
        dbcluster_snapshot_list: list[dict] = []
        try:
            response = self.neptune_client.describe_db_cluster_snapshots()
            dbcluster_snapshot_list.extend(_ for _ in response['DBClusterSnapshots'])
            while 'Marker' in response:
                response = self.neptune_client.describe_db_cluster_snapshots(Marker=response['Marker'])
                dbcluster_snapshot_list.extend(_ for _ in response['DBClusterSnapshots'])
            return dbcluster_snapshot_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def neptune_db_cluster_snapshot_public_compliant(self, dbcluster_snapshot_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.neptune_client.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=dbcluster_snapshot_arn)
            for detail_resposne in response['DBClusterSnapshots']['DBClusterSnapshotAttributes']:
                if detail_resposne['AttributeName'] == 'restore':
                    if 'all' in detail_resposne['AttributeValues']:
                        compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
    
    @DecoratorClass.my_decorator
    def neptune_one(self) -> None:
        result_list = self.neptune_db_cluster_list()
        if not result_list:
            self.neptune_list.append(self.create_neptune_item(
                'Neptune.1',
                'Neptune DB clusters should be encrypted at rest',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('StorageEncrypted') != True:
                self.neptune_list.append(self.create_neptune_item(
                    'Neptune.1',
                    'Neptune DB clusters should be encrypted at rest',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))
            else:
                self.neptune_list.append(self.create_neptune_item(
                    'Neptune.1',
                    'Neptune DB clusters should be encrypted at rest',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))

    @DecoratorClass.my_decorator
    def neptune_two(self) -> None:
        result_list = self.neptune_db_cluster_list()
        if not result_list:
            self.neptune_list.append(self.create_neptune_item(
                'Neptune.2',
                'Neptune DB clusters should publish audit logs to CloudWatch Logs',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if "audit" not in response_detail.get('EnabledCloudwatchLogsExports', []):
                self.neptune_list.append(self.create_neptune_item(
                    'Neptune.2',
                    'Neptune DB clusters should publish audit logs to CloudWatch Logs',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))
            else:
                self.neptune_list.append(self.create_neptune_item(
                    'Neptune.2',
                    'Neptune DB clusters should publish audit logs to CloudWatch Logs',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))

    @DecoratorClass.my_decorator
    def neptune_three(self) -> None:
        result_list = self.neptune_db_cluster_snapshot_list()
        if not result_list:
            self.neptune_list.append(self.create_neptune_item(
                'Neptune.3',
                'Neptune DB cluster snapshots should not be public',
                'not_found',
                'CRITICAL',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.neptune_db_cluster_snapshot_public_compliant(response_detail['DBClusterSnapshotArn'])
            self.neptune_list.append(self.create_neptune_item(
                'Neptune.3',
                'Neptune DB cluster snapshots should not be public',
                compliant_status,
                'CRITICAL',
                'not_available',
                response_detail['DBClusterSnapshotArn']
            ))

    @DecoratorClass.my_decorator
    def neptune_four(self) -> None:
        result_list = self.neptune_db_cluster_list()
        if not result_list:
            self.neptune_list.append(self.create_neptune_item(
                'Neptune.4',
                'Neptune DB clusters should have deletion protection enabled',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('DeletionProtection') != True:
                self.neptune_list.append(self.create_neptune_item(
                    'Neptune.4',
                    'Neptune DB clusters should have deletion protection enabled',
                    'failed',
                    'LOW',
                    'not_available',
                    response_detail['DBClusterArn']
                ))
            else:
                self.neptune_list.append(self.create_neptune_item(
                    'Neptune.4',
                    'Neptune DB clusters should have deletion protection enabled',
                    'passed',
                    'LOW',
                    'not_available',
                    response_detail['DBClusterArn']
                ))

    @DecoratorClass.my_decorator
    def neptune_five(self) -> None:
        result_list = self.neptune_db_cluster_list()
        if not result_list:
            self.neptune_list.append(self.create_neptune_item(
                'Neptune.5',
                'Neptune DB clusters should have automated backups enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if not isinstance(response_detail.get('BackupRetentionPeriod'), int) or \
                response_detail.get('BackupRetentionPeriod') not in range(7, 36):
                self.neptune_list.append(self.create_neptune_item(
                    'Neptune.5',
                    'Neptune DB clusters should have automated backups enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))
            else:
                self.neptune_list.append(self.create_neptune_item(
                    'Neptune.5',
                    'Neptune DB clusters should have automated backups enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))

    @DecoratorClass.my_decorator
    def neptune_six(self) -> None:
        result_list = self.neptune_db_cluster_snapshot_list()
        if not result_list:
            self.neptune_list.append(self.create_neptune_item(
                'Neptune.6',
                'Neptune DB cluster snapshots should be encrypted at rest',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('StorageEncrypted') != True:
                self.neptune_list.append(self.create_neptune_item(
                    'Neptune.6',
                    'Neptune DB cluster snapshots should be encrypted at rest',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterSnapshotArn']
                ))
            else:
                self.neptune_list.append(self.create_neptune_item(
                    'Neptune.6',
                    'Neptune DB cluster snapshots should be encrypted at rest',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterSnapshotArn']
                ))

    @DecoratorClass.my_decorator
    def neptune_seven(self) -> None:
        result_list = self.neptune_db_cluster_list()
        if not result_list:
            self.neptune_list.append(self.create_neptune_item(
                'Neptune.7',
                'Neptune DB clusters should have IAM database authentication enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('IAMDatabaseAuthenticationEnabled') != True:
                self.neptune_list.append(self.create_neptune_item(
                    'Neptune.7',
                    'Neptune DB clusters should have IAM database authentication enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))
            else:
                self.neptune_list.append(self.create_neptune_item(
                    'Neptune.7',
                    'Neptune DB clusters should have IAM database authentication enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))

    @DecoratorClass.my_decorator
    def neptune_eight(self) -> None:
        result_list = self.neptune_db_cluster_list()
        if not result_list:
            self.neptune_list.append(self.create_neptune_item(
                'Neptune.8',
                'Neptune DB clusters should be configured to copy tags to snapshots',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('CopyTagsToSnapshot') != True:
                self.neptune_list.append(self.create_neptune_item(
                    'Neptune.8',
                    'Neptune DB clusters should be configured to copy tags to snapshots',
                    'failed',
                    'LOW',
                    'not_available',
                    response_detail['DBClusterArn']
                ))
            else:
                self.neptune_list.append(self.create_neptune_item(
                    'Neptune.8',
                    'Neptune DB clusters should be configured to copy tags to snapshots',
                    'passed',
                    'LOW',
                    'not_available',
                    response_detail['DBClusterArn']
                ))

    @DecoratorClass.my_decorator
    def neptune_nine(self) -> None:
        result_list = self.neptune_db_cluster_list()
        if not result_list:
            self.neptune_list.append(self.create_neptune_item(
                'Neptune.9',
                'Neptune DB clusters should be deployed across multiple Availability Zones',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('MultiAZ') != True:
                self.neptune_list.append(self.create_neptune_item(
                    'Neptune.9',
                    'Neptune DB clusters should be deployed across multiple Availability Zones',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))
            else:
                self.neptune_list.append(self.create_neptune_item(
                    'Neptune.9',
                    'Neptune DB clusters should be deployed across multiple Availability Zones',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))