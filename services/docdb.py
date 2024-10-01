'''
Class name DocumentDBComplianceChecker
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
from datetime import datetime, timezone

class DocumentDBComplianceChecker:
    def __init__(self) -> None:
        self.docdb_client = boto3.client('docdb')
        self.docdb_list = compliance_check_list

    def create_docdb_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("DocumentDB", control_id, compliance, severity, auto_remediation):
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
    
    def doc_db_list(self) -> list[dict]:
        docdb_list: list[dict] = []
        try:
            response = self.docdb_client.describe_db_clusters()
            docdb_list.extend(_ for _ in response['DBClusters'] if re.match(r'^.*docdb.', _['DBClusterParameterGroup']))
            while 'nextToken' in response:
                response = self.docdb_client.describe_db_clusters(Marker=response['Marker'])
                docdb_list.extend(_ for _ in response['DBClusters'] if re.match(r'^.*docdb.', _['DBClusterParameterGroup']))
            return docdb_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def doc_db_snapshot_list(self) -> list[str]:
        result_list = self.doc_db_list()
        docdb_list: list[str] = []
        try:
            for detail_response in result_list:
                response = self.docdb_client.describe_db_cluster_snapshots(DBClusterIdentifier=detail_response['DBClusterIdentifier'])
                if any([(datetime.now(timezone.utc) - _['SnapshotCreateTime']).days >= 7 \
                    for _ in response['DBClusterSnapshots']]):
                    docdb_list.append(detail_response['DBClusterIdentifier'])
                while 'nextToken' in response:
                    response = self.docdb_client.describe_db_cluster_snapshots(DBClusterIdentifier=detail_response['DBClusterIdentifier'], \
                                                                                Marker=response['Marker'])
                    if any([(datetime.now(timezone.utc) - _['SnapshotCreateTime']).days >= 7 \
                        for _ in response['DBClusterSnapshots']]):
                        docdb_list.append(detail_response['DBClusterIdentifier'])
            return docdb_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def doc_db_manual_snapshot_list(self) -> list[dict]:
        docdb_list: list[dict] = []
        try:
            response = self.docdb_client.describe_db_cluster_snapshots(SnapshotType='manual')
            docdb_list.extend(_ for _ in response['DBClusterSnapshots'])
            while 'nextToken' in response:
                response = self.docdb_client.describe_db_cluster_snapshots(SnapshotType='manual', Marker=response['Marker'])
                docdb_list.extend(_ for _ in response['DBClusterSnapshots'])
            return docdb_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def doc_db_public_snapshot_list(self) -> list[str]:
        docdb_list: list[str] = []
        try:
            response = self.docdb_client.describe_db_cluster_snapshots(IncludePublic=True)
            for _ in response['DBClusterSnapshots']:
                docdb_list.append(_['DBClusterSnapshotArn'])
            while 'nextToken' in response:
                response = self.docdb_client.describe_db_cluster_snapshots(IncludePublic=True, Marker=response['Marker'])
                for _ in response['DBClusterSnapshots']:
                    docdb_list.append(_['DBClusterSnapshotArn'])
            return docdb_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    @DecoratorClass.my_decorator
    def docdb_one(self) -> None:
        result_list = self.doc_db_list()
        if not result_list:
            self.docdb_list.append(self.create_docdb_item(
                'DocumentDB.1',
                'Amazon DocumentDB clusters should be encrypted at rest',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['StorageEncrypted'] == False:
                self.docdb_list.append(self.create_docdb_item(
                    'DocumentDB.1',
                    'Amazon DocumentDB clusters should be encrypted at rest',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))
            else:
                self.docdb_list.append(self.create_docdb_item(
                    'DocumentDB.1',
                    'Amazon DocumentDB clusters should be encrypted at rest',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))

    @DecoratorClass.my_decorator
    def docdb_two(self) -> None:
        snapshot_list = self.doc_db_snapshot_list()
        result_list = self.doc_db_list()
        if not result_list:
            self.docdb_list.append(self.create_docdb_item(
                'DocumentDB.2',
                'Amazon DocumentDB clusters should have an adequate backup retention period',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['DBClusterIdentifier'] not in snapshot_list:
                self.docdb_list.append(self.create_docdb_item(
                    'DocumentDB.2',
                    'Amazon DocumentDB clusters should have an adequate backup retention period',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))
            else:
                self.docdb_list.append(self.create_docdb_item(
                    'DocumentDB.2',
                    'Amazon DocumentDB clusters should have an adequate backup retention period',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))

    @DecoratorClass.my_decorator
    def docdb_three(self) -> None:
        result_list = self.doc_db_manual_snapshot_list()
        db_cluster_id_list = [_['DBClusterIdentifier'] for _ in self.doc_db_list()]
        public_snapshot_list = self.doc_db_public_snapshot_list()
        if not result_list or all([_['DBClusterIdentifier'] not in db_cluster_id_list for _ in result_list]):
            self.docdb_list.append(self.create_docdb_item(
                'DocumentDB.3',
                'Amazon DocumentDB manual cluster snapshots should not be public',
                'not_found',
                'CRITICAL',
                'not_available',
                'not_found'
            ))
        else:
            for response_detail in result_list:
                if response_detail['DBClusterSnapshotArn'] in public_snapshot_list \
                    and response_detail['DBClusterIdentifier'] not in db_cluster_id_list:
                    self.docdb_list.append(self.create_docdb_item(
                        'DocumentDB.3',
                        'Amazon DocumentDB manual cluster snapshots should not be public',
                        'failed',
                        'CRITICAL',
                        'not_available',
                        response_detail['DBClusterSnapshotArn']
                    ))
                else:
                    self.docdb_list.append(self.create_docdb_item(
                        'DocumentDB.3',
                        'Amazon DocumentDB manual cluster snapshots should not be public',
                        'passed',
                        'CRITICAL',
                        'not_available',
                        response_detail['DBClusterSnapshotArn']
                    ))

    @DecoratorClass.my_decorator
    def docdb_four(self) -> None:
        result_list = self.doc_db_list()
        if not result_list:
            self.docdb_list.append(self.create_docdb_item(
                'DocumentDB.4',
                'Amazon DocumentDB clusters should publish audit logs to CloudWatch Logs',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if 'none' in response_detail['EnabledCloudwatchLogsExports']:
                self.docdb_list.append(self.create_docdb_item(
                    'DocumentDB.4',
                    'Amazon DocumentDB clusters should publish audit logs to CloudWatch Logs',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))
            else:
                self.docdb_list.append(self.create_docdb_item(
                    'DocumentDB.4',
                    'Amazon DocumentDB clusters should publish audit logs to CloudWatch Logs',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))

    @DecoratorClass.my_decorator
    def docdb_five(self) -> None:
        result_list = self.doc_db_list()
        if not result_list:
            self.docdb_list.append(self.create_docdb_item(
                'DocumentDB.5',
                'Amazon DocumentDB clusters should have deletion protection enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['DeletionProtection'] == False:
                self.docdb_list.append(self.create_docdb_item(
                    'DocumentDB.5',
                    'Amazon DocumentDB clusters should have deletion protection enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))
            else:
                self.docdb_list.append(self.create_docdb_item(
                    'DocumentDB.5',
                    'Amazon DocumentDB clusters should have deletion protection enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))

class CrossAccountDocumentDBComplianceChecker:
    def __init__(self) -> None:
        self.docdb_client = UseCrossAccount().client('docdb')
        self.docdb_list = compliance_check_list

    def create_docdb_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("DocumentDB", control_id, compliance, severity, auto_remediation):
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
    
    def doc_db_list(self) -> list[dict]:
        docdb_list: list[dict] = []
        try:
            response = self.docdb_client.describe_db_clusters()
            docdb_list.extend(_ for _ in response['DBClusters'] if re.match(r'^.*docdb.', _['DBClusterParameterGroup']))
            while 'nextToken' in response:
                response = self.docdb_client.describe_db_clusters(Marker=response['Marker'])
                docdb_list.extend(_ for _ in response['DBClusters'] if re.match(r'^.*docdb.', _['DBClusterParameterGroup']))
            return docdb_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def doc_db_snapshot_list(self) -> list[str]:
        result_list = self.doc_db_list()
        docdb_list: list[str] = []
        try:
            for detail_response in result_list:
                response = self.docdb_client.describe_db_cluster_snapshots(DBClusterIdentifier=detail_response['DBClusterIdentifier'])
                if any([(datetime.now(timezone.utc) - _['SnapshotCreateTime']).days >= 7 \
                    for _ in response['DBClusterSnapshots']]):
                    docdb_list.append(detail_response['DBClusterIdentifier'])
                while 'nextToken' in response:
                    response = self.docdb_client.describe_db_cluster_snapshots(DBClusterIdentifier=detail_response['DBClusterIdentifier'], \
                                                                                Marker=response['Marker'])
                    if any([(datetime.now(timezone.utc) - _['SnapshotCreateTime']).days >= 7 \
                        for _ in response['DBClusterSnapshots']]):
                        docdb_list.append(detail_response['DBClusterIdentifier'])
            return docdb_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def doc_db_manual_snapshot_list(self) -> list[dict]:
        docdb_list: list[dict] = []
        try:
            response = self.docdb_client.describe_db_cluster_snapshots(SnapshotType='manual')
            docdb_list.extend(_ for _ in response['DBClusterSnapshots'])
            while 'nextToken' in response:
                response = self.docdb_client.describe_db_cluster_snapshots(SnapshotType='manual', Marker=response['Marker'])
                docdb_list.extend(_ for _ in response['DBClusterSnapshots'])
            return docdb_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def doc_db_public_snapshot_list(self) -> list[str]:
        docdb_list: list[str] = []
        try:
            response = self.docdb_client.describe_db_cluster_snapshots(IncludePublic=True)
            for _ in response['DBClusterSnapshots']:
                docdb_list.append(_['DBClusterSnapshotArn'])
            while 'nextToken' in response:
                response = self.docdb_client.describe_db_cluster_snapshots(IncludePublic=True, Marker=response['Marker'])
                for _ in response['DBClusterSnapshots']:
                    docdb_list.append(_['DBClusterSnapshotArn'])
            return docdb_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    @DecoratorClass.my_decorator
    def docdb_one(self) -> None:
        result_list = self.doc_db_list()
        if not result_list:
            self.docdb_list.append(self.create_docdb_item(
                'DocumentDB.1',
                'Amazon DocumentDB clusters should be encrypted at rest',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['StorageEncrypted'] == False:
                self.docdb_list.append(self.create_docdb_item(
                    'DocumentDB.1',
                    'Amazon DocumentDB clusters should be encrypted at rest',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))
            else:
                self.docdb_list.append(self.create_docdb_item(
                    'DocumentDB.1',
                    'Amazon DocumentDB clusters should be encrypted at rest',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))

    @DecoratorClass.my_decorator
    def docdb_two(self) -> None:
        snapshot_list = self.doc_db_snapshot_list()
        result_list = self.doc_db_list()
        if not result_list:
            self.docdb_list.append(self.create_docdb_item(
                'DocumentDB.2',
                'Amazon DocumentDB clusters should have an adequate backup retention period',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['DBClusterIdentifier'] not in snapshot_list:
                self.docdb_list.append(self.create_docdb_item(
                    'DocumentDB.2',
                    'Amazon DocumentDB clusters should have an adequate backup retention period',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))
            else:
                self.docdb_list.append(self.create_docdb_item(
                    'DocumentDB.2',
                    'Amazon DocumentDB clusters should have an adequate backup retention period',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))

    @DecoratorClass.my_decorator
    def docdb_three(self) -> None:
        result_list = self.doc_db_manual_snapshot_list()
        db_cluster_id_list = [_['DBClusterIdentifier'] for _ in self.doc_db_list()]
        public_snapshot_list = self.doc_db_public_snapshot_list()
        if not result_list or all([_['DBClusterIdentifier'] not in db_cluster_id_list for _ in result_list]):
            self.docdb_list.append(self.create_docdb_item(
                'DocumentDB.3',
                'Amazon DocumentDB manual cluster snapshots should not be public',
                'not_found',
                'CRITICAL',
                'not_available',
                'not_found'
            ))
        else:
            for response_detail in result_list:
                if response_detail['DBClusterSnapshotArn'] in public_snapshot_list \
                    and response_detail['DBClusterIdentifier'] not in db_cluster_id_list:
                    self.docdb_list.append(self.create_docdb_item(
                        'DocumentDB.3',
                        'Amazon DocumentDB manual cluster snapshots should not be public',
                        'failed',
                        'CRITICAL',
                        'not_available',
                        response_detail['DBClusterSnapshotArn']
                    ))
                else:
                    self.docdb_list.append(self.create_docdb_item(
                        'DocumentDB.3',
                        'Amazon DocumentDB manual cluster snapshots should not be public',
                        'passed',
                        'CRITICAL',
                        'not_available',
                        response_detail['DBClusterSnapshotArn']
                    ))

    @DecoratorClass.my_decorator
    def docdb_four(self) -> None:
        result_list = self.doc_db_list()
        if not result_list:
            self.docdb_list.append(self.create_docdb_item(
                'DocumentDB.4',
                'Amazon DocumentDB clusters should publish audit logs to CloudWatch Logs',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if 'none' in response_detail['EnabledCloudwatchLogsExports']:
                self.docdb_list.append(self.create_docdb_item(
                    'DocumentDB.4',
                    'Amazon DocumentDB clusters should publish audit logs to CloudWatch Logs',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))
            else:
                self.docdb_list.append(self.create_docdb_item(
                    'DocumentDB.4',
                    'Amazon DocumentDB clusters should publish audit logs to CloudWatch Logs',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))

    @DecoratorClass.my_decorator
    def docdb_five(self) -> None:
        result_list = self.doc_db_list()
        if not result_list:
            self.docdb_list.append(self.create_docdb_item(
                'DocumentDB.5',
                'Amazon DocumentDB clusters should have deletion protection enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['DeletionProtection'] == False:
                self.docdb_list.append(self.create_docdb_item(
                    'DocumentDB.5',
                    'Amazon DocumentDB clusters should have deletion protection enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))
            else:
                self.docdb_list.append(self.create_docdb_item(
                    'DocumentDB.5',
                    'Amazon DocumentDB clusters should have deletion protection enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['DBClusterArn']
                ))