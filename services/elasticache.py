'''
Class name ElastiCacheComplianceChecker
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

class ElastiCacheComplianceChecker:
    def __init__(self) -> None:
        self.recommended_replication_group_version = float(6.0)
        self.elasticache_client = boto3.client('elasticache')
        self.elasticache_list = compliance_check_list

    def create_elasticache_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("ElastiCache", control_id, compliance, severity, auto_remediation):
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
    
    def describe_elasticache_list(self) -> list[dict]:
        elasticache_list: list[dict] = []
        try:
            response = self.elasticache_client.describe_cache_clusters()
            elasticache_list.extend(_ for _ in response['CacheClusters'])
            while 'Marker' in response:
                response = self.elasticache_client.describe_cache_clusters(Marker=response['Marker'])
                elasticache_list.extend(_ for _ in response['CacheClusters'])
            return elasticache_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def describe_elasticache_replication_group_list(self) -> list[dict]:
        replication_group_list: list[dict] = []
        try:
            response = self.elasticache_client.describe_replication_groups()
            replication_group_list.extend(_ for _ in response['ReplicationGroups'])
            while 'Marker' in response:
                response = self.elasticache_client.describe_replication_groups(Marker=response['Marker'])
                replication_group_list.extend(_ for _ in response['ReplicationGroups'])
            return replication_group_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def describe_elasticache_global_replication_group_list(self) -> list[dict]:
        replication_group_list: list[dict] = []
        try:
            response = self.elasticache_client.describe_global_replication_groups()
            replication_group_list.extend(_ for _ in response['GlobalReplicationGroups'])
            while 'Marker' in response:
                response = self.elasticache_client.describe_global_replication_groups(Marker=response['Marker'])
                replication_group_list.extend(_ for _ in response['GlobalReplicationGroups'])
            return replication_group_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def describe_elasticache_cache_cluster_list(self) -> list[dict]:
        cache_cluster_list: list[dict] = []
        try:
            response = self.elasticache_client.describe_cache_clusters()
            cache_cluster_list.extend(_ for _ in response['CacheClusters'])
            while 'Marker' in response:
                response = self.elasticache_client.describe_cache_clusters(Marker=response['Marker'])
                cache_cluster_list.extend(_ for _ in response['CacheClusters'])
            return cache_cluster_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    @DecoratorClass.my_decorator
    def elasticache_one(self) -> None:
        result_list = self.describe_elasticache_list()
        if not result_list:
            self.elasticache_list.append(self.create_elasticache_item(
                'ElastiCache.1',
                'ElastiCache Redis clusters should have automatic backup enabled',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['SnapshotRetentionLimit'] < 1:
                self.elasticache_list.append(self.create_elasticache_item(
                    'ElastiCache.1',
                    'ElastiCache Redis clusters should have automatic backup enabled',
                    'failed',
                    'HIGH',
                    'not_available',
                    response_detail['ARN']
                ))
            self.elasticache_list.append(self.create_elasticache_item(
                'ElastiCache.1',
                'ElastiCache Redis clusters should have automatic backup enabled',
                'passed',
                'HIGH',
                'not_available',
                response_detail['ARN']
            ))
    
    @DecoratorClass.my_decorator
    def elasticache_two(self) -> None:
        result_list = self.describe_elasticache_list()
        if not result_list:
            self.elasticache_list.append(self.create_elasticache_item(
                'ElastiCache.2',
                'ElastiCache for Redis cache clusters should have auto minor version upgrade enabled',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['AutoMinorVersionUpgrade'] == False:
                self.elasticache_list.append(self.create_elasticache_item(
                    'ElastiCache.2',
                    'ElastiCache for Redis cache clusters should have auto minor version upgrade enabled',
                    'failed',
                    'HIGH',
                    'not_available',
                    response_detail['ARN']
                ))
            self.elasticache_list.append(self.create_elasticache_item(
                'ElastiCache.2',
                'ElastiCache for Redis cache clusters should have auto minor version upgrade enabled',
                'passed',
                'HIGH',
                'not_available',
                response_detail['ARN']
            ))
    
    @DecoratorClass.my_decorator
    def elasticache_three(self) -> None:
        result_list = self.describe_elasticache_replication_group_list()
        global_result_list = self.describe_elasticache_global_replication_group_list()
        if not result_list and not global_result_list:
            self.elasticache_list.append(self.create_elasticache_item(
                'ElastiCache.3',
                'ElastiCache for Redis replication groups should have automatic failover enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['AutomaticFailover'] != "enabled":
                self.elasticache_list.append(self.create_elasticache_item(
                    'ElastiCache.3',
                    'ElastiCache for Redis replication groups should have automatic failover enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))
            else:
                self.elasticache_list.append(self.create_elasticache_item(
                    'ElastiCache.3',
                    'ElastiCache for Redis replication groups should have automatic failover enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))
        for global_response_detail in global_result_list:
            compliant_status = "passed"
            if any([member['AutomaticFailover'] != "enabled" for member in global_response_detail['Members']]):
                compliant_status = "failed"
            self.elasticache_list.append(self.create_elasticache_item(
                'ElastiCache.3',
                'ElastiCache for Redis replication groups should have automatic failover enabled',
                compliant_status,
                'MEDIUM',
                'not_available',
                global_response_detail['ARN']
            ))
    
    @DecoratorClass.my_decorator
    def elasticache_four(self) -> None:
        result_list = self.describe_elasticache_replication_group_list()
        global_result_list = self.describe_elasticache_global_replication_group_list()
        if not result_list and not global_result_list:
            self.elasticache_list.append(self.create_elasticache_item(
                'ElastiCache.4',
                'ElastiCache for Redis replication groups should be encrypted at rest',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['AtRestEncryptionEnabled'] == False:
                self.elasticache_list.append(self.create_elasticache_item(
                    'ElastiCache.4',
                    'ElastiCache for Redis replication groups should be encrypted at rest',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))
            else:
                self.elasticache_list.append(self.create_elasticache_item(
                    'ElastiCache.4',
                    'ElastiCache for Redis replication groups should be encrypted at rest',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))
        for global_response_detail in global_result_list:
            if global_response_detail['AtRestEncryptionEnabled'] == False:
                self.elasticache_list.append(self.create_elasticache_item(
                    'ElastiCache.4',
                    'ElastiCache for Redis replication groups should be encrypted at rest',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    global_response_detail['ARN']
                ))
            else:
                self.elasticache_list.append(self.create_elasticache_item(
                    'ElastiCache.4',
                    'ElastiCache for Redis replication groups should be encrypted at rest',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    global_response_detail['ARN']
                ))
    
    @DecoratorClass.my_decorator
    def elasticache_five(self) -> None:
        result_list = self.describe_elasticache_replication_group_list()
        global_result_list = self.describe_elasticache_global_replication_group_list()
        if not result_list and not global_result_list:
            self.elasticache_list.append(self.create_elasticache_item(
                'ElastiCache.5',
                'ElastiCache for Redis replication groups should be encrypted in transit',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['TransitEncryptionEnabled'] == False:
                self.elasticache_list.append(self.create_elasticache_item(
                    'ElastiCache.5',
                    'ElastiCache for Redis replication groups should be encrypted in transit',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))
            else:
                self.elasticache_list.append(self.create_elasticache_item(
                    'ElastiCache.5',
                    'ElastiCache for Redis replication groups should be encrypted in transit',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))
        for global_response_detail in global_result_list:
            if global_response_detail['TransitEncryptionEnabled'] == False:
                self.elasticache_list.append(self.create_elasticache_item(
                    'ElastiCache.5',
                    'ElastiCache for Redis replication groups should be encrypted in transit',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    global_response_detail['ARN']
                ))
            else:
                self.elasticache_list.append(self.create_elasticache_item(
                    'ElastiCache.5',
                    'ElastiCache for Redis replication groups should be encrypted in transit',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    global_response_detail['ARN']
                ))
    
    @DecoratorClass.my_decorator
    def elasticache_six(self) -> None:
        updated_version_list = [_['CacheClusterId'] for _ in self.describe_elasticache_cache_cluster_list() if float(_['EngineVersion'] >= self.recommended_replication_group_version)]
        result_list = self.describe_elasticache_replication_group_list()
        global_result_list = self.describe_elasticache_global_replication_group_list()
        if not result_list and not global_result_list:
            self.elasticache_list.append(self.create_elasticache_item(
                'ElastiCache.6',
                'ElastiCache for Redis replication groups before version 6.0 should use Redis AUTH',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if not any([node_member['CacheClusterId'] not in updated_version_list for node_group in response_detail['NodeGroups'] for node_member in node_group['NodeGroupMembers']]):
                if response_detail['AuthTokenEnabled'] == False:
                    compliant_status = "failed"
            self.elasticache_list.append(self.create_elasticache_item(
                'ElastiCache.6',
                'ElastiCache for Redis replication groups before version 6.0 should use Redis AUTH',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['ARN']
            ))
        for global_response_detail in global_result_list:
            global_compliant_status = "passed"
            if float(global_response_detail['EngineVersion']) < self.recommended_replication_group_version:
                if global_response_detail['AuthTokenEnabled'] == False:
                    global_compliant_status = "failed"
            self.elasticache_list.append(self.create_elasticache_item(
                'ElastiCache.6',
                'ElastiCache for Redis replication groups before version 6.0 should use Redis AUTH',
                global_compliant_status,
                'MEDIUM',
                'not_available',
                global_response_detail['ARN']
            ))
    
    @DecoratorClass.my_decorator
    def elasticache_seven(self) -> None:
        result_list = self.describe_elasticache_cache_cluster_list()
        if not result_list:
            self.elasticache_list.append(self.create_elasticache_item(
                'ElastiCache.7',
                'ElastiCache clusters should not use the default subnet group',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['CacheSubnetGroupName'] == "default":
                self.elasticache_list.append(self.create_elasticache_item(
                    'ElastiCache.7',
                    'ElastiCache clusters should not use the default subnet group',
                    'failed',
                    'HIGH',
                    'not_available',
                    response_detail['ARN']
                ))
            else:
                self.elasticache_list.append(self.create_elasticache_item(
                    'ElastiCache.7',
                    'ElastiCache clusters should not use the default subnet group',
                    'passed',
                    'HIGH',
                    'not_available',
                    response_detail['ARN']
                ))

class CrossAccountElastiCacheComplianceChecker:
    def __init__(self) -> None:
        self.recommended_replication_group_version = float(6.0)
        self.elasticache_client = UseCrossAccount().client('elasticache')
        self.elasticache_list = compliance_check_list

    def create_elasticache_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("ElastiCache", control_id, compliance, severity, auto_remediation):
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
    
    def describe_elasticache_list(self) -> list[dict]:
        elasticache_list: list[dict] = []
        try:
            response = self.elasticache_client.describe_cache_clusters()
            elasticache_list.extend(_ for _ in response['CacheClusters'])
            while 'Marker' in response:
                response = self.elasticache_client.describe_cache_clusters(Marker=response['Marker'])
                elasticache_list.extend(_ for _ in response['CacheClusters'])
            return elasticache_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def describe_elasticache_replication_group_list(self) -> list[dict]:
        replication_group_list: list[dict] = []
        try:
            response = self.elasticache_client.describe_replication_groups()
            replication_group_list.extend(_ for _ in response['ReplicationGroups'])
            while 'Marker' in response:
                response = self.elasticache_client.describe_replication_groups(Marker=response['Marker'])
                replication_group_list.extend(_ for _ in response['ReplicationGroups'])
            return replication_group_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def describe_elasticache_global_replication_group_list(self) -> list[dict]:
        replication_group_list: list[dict] = []
        try:
            response = self.elasticache_client.describe_global_replication_groups()
            replication_group_list.extend(_ for _ in response['GlobalReplicationGroups'])
            while 'Marker' in response:
                response = self.elasticache_client.describe_global_replication_groups(Marker=response['Marker'])
                replication_group_list.extend(_ for _ in response['GlobalReplicationGroups'])
            return replication_group_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def describe_elasticache_cache_cluster_list(self) -> list[dict]:
        cache_cluster_list: list[dict] = []
        try:
            response = self.elasticache_client.describe_cache_clusters()
            cache_cluster_list.extend(_ for _ in response['CacheClusters'])
            while 'Marker' in response:
                response = self.elasticache_client.describe_cache_clusters(Marker=response['Marker'])
                cache_cluster_list.extend(_ for _ in response['CacheClusters'])
            return cache_cluster_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    @DecoratorClass.my_decorator
    def elasticache_one(self) -> None:
        result_list = self.describe_elasticache_list()
        if not result_list:
            self.elasticache_list.append(self.create_elasticache_item(
                'ElastiCache.1',
                'ElastiCache Redis clusters should have automatic backup enabled',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['SnapshotRetentionLimit'] < 1:
                self.elasticache_list.append(self.create_elasticache_item(
                    'ElastiCache.1',
                    'ElastiCache Redis clusters should have automatic backup enabled',
                    'failed',
                    'HIGH',
                    'not_available',
                    response_detail['ARN']
                ))
            self.elasticache_list.append(self.create_elasticache_item(
                'ElastiCache.1',
                'ElastiCache Redis clusters should have automatic backup enabled',
                'passed',
                'HIGH',
                'not_available',
                response_detail['ARN']
            ))
    
    @DecoratorClass.my_decorator
    def elasticache_two(self) -> None:
        result_list = self.describe_elasticache_list()
        if not result_list:
            self.elasticache_list.append(self.create_elasticache_item(
                'ElastiCache.2',
                'ElastiCache for Redis cache clusters should have auto minor version upgrade enabled',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['AutoMinorVersionUpgrade'] == False:
                self.elasticache_list.append(self.create_elasticache_item(
                    'ElastiCache.2',
                    'ElastiCache for Redis cache clusters should have auto minor version upgrade enabled',
                    'failed',
                    'HIGH',
                    'not_available',
                    response_detail['ARN']
                ))
            self.elasticache_list.append(self.create_elasticache_item(
                'ElastiCache.2',
                'ElastiCache for Redis cache clusters should have auto minor version upgrade enabled',
                'passed',
                'HIGH',
                'not_available',
                response_detail['ARN']
            ))
    
    @DecoratorClass.my_decorator
    def elasticache_three(self) -> None:
        result_list = self.describe_elasticache_replication_group_list()
        global_result_list = self.describe_elasticache_global_replication_group_list()
        if not result_list and not global_result_list:
            self.elasticache_list.append(self.create_elasticache_item(
                'ElastiCache.3',
                'ElastiCache for Redis replication groups should have automatic failover enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['AutomaticFailover'] != "enabled":
                self.elasticache_list.append(self.create_elasticache_item(
                    'ElastiCache.3',
                    'ElastiCache for Redis replication groups should have automatic failover enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))
            else:
                self.elasticache_list.append(self.create_elasticache_item(
                    'ElastiCache.3',
                    'ElastiCache for Redis replication groups should have automatic failover enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))
        for global_response_detail in global_result_list:
            compliant_status = "passed"
            if any([member['AutomaticFailover'] != "enabled" for member in global_response_detail['Members']]):
                compliant_status = "failed"
            self.elasticache_list.append(self.create_elasticache_item(
                'ElastiCache.3',
                'ElastiCache for Redis replication groups should have automatic failover enabled',
                compliant_status,
                'MEDIUM',
                'not_available',
                global_response_detail['ARN']
            ))
    
    @DecoratorClass.my_decorator
    def elasticache_four(self) -> None:
        result_list = self.describe_elasticache_replication_group_list()
        global_result_list = self.describe_elasticache_global_replication_group_list()
        if not result_list and not global_result_list:
            self.elasticache_list.append(self.create_elasticache_item(
                'ElastiCache.4',
                'ElastiCache for Redis replication groups should be encrypted at rest',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['AtRestEncryptionEnabled'] == False:
                self.elasticache_list.append(self.create_elasticache_item(
                    'ElastiCache.4',
                    'ElastiCache for Redis replication groups should be encrypted at rest',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))
            else:
                self.elasticache_list.append(self.create_elasticache_item(
                    'ElastiCache.4',
                    'ElastiCache for Redis replication groups should be encrypted at rest',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))
        for global_response_detail in global_result_list:
            if global_response_detail['AtRestEncryptionEnabled'] == False:
                self.elasticache_list.append(self.create_elasticache_item(
                    'ElastiCache.4',
                    'ElastiCache for Redis replication groups should be encrypted at rest',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    global_response_detail['ARN']
                ))
            else:
                self.elasticache_list.append(self.create_elasticache_item(
                    'ElastiCache.4',
                    'ElastiCache for Redis replication groups should be encrypted at rest',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    global_response_detail['ARN']
                ))
    
    @DecoratorClass.my_decorator
    def elasticache_five(self) -> None:
        result_list = self.describe_elasticache_replication_group_list()
        global_result_list = self.describe_elasticache_global_replication_group_list()
        if not result_list and not global_result_list:
            self.elasticache_list.append(self.create_elasticache_item(
                'ElastiCache.5',
                'ElastiCache for Redis replication groups should be encrypted in transit',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['TransitEncryptionEnabled'] == False:
                self.elasticache_list.append(self.create_elasticache_item(
                    'ElastiCache.5',
                    'ElastiCache for Redis replication groups should be encrypted in transit',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))
            else:
                self.elasticache_list.append(self.create_elasticache_item(
                    'ElastiCache.5',
                    'ElastiCache for Redis replication groups should be encrypted in transit',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ARN']
                ))
        for global_response_detail in global_result_list:
            if global_response_detail['TransitEncryptionEnabled'] == False:
                self.elasticache_list.append(self.create_elasticache_item(
                    'ElastiCache.5',
                    'ElastiCache for Redis replication groups should be encrypted in transit',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    global_response_detail['ARN']
                ))
            else:
                self.elasticache_list.append(self.create_elasticache_item(
                    'ElastiCache.5',
                    'ElastiCache for Redis replication groups should be encrypted in transit',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    global_response_detail['ARN']
                ))
    
    @DecoratorClass.my_decorator
    def elasticache_six(self) -> None:
        updated_version_list = [_['CacheClusterId'] for _ in self.describe_elasticache_cache_cluster_list() if float(_['EngineVersion'] >= self.recommended_replication_group_version)]
        result_list = self.describe_elasticache_replication_group_list()
        global_result_list = self.describe_elasticache_global_replication_group_list()
        if not result_list and not global_result_list:
            self.elasticache_list.append(self.create_elasticache_item(
                'ElastiCache.6',
                'ElastiCache for Redis replication groups before version 6.0 should use Redis AUTH',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if not any([node_member['CacheClusterId'] not in updated_version_list for node_group in response_detail['NodeGroups'] for node_member in node_group['NodeGroupMembers']]):
                if response_detail['AuthTokenEnabled'] == False:
                    compliant_status = "failed"
            self.elasticache_list.append(self.create_elasticache_item(
                'ElastiCache.6',
                'ElastiCache for Redis replication groups before version 6.0 should use Redis AUTH',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['ARN']
            ))
        for global_response_detail in global_result_list:
            global_compliant_status = "passed"
            if float(global_response_detail['EngineVersion']) < self.recommended_replication_group_version:
                if global_response_detail['AuthTokenEnabled'] == False:
                    global_compliant_status = "failed"
            self.elasticache_list.append(self.create_elasticache_item(
                'ElastiCache.6',
                'ElastiCache for Redis replication groups before version 6.0 should use Redis AUTH',
                global_compliant_status,
                'MEDIUM',
                'not_available',
                global_response_detail['ARN']
            ))
    
    @DecoratorClass.my_decorator
    def elasticache_seven(self) -> None:
        result_list = self.describe_elasticache_cache_cluster_list()
        if not result_list:
            self.elasticache_list.append(self.create_elasticache_item(
                'ElastiCache.7',
                'ElastiCache clusters should not use the default subnet group',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['CacheSubnetGroupName'] == "default":
                self.elasticache_list.append(self.create_elasticache_item(
                    'ElastiCache.7',
                    'ElastiCache clusters should not use the default subnet group',
                    'failed',
                    'HIGH',
                    'not_available',
                    response_detail['ARN']
                ))
            else:
                self.elasticache_list.append(self.create_elasticache_item(
                    'ElastiCache.7',
                    'ElastiCache clusters should not use the default subnet group',
                    'passed',
                    'HIGH',
                    'not_available',
                    response_detail['ARN']
                ))