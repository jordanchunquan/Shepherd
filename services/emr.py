'''
Class name EMRComplianceChecker
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

class EMRComplianceChecker:
    def __init__(self) -> None:
        self.emr_client = boto3.client('emr')
        self.session_account = boto3.client('sts').get_caller_identity().get('Account')
        self.emr_list = compliance_check_list

    def create_emr_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("EMR", control_id, compliance, severity, auto_remediation):
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
    
    def emr_cluster_list(self) -> list[dict]:
        cluster_list: list[dict] = []
        try:
            response = self.emr_client.list_clusters()
            cluster_list.extend(_ for _ in response['Clusters'])
            while 'Marker' in response:
                response = self.emr_client.list_clusters(Marker=response['Marker'])
                cluster_list.extend(_ for _ in response['Clusters'])
            return cluster_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def emr_describe_cluster_list(self) -> list[dict]:
        result_list = self.emr_cluster_list()
        cluster_detail_list: list[dict] = []
        for cluster in result_list:
            try:
                response = self.emr_client.describe_cluster(ClusterId=cluster['Id'])
                cluster_detail_list.append(response['Cluster'])
            except ClientError as e:
                print(f"Error: {e}")
                return []
        return cluster_detail_list
    
    def emr_available_cluster_list(self) -> list[dict]:
        result_list = self.emr_describe_cluster_list()
        available_cluster_list: list[dict] = []
        for cluster in result_list:
            if cluster.get('Status', {}).get('State') in ["WAITING","RUNNING"]:
                available_cluster_list.append(cluster)
        return available_cluster_list
    
    def cluster_instance_compliant(self, emr_cluster_id: str) -> str:
        compliant_status = "passed"
        try:
            response = self.emr_client.list_instances(ClusterId=emr_cluster_id)
            for instance in response['Instances']:
                if "PublicIpAddress" in instance:
                    compliant_status = "failed"
            while 'Marker' in response:
                response = self.emr_client.list_instances(ClusterId=emr_cluster_id, Marker=response['Marker'])
                for instance in response['Instances']:
                    if "PublicIpAddress" in instance:
                        compliant_status = "failed"
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        return compliant_status
    
    @DecoratorClass.my_decorator
    def emr_one(self) -> None:
        result_list = self.emr_available_cluster_list()
        if not result_list:
            self.emr_list.append(self.create_emr_item(
                'EMR.1',
                'Amazon EMR cluster primary nodes should not have public IP addresses',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.cluster_instance_compliant(response_detail['Id'])
            self.emr_list.append(self.create_emr_item(
                'EMR.1',
                'Amazon EMR cluster primary nodes should not have public IP addresses',
                compliant_status,
                'HIGH',
                'available',
                response_detail['Id']
            ))

    @DecoratorClass.my_decorator
    def emr_two(self) -> None:
        try:
            response = self.emr_client.get_block_public_access_configuration()
            if not response['BlockPublicAccessConfiguration']['BlockPublicSecurityGroupRules']:
                self.emr_list.append(self.create_emr_item(
                    'EMR.2',
                    'Amazon EMR block public access setting should be enabled',
                    'failed',
                    'CRITICAL',
                    'available',
                    self.session_account
                ))
            else:
                self.emr_list.append(self.create_emr_item(
                    'EMR.2',
                    'Amazon EMR block public access setting should be enabled',
                    'passed',
                    'CRITICAL',
                    'available',
                    self.session_account
                ))
        except ClientError as e:
            print(f"Error: {e}")

class CrossAccountEMRComplianceChecker:
    def __init__(self) -> None:
        self.emr_client = UseCrossAccount().client('emr')
        self.session_account = UseCrossAccount().client('sts').get_caller_identity().get('Account')
        self.emr_list = compliance_check_list

    def create_emr_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("EMR", control_id, compliance, severity, auto_remediation):
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
    
    def emr_cluster_list(self) -> list[dict]:
        cluster_list: list[dict] = []
        try:
            response = self.emr_client.list_clusters()
            cluster_list.extend(_ for _ in response['Clusters'])
            while 'Marker' in response:
                response = self.emr_client.list_clusters(Marker=response['Marker'])
                cluster_list.extend(_ for _ in response['Clusters'])
            return cluster_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def emr_describe_cluster_list(self) -> list[dict]:
        result_list = self.emr_cluster_list()
        cluster_detail_list: list[dict] = []
        for cluster in result_list:
            try:
                response = self.emr_client.describe_cluster(ClusterId=cluster['Id'])
                cluster_detail_list.append(response['Cluster'])
            except ClientError as e:
                print(f"Error: {e}")
                return []
        return cluster_detail_list
    
    def emr_available_cluster_list(self) -> list[dict]:
        result_list = self.emr_describe_cluster_list()
        available_cluster_list: list[dict] = []
        for cluster in result_list:
            if cluster.get('Status', {}).get('State') in ["WAITING","RUNNING"]:
                available_cluster_list.append(cluster)
        return available_cluster_list
    
    def cluster_instance_compliant(self, emr_cluster_id: str) -> str:
        compliant_status = "passed"
        try:
            response = self.emr_client.list_instances(ClusterId=emr_cluster_id)
            for instance in response['Instances']:
                if "PublicIpAddress" in instance:
                    compliant_status = "failed"
            while 'Marker' in response:
                response = self.emr_client.list_instances(ClusterId=emr_cluster_id, Marker=response['Marker'])
                for instance in response['Instances']:
                    if "PublicIpAddress" in instance:
                        compliant_status = "failed"
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        return compliant_status
    
    @DecoratorClass.my_decorator
    def emr_one(self) -> None:
        result_list = self.emr_available_cluster_list()
        if not result_list:
            self.emr_list.append(self.create_emr_item(
                'EMR.1',
                'Amazon EMR cluster primary nodes should not have public IP addresses',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.cluster_instance_compliant(response_detail['Id'])
            self.emr_list.append(self.create_emr_item(
                'EMR.1',
                'Amazon EMR cluster primary nodes should not have public IP addresses',
                compliant_status,
                'HIGH',
                'available',
                response_detail['Id']
            ))

    @DecoratorClass.my_decorator
    def emr_two(self) -> None:
        try:
            response = self.emr_client.get_block_public_access_configuration()
            if not response['BlockPublicAccessConfiguration']['BlockPublicSecurityGroupRules']:
                self.emr_list.append(self.create_emr_item(
                    'EMR.2',
                    'Amazon EMR block public access setting should be enabled',
                    'failed',
                    'CRITICAL',
                    'available',
                    self.session_account
                ))
            else:
                self.emr_list.append(self.create_emr_item(
                    'EMR.2',
                    'Amazon EMR block public access setting should be enabled',
                    'passed',
                    'CRITICAL',
                    'available',
                    self.session_account
                ))
        except ClientError as e:
            print(f"Error: {e}")