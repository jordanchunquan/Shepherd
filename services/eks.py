'''
Class name EKSComplianceChecker
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

class EKSComplianceChecker:
    def __init__(self) -> None:
        self.eks_oldest_version = "1.28"
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.eks_client = boto3.client('eks')
        self.eks_list = compliance_check_list

    def create_eks_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("EKS", control_id, compliance, severity, auto_remediation):
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
    
    def eks_cluster_list(self) -> list[str]:
        cluster_list: list[str] = []
        try:
            response = self.eks_client.list_clusters()
            for response_detail in response['clusters']:
                cluster_list.append(response_detail)
            while 'nextToken' in response:
                response = self.eks_client.list_clusters(nextToken=response['nextToken'])
                for response_detail in response['clusters']:
                    cluster_list.append(response_detail)
            return cluster_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def describe_eks_cluster_list(self) -> list[dict]:
        cluster_list: list[dict] = []
        result_list = self.eks_cluster_list()
        for response_detail in result_list:
            try:
                response = self.eks_client.describe_cluster(name=response_detail)
                cluster_list.extend(_ for _ in response['cluster'])
                while 'nextToken' in response:
                    response = self.eks_client.describe_cluster(nextToken=response['nextToken'])
                    cluster_list.extend(_ for _ in response['cluster'])
            except ClientError as e:
                print(f"Error: {e}")
                return []
        return cluster_list
    
    def eks_identity_provider_list(self) -> list[dict]:
        identity_provider_list: list[dict] = []
        result_list = self.eks_cluster_list()
        for response_detail in result_list:
            try:
                identity_provider_response = self.eks_client.list_identity_provider_configs(name=response_detail)
                for identity_provider_response_detail in identity_provider_response['identityProviderConfigs']:
                    response = self.eks_client.describe_identity_provider_config(name=response_detail, identityProviderConfig=identity_provider_response_detail)
                    identity_provider_list.extend(_ for _ in response['identityProviderConfig'])
                while 'nextToken' in identity_provider_response:
                    identity_provider_response = self.eks_client.list_identity_provider_configs(nextToken=identity_provider_response['nextToken'])
                    for identity_provider_response_detail in identity_provider_response['identityProviderConfigs']:
                        response = self.eks_client.describe_identity_provider_config(name=response_detail, identityProviderConfig=identity_provider_response_detail)
                        identity_provider_list.extend(_ for _ in response['identityProviderConfig'])
            except ClientError as e:
                print(f"Error: {e}")
                return []
        return identity_provider_list
    
    @DecoratorClass.my_decorator
    def eks_one(self) -> None:
        result_list = self.describe_eks_cluster_list()
        if not result_list:
            self.eks_list.append(self.create_eks_item(
                'EKS.1',
                'EKS cluster endpoints should not be publicly accessible',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['resourcesVpcConfig']['endpointPublicAccess'] == True:
                self.eks_list.append(self.create_eks_item(
                    'EKS.1',
                    'EKS cluster endpoints should not be publicly accessible',
                    'failed',
                    'HIGH',
                    'not_available',
                    response_detail['arn']
                ))
            else:
                self.eks_list.append(self.create_eks_item(
                    'EKS.1',
                    'EKS cluster endpoints should not be publicly accessible',
                    'passed',
                    'HIGH',
                    'not_available',
                    response_detail['arn']
                ))
    
    @DecoratorClass.my_decorator
    def eks_two(self) -> None:
        result_list = self.describe_eks_cluster_list()
        if not result_list:
            self.eks_list.append(self.create_eks_item(
                'EKS.2',
                'EKS clusters should run on a supported Kubernetes version',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if float(response_detail['platformVersion']) < float(self.eks_oldest_version):
                self.eks_list.append(self.create_eks_item(
                    'EKS.2',
                    'EKS clusters should run on a supported Kubernetes version',
                    'failed',
                    'HIGH',
                    'not_available',
                    response_detail['arn']
                ))
            else:
                self.eks_list.append(self.create_eks_item(
                    'EKS.2',
                    'EKS clusters should run on a supported Kubernetes version',
                    'passed',
                    'HIGH',
                    'not_available',
                    response_detail['arn']
                ))
    
    @DecoratorClass.my_decorator
    def eks_three(self) -> None:
        result_list = self.describe_eks_cluster_list()
        if not result_list:
            self.eks_list.append(self.create_eks_item(
                'EKS.3',
                'EKS clusters should use encrypted Kubernetes secrets',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if 'encryptionConfig' not in response_detail:
                self.eks_list.append(self.create_eks_item(
                    'EKS.3',
                    'EKS clusters should use encrypted Kubernetes secrets',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['arn']
                ))
            else:
                self.eks_list.append(self.create_eks_item(
                    'EKS.3',
                    'EKS clusters should use encrypted Kubernetes secrets',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['arn']
                ))
    
    @DecoratorClass.my_decorator
    def eks_six(self) -> None:
        result_list = self.describe_eks_cluster_list()
        if not result_list:
            self.eks_list.append(self.create_eks_item(
                'EKS.6',
                'EKS clusters should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if 'tags' not in response_detail:
                compliant_status = "failed"
            else:
                tag_key_list = [tag['key'] for tag in response_detail['tags']]
                if list(set(self.require_tag_keys) - set(tag_key_list)):
                    compliant_status = "failed"
            self.eks_list.append(self.create_eks_item(
                'EKS.6',
                'EKS clusters should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['arn']
            ))
    
    @DecoratorClass.my_decorator
    def eks_seven(self) -> None:
        result_list = self.eks_identity_provider_list()
        if not result_list:
            self.eks_list.append(self.create_eks_item(
                'EKS.7',
                'EKS identity provider configurations should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if 'tags' not in response_detail['oidc']:
                compliant_status = "failed"
            else:
                tag_key_list = [tag['key'] for tag in response_detail['oidc']['tags']]
                if list(set(self.require_tag_keys) - set(tag_key_list)):
                    compliant_status = "failed"
            self.eks_list.append(self.create_eks_item(
                'EKS.7',
                'EKS identity provider configurations should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['identityProviderConfigArn']
            ))
    
    @DecoratorClass.my_decorator
    def eks_eight(self) -> None:
        result_list = self.describe_eks_cluster_list()
        if not result_list:
            self.eks_list.append(self.create_eks_item(
                'EKS.8',
                'EKS clusters should have audit logging enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if 'logging' not in response_detail or 'clusterLogging' not in response_detail['logging']:
                compliant_status = "failed"
            else:
                if not any([log['enabled'] == True for log in response_detail['logging']['clusterLogging']]):
                    compliant_status = "failed"
            self.eks_list.append(self.create_eks_item(
                'EKS.8',
                'EKS clusters should have audit logging enabled',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['arn']
            ))

class CrossAccountEKSComplianceChecker:
    def __init__(self) -> None:
        self.eks_oldest_version = "1.28"
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.eks_client = UseCrossAccount().client('eks')
        self.eks_list = compliance_check_list

    def create_eks_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("EKS", control_id, compliance, severity, auto_remediation):
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
    
    def eks_cluster_list(self) -> list[str]:
        cluster_list: list[str] = []
        try:
            response = self.eks_client.list_clusters()
            for response_detail in response['clusters']:
                cluster_list.append(response_detail)
            while 'nextToken' in response:
                response = self.eks_client.list_clusters(nextToken=response['nextToken'])
                for response_detail in response['clusters']:
                    cluster_list.append(response_detail)
            return cluster_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def describe_eks_cluster_list(self) -> list[dict]:
        cluster_list: list[dict] = []
        result_list = self.eks_cluster_list()
        for response_detail in result_list:
            try:
                response = self.eks_client.describe_cluster(name=response_detail)
                cluster_list.extend(_ for _ in response['cluster'])
                while 'nextToken' in response:
                    response = self.eks_client.describe_cluster(nextToken=response['nextToken'])
                    cluster_list.extend(_ for _ in response['cluster'])
            except ClientError as e:
                print(f"Error: {e}")
                return []
        return cluster_list
    
    def eks_identity_provider_list(self) -> list[dict]:
        identity_provider_list: list[dict] = []
        result_list = self.eks_cluster_list()
        for response_detail in result_list:
            try:
                identity_provider_response = self.eks_client.list_identity_provider_configs(name=response_detail)
                for identity_provider_response_detail in identity_provider_response['identityProviderConfigs']:
                    response = self.eks_client.describe_identity_provider_config(name=response_detail, identityProviderConfig=identity_provider_response_detail)
                    identity_provider_list.extend(_ for _ in response['identityProviderConfig'])
                while 'nextToken' in identity_provider_response:
                    identity_provider_response = self.eks_client.list_identity_provider_configs(nextToken=identity_provider_response['nextToken'])
                    for identity_provider_response_detail in identity_provider_response['identityProviderConfigs']:
                        response = self.eks_client.describe_identity_provider_config(name=response_detail, identityProviderConfig=identity_provider_response_detail)
                        identity_provider_list.extend(_ for _ in response['identityProviderConfig'])
            except ClientError as e:
                print(f"Error: {e}")
                return []
        return identity_provider_list
    
    @DecoratorClass.my_decorator
    def eks_one(self) -> None:
        result_list = self.describe_eks_cluster_list()
        if not result_list:
            self.eks_list.append(self.create_eks_item(
                'EKS.1',
                'EKS cluster endpoints should not be publicly accessible',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['resourcesVpcConfig']['endpointPublicAccess'] == True:
                self.eks_list.append(self.create_eks_item(
                    'EKS.1',
                    'EKS cluster endpoints should not be publicly accessible',
                    'failed',
                    'HIGH',
                    'not_available',
                    response_detail['arn']
                ))
            else:
                self.eks_list.append(self.create_eks_item(
                    'EKS.1',
                    'EKS cluster endpoints should not be publicly accessible',
                    'passed',
                    'HIGH',
                    'not_available',
                    response_detail['arn']
                ))
    
    @DecoratorClass.my_decorator
    def eks_two(self) -> None:
        result_list = self.describe_eks_cluster_list()
        if not result_list:
            self.eks_list.append(self.create_eks_item(
                'EKS.2',
                'EKS clusters should run on a supported Kubernetes version',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if float(response_detail['platformVersion']) < float(self.eks_oldest_version):
                self.eks_list.append(self.create_eks_item(
                    'EKS.2',
                    'EKS clusters should run on a supported Kubernetes version',
                    'failed',
                    'HIGH',
                    'not_available',
                    response_detail['arn']
                ))
            else:
                self.eks_list.append(self.create_eks_item(
                    'EKS.2',
                    'EKS clusters should run on a supported Kubernetes version',
                    'passed',
                    'HIGH',
                    'not_available',
                    response_detail['arn']
                ))
    
    @DecoratorClass.my_decorator
    def eks_three(self) -> None:
        result_list = self.describe_eks_cluster_list()
        if not result_list:
            self.eks_list.append(self.create_eks_item(
                'EKS.3',
                'EKS clusters should use encrypted Kubernetes secrets',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if 'encryptionConfig' not in response_detail:
                self.eks_list.append(self.create_eks_item(
                    'EKS.3',
                    'EKS clusters should use encrypted Kubernetes secrets',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['arn']
                ))
            else:
                self.eks_list.append(self.create_eks_item(
                    'EKS.3',
                    'EKS clusters should use encrypted Kubernetes secrets',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['arn']
                ))
    
    @DecoratorClass.my_decorator
    def eks_six(self) -> None:
        result_list = self.describe_eks_cluster_list()
        if not result_list:
            self.eks_list.append(self.create_eks_item(
                'EKS.6',
                'EKS clusters should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if 'tags' not in response_detail:
                compliant_status = "failed"
            else:
                tag_key_list = [tag['key'] for tag in response_detail['tags']]
                if list(set(self.require_tag_keys) - set(tag_key_list)):
                    compliant_status = "failed"
            self.eks_list.append(self.create_eks_item(
                'EKS.6',
                'EKS clusters should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['arn']
            ))
    
    @DecoratorClass.my_decorator
    def eks_seven(self) -> None:
        result_list = self.eks_identity_provider_list()
        if not result_list:
            self.eks_list.append(self.create_eks_item(
                'EKS.7',
                'EKS identity provider configurations should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if 'tags' not in response_detail['oidc']:
                compliant_status = "failed"
            else:
                tag_key_list = [tag['key'] for tag in response_detail['oidc']['tags']]
                if list(set(self.require_tag_keys) - set(tag_key_list)):
                    compliant_status = "failed"
            self.eks_list.append(self.create_eks_item(
                'EKS.7',
                'EKS identity provider configurations should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['identityProviderConfigArn']
            ))
    
    @DecoratorClass.my_decorator
    def eks_eight(self) -> None:
        result_list = self.describe_eks_cluster_list()
        if not result_list:
            self.eks_list.append(self.create_eks_item(
                'EKS.8',
                'EKS clusters should have audit logging enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if 'logging' not in response_detail or 'clusterLogging' not in response_detail['logging']:
                compliant_status = "failed"
            else:
                if not any([log['enabled'] == True for log in response_detail['logging']['clusterLogging']]):
                    compliant_status = "failed"
            self.eks_list.append(self.create_eks_item(
                'EKS.8',
                'EKS clusters should have audit logging enabled',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['arn']
            ))