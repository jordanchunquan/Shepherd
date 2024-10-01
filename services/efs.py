'''
Class name EFSComplianceChecker
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

class EFSComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.efs_client = boto3.client('efs')
        self.ec2_client = boto3.client('ec2')
        self.backup_client = boto3.client('backup')
        self.efs_list = compliance_check_list

    def create_efs_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("EFS", control_id, compliance, severity, auto_remediation):
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
    
    def describe_efs_list(self) -> list[dict]:
        efs_list: list[dict] = []
        try:
            response = self.efs_client.describe_file_systems()
            efs_list.extend(_ for _ in response['FileSystems'])
            while 'Marker' in response:
                response = self.efs_client.describe_file_systems(Marker=response['Marker'])
                efs_list.extend(_ for _ in response['FileSystems'])
            return efs_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def backup_recovery_point_list(self) -> list[str]:
        recovery_point_list: list[str] = []
        try:
            backup_vault_response = self.backup_client.list_backup_vaults()
            for backup_vault in backup_vault_response['BackupVaultList']:
                recovery_point_response = self.backup_client.list_recovery_points_by_backup_vault(
                    BackupVaultName=backup_vault['BackupVaultArn'].split(':')[-1]
                )
                for recovery_point in recovery_point_response['RecoveryPoints']:
                    if re.match(r"^arn:aws:ec2:*", recovery_point['ResourceArn']):
                        recovery_point_list.append(recovery_point['ResourceArn'].split(':')[-1].split('/')[-1])
                    else:
                        recovery_point_list.append(recovery_point['ResourceArn'])
            while 'NextToken' in backup_vault_response:
                backup_vault_response = self.backup_client.describe_config_rules(NextToken=backup_vault_response['NextToken'])
                for backup_vault in backup_vault_response['BackupVaultList']:
                    recovery_point_response = self.backup_client.list_recovery_points_by_backup_vault(
                        BackupVaultName=backup_vault['BackupVaultArn'].split(':')[-1]
                    )
                    for recovery_point in recovery_point_response['RecoveryPoints']:
                        if re.match(r"^arn:aws:ec2:*", recovery_point['ResourceArn']):
                            recovery_point_list.append(recovery_point['ResourceArn'].split(':')[-1].split('/')[-1])
                        else:
                            recovery_point_list.append(recovery_point['ResourceArn'])
            return list(set(recovery_point_list))
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def describe_efs_access_point_list(self) -> list[dict]:
        efs_access_point_list: list[dict] = []
        try:
            response = self.efs_client.describe_access_points()
            efs_access_point_list.extend(_ for _ in response['AccessPoints'])
            while 'NextToken' in response:
                response = self.efs_client.describe_access_points(NextToken=response['NextToken'])
                efs_access_point_list.extend(_ for _ in response['AccessPoints'])
            return efs_access_point_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def describe_efs_mount_target_list(self) -> list[dict]:
        result_list = self.describe_efs_access_point_list()
        efs_mount_target_list: list[dict] = []
        for response_detail in result_list:
            try:
                response = self.efs_client.describe_mount_targets(AccessPointId=response_detail['AccessPointId'])
                efs_mount_target_list.extend(_ for _ in response['MountTargets'])
                while 'NextMarker' in response:
                    response = self.efs_client.describe_mount_targets(AccessPointId=response_detail['AccessPointId'], Marker=response['NextMarker'])
                    efs_mount_target_list.extend(_ for _ in response['MountTargets'])
            except ClientError as e:
                print(f"Error: {e}")
                return []
        return efs_mount_target_list
        
    def describe_subnet_list(self) -> list[str]:
        subnet_list: list[str] = []
        try:
            response = self.ec2_client.describe_subnets()
            for response_detail in response['Subnets']:
                if 'MapPublicIpOnLaunch' == True:
                    subnet_list.append(response_detail['SubnetId'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_subnets(NextToken=response['NextToken'])
                for response_detail in response['Subnets']:
                    if 'MapPublicIpOnLaunch' == True:
                        subnet_list.append(response_detail['SubnetId'])
            return subnet_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    @DecoratorClass.my_decorator
    def efs_one(self) -> None:
        result_list = self.describe_efs_list()
        if not result_list:
            self.efs_list.append(self.create_efs_item(
                'EFS.1',
                'Elastic File System should be configured to encrypt file data at-rest using AWS KMS',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if 'KmsKeyId' not in response_detail:
                self.efs_list.append(self.create_efs_item(
                    'EFS.1',
                    'Elastic File System should be configured to encrypt file data at-rest using AWS KMS',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FileSystemArn']
                ))
            else:
                self.efs_list.append(self.create_efs_item(
                    'EFS.1',
                    'Elastic File System should be configured to encrypt file data at-rest using AWS KMS',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FileSystemArn']
                ))
    
    @DecoratorClass.my_decorator
    def efs_two(self) -> None:
        result_list = self.describe_efs_list()
        backup_list = self.backup_recovery_point_list()
        if not result_list:
            self.efs_list.append(self.create_efs_item(
                'EFS.2',
                'Amazon EFS volumes should be in backup plans',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['FileSystemArn'] not in backup_list:
                self.efs_list.append(self.create_efs_item(
                    'EFS.2',
                    'Amazon EFS volumes should be in backup plans',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FileSystemArn']
                ))
            else:
                self.efs_list.append(self.create_efs_item(
                    'EFS.2',
                    'Amazon EFS volumes should be in backup plans',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FileSystemArn']
                ))
    
    @DecoratorClass.my_decorator
    def efs_three(self) -> None:
        result_list = self.describe_efs_access_point_list()
        if not result_list:
            self.efs_list.append(self.create_efs_item(
                'EFS.3',
                'EFS access points should enforce a root directory',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['RootDirectory']['Path'] == '/':
                self.efs_list.append(self.create_efs_item(
                    'EFS.3',
                    'EFS access points should enforce a root directory',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['AccessPointArn']
                ))
            else:
                self.efs_list.append(self.create_efs_item(
                    'EFS.3',
                    'EFS access points should enforce a root directory',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['AccessPointArn']
                ))
    
    @DecoratorClass.my_decorator
    def efs_four(self) -> None:
        result_list = self.describe_efs_access_point_list()
        if not result_list:
            self.efs_list.append(self.create_efs_item(
                'EFS.4',
                'EFS access points should enforce a user identity',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if 'PosixUser' not in response_detail:
                self.efs_list.append(self.create_efs_item(
                    'EFS.4',
                    'EFS access points should enforce a user identity',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['AccessPointArn']
                ))
            else:
                self.efs_list.append(self.create_efs_item(
                    'EFS.4',
                    'EFS access points should enforce a user identity',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['AccessPointArn']
                ))
    
    @DecoratorClass.my_decorator
    def efs_five(self) -> None:
        result_list = self.describe_efs_access_point_list()
        if not result_list:
            self.efs_list.append(self.create_efs_item(
                'EFS.5',
                'EFS access points should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if 'Tags' not in response_detail:
                compliant_status = "failed"
            else:
                tag_key_list = [tag['Key'] for tag in response_detail['Tags']]
                if list(set(self.require_tag_keys) - set(tag_key_list)):
                    compliant_status = "failed"
            self.efs_list.append(self.create_efs_item(
                'EFS.5',
                'EFS access points should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['AccessPointArn']
            ))
    
    @DecoratorClass.my_decorator
    def efs_six(self) -> None:
        result_list = self.describe_efs_mount_target_list()
        subnet_list = self.describe_subnet_list()
        if not result_list:
            self.efs_list.append(self.create_efs_item(
                'EFS.6',
                'EFS mount targets should not be associated with a public subnet',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['SubnetId'] in subnet_list:
                self.efs_list.append(self.create_efs_item(
                    'EFS.6',
                    'EFS mount targets should not be associated with a public subnet',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FileSystemId']
                ))
            else:
                self.efs_list.append(self.create_efs_item(
                    'EFS.6',
                    'EFS mount targets should not be associated with a public subnet',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FileSystemId']
                ))

class CrossAccountEFSComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.efs_client = UseCrossAccount().client('efs')
        self.ec2_client = UseCrossAccount().client('ec2')
        self.backup_client = UseCrossAccount().client('backup')
        self.efs_list = compliance_check_list

    def create_efs_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("EFS", control_id, compliance, severity, auto_remediation):
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
    
    def describe_efs_list(self) -> list[dict]:
        efs_list: list[dict] = []
        try:
            response = self.efs_client.describe_file_systems()
            efs_list.extend(_ for _ in response['FileSystems'])
            while 'Marker' in response:
                response = self.efs_client.describe_file_systems(Marker=response['Marker'])
                efs_list.extend(_ for _ in response['FileSystems'])
            return efs_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def backup_recovery_point_list(self) -> list[str]:
        recovery_point_list: list[str] = []
        try:
            backup_vault_response = self.backup_client.list_backup_vaults()
            for backup_vault in backup_vault_response['BackupVaultList']:
                recovery_point_response = self.backup_client.list_recovery_points_by_backup_vault(
                    BackupVaultName=backup_vault['BackupVaultArn'].split(':')[-1]
                )
                for recovery_point in recovery_point_response['RecoveryPoints']:
                    if re.match(r"^arn:aws:ec2:*", recovery_point['ResourceArn']):
                        recovery_point_list.append(recovery_point['ResourceArn'].split(':')[-1].split('/')[-1])
                    else:
                        recovery_point_list.append(recovery_point['ResourceArn'])
            while 'NextToken' in backup_vault_response:
                backup_vault_response = self.backup_client.describe_config_rules(NextToken=backup_vault_response['NextToken'])
                for backup_vault in backup_vault_response['BackupVaultList']:
                    recovery_point_response = self.backup_client.list_recovery_points_by_backup_vault(
                        BackupVaultName=backup_vault['BackupVaultArn'].split(':')[-1]
                    )
                    for recovery_point in recovery_point_response['RecoveryPoints']:
                        if re.match(r"^arn:aws:ec2:*", recovery_point['ResourceArn']):
                            recovery_point_list.append(recovery_point['ResourceArn'].split(':')[-1].split('/')[-1])
                        else:
                            recovery_point_list.append(recovery_point['ResourceArn'])
            return list(set(recovery_point_list))
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def describe_efs_access_point_list(self) -> list[dict]:
        efs_access_point_list: list[dict] = []
        try:
            response = self.efs_client.describe_access_points()
            efs_access_point_list.extend(_ for _ in response['AccessPoints'])
            while 'NextToken' in response:
                response = self.efs_client.describe_access_points(NextToken=response['NextToken'])
                efs_access_point_list.extend(_ for _ in response['AccessPoints'])
            return efs_access_point_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def describe_efs_mount_target_list(self) -> list[dict]:
        efs_mount_target_list: list[dict] = []
        try:
            response = self.efs_client.describe_mount_targets()
            efs_mount_target_list.extend(_ for _ in response['MountTargets'])
            while 'NextToken' in response:
                response = self.efs_client.describe_mount_targets(NextToken=response['NextToken'])
                efs_mount_target_list.extend(_ for _ in response['MountTargets'])
            return efs_mount_target_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def describe_subnet_list(self) -> list[str]:
        subnet_list: list[str] = []
        try:
            response = self.ec2_client.describe_subnets()
            for response_detail in response['Subnets']:
                if 'MapPublicIpOnLaunch' == True:
                    subnet_list.append(response_detail['SubnetId'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_subnets(NextToken=response['NextToken'])
                for response_detail in response['Subnets']:
                    if 'MapPublicIpOnLaunch' == True:
                        subnet_list.append(response_detail['SubnetId'])
            return subnet_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    @DecoratorClass.my_decorator
    def efs_one(self) -> None:
        result_list = self.describe_efs_list()
        if not result_list:
            self.efs_list.append(self.create_efs_item(
                'EFS.1',
                'Elastic File System should be configured to encrypt file data at-rest using AWS KMS',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if 'KmsKeyId' not in response_detail:
                self.efs_list.append(self.create_efs_item(
                    'EFS.1',
                    'Elastic File System should be configured to encrypt file data at-rest using AWS KMS',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FileSystemArn']
                ))
            else:
                self.efs_list.append(self.create_efs_item(
                    'EFS.1',
                    'Elastic File System should be configured to encrypt file data at-rest using AWS KMS',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FileSystemArn']
                ))
    
    @DecoratorClass.my_decorator
    def efs_two(self) -> None:
        result_list = self.describe_efs_list()
        backup_list = self.backup_recovery_point_list()
        if not result_list:
            self.efs_list.append(self.create_efs_item(
                'EFS.2',
                'Amazon EFS volumes should be in backup plans',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['FileSystemArn'] not in backup_list:
                self.efs_list.append(self.create_efs_item(
                    'EFS.2',
                    'Amazon EFS volumes should be in backup plans',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FileSystemArn']
                ))
            else:
                self.efs_list.append(self.create_efs_item(
                    'EFS.2',
                    'Amazon EFS volumes should be in backup plans',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FileSystemArn']
                ))
    
    @DecoratorClass.my_decorator
    def efs_three(self) -> None:
        result_list = self.describe_efs_access_point_list()
        if not result_list:
            self.efs_list.append(self.create_efs_item(
                'EFS.3',
                'EFS access points should enforce a root directory',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['RootDirectory']['Path'] == '/':
                self.efs_list.append(self.create_efs_item(
                    'EFS.3',
                    'EFS access points should enforce a root directory',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['AccessPointArn']
                ))
            else:
                self.efs_list.append(self.create_efs_item(
                    'EFS.3',
                    'EFS access points should enforce a root directory',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['AccessPointArn']
                ))
    
    @DecoratorClass.my_decorator
    def efs_four(self) -> None:
        result_list = self.describe_efs_access_point_list()
        if not result_list:
            self.efs_list.append(self.create_efs_item(
                'EFS.4',
                'EFS access points should enforce a user identity',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if 'PosixUser' not in response_detail:
                self.efs_list.append(self.create_efs_item(
                    'EFS.4',
                    'EFS access points should enforce a user identity',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['AccessPointArn']
                ))
            else:
                self.efs_list.append(self.create_efs_item(
                    'EFS.4',
                    'EFS access points should enforce a user identity',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['AccessPointArn']
                ))
    
    @DecoratorClass.my_decorator
    def efs_five(self) -> None:
        result_list = self.describe_efs_access_point_list()
        if not result_list:
            self.efs_list.append(self.create_efs_item(
                'EFS.5',
                'EFS access points should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if 'Tags' not in response_detail:
                compliant_status = "failed"
            else:
                tag_key_list = [tag['Key'] for tag in response_detail['Tags']]
                if list(set(self.require_tag_keys) - set(tag_key_list)):
                    compliant_status = "failed"
            self.efs_list.append(self.create_efs_item(
                'EFS.5',
                'EFS access points should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['AccessPointArn']
            ))
    
    @DecoratorClass.my_decorator
    def efs_six(self) -> None:
        result_list = self.describe_efs_mount_target_list()
        subnet_list = self.describe_subnet_list()
        if not result_list:
            self.efs_list.append(self.create_efs_item(
                'EFS.6',
                'EFS mount targets should not be associated with a public subnet',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['SubnetId'] in subnet_list:
                self.efs_list.append(self.create_efs_item(
                    'EFS.6',
                    'EFS mount targets should not be associated with a public subnet',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FileSystemId']
                ))
            else:
                self.efs_list.append(self.create_efs_item(
                    'EFS.6',
                    'EFS mount targets should not be associated with a public subnet',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FileSystemId']
                ))