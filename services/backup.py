'''
Class name BackupComplianceChecker
Create functions to check compliants and return as 
'control_id': security contorl id,
'control_title': security control title,
'compliance': passed, failed or not_found,
'severity': CRITICAL, HIGH, MEDIUM or LOW,
'auto_remediation': available or not_available,
'resource_id': account id, resource arn or not_found

No autoremediate because AWS Backup already support encrypt by default while creating backup vault with encryption key
'''

import boto3 # type: ignore
from botocore.exceptions import ClientError # type: ignore
from utils.decorator_class import DecoratorClass # type: ignore
from utils.validate import ParameterValidation # type: ignore
from utils.cross_account import UseCrossAccount # type: ignore
from utils.global_data import compliance_check_list # type: ignore

class BackupComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.backup_client = boto3.client('backup')
        self.backup_list = compliance_check_list

    def create_backup_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("Backup", control_id, compliance, severity, auto_remediation):
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
    
    def backup_vault(self) -> list[dict]:
        next_token = None # type: ignore
        backup_vault_list: list[dict] = []
        while True:
            try:
                response_iterator = self.backup_client.get_paginator('list_backup_vaults').paginate(
                    PaginationConfig={
                        'StartingToken': next_token
                        }
                    )
                for page in response_iterator:
                    vault_list = page['BackupVaultList']
                    backup_vault_list.extend(_ for _ in vault_list)
                    if 'NextToken' in page:
                        next_token = page['NextToken']
                    else:
                        return backup_vault_list
            except ClientError as e:
                print(f"Error: {e}")
                return []

    def recovery_point(self) -> list[dict]:
        result_list = self.backup_vault()
        next_token = None
        recovery_point_list: list[dict] = []
        for response_detail in result_list:
            while True:
                try:
                    response_iterator = self.backup_client.get_paginator('list_recovery_points_by_backup_vault').paginate(
                        BackupVaultName=response_detail['BackupVaultName'],
                        PaginationConfig={
                            'StartingToken': next_token
                            }
                        )
                    for page in response_iterator:
                        recovery_points_list = page['RecoveryPoints']
                        recovery_point_list.extend(_ for _ in recovery_points_list)
                        if 'NextToken' in page:
                            next_token = page['NextToken']
                        else:
                            return recovery_point_list
                except ClientError as e:
                    print(f"Error: {e}")
                    return []
        return recovery_point_list
    
    def report_plan(self) -> list[dict]:
        report_plan_list: list[dict] = []
        try:
            response = self.backup_client.list_report_plans()
            report_plan_list.extend(_ for _ in response['ReportPlans'])
            while 'NextToken' in response:
                response = self.backup_client.list_report_plans(NextToken=response['NextToken'])
                report_plan_list.extend(_ for _ in response['ReportPlans'])
            return report_plan_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def backup_plan(self) -> list[dict]:
        next_token = None # type: ignore
        backup_plan_list: list[dict] = []
        while True:
            try:
                response_iterator = self.backup_client.get_paginator('list_backup_plans').paginate(
                    PaginationConfig={
                        'StartingToken': next_token
                        }
                    )
                for page in response_iterator:
                    vault_list = page['BackupPlansList']
                    backup_plan_list.extend(_ for _ in vault_list)
                    if 'NextToken' in page:
                        next_token = page['NextToken']
                    else:
                        return backup_plan_list
            except ClientError as e:
                print(f"Error: {e}")
                return []

    def backup_tag(self, backup_resource_arn:str) -> str:
        try:
            compliant_status = "passed"
            tag_key_list: list[str] = []
            response = self.backup_client.list_tags(ResourceArn=backup_resource_arn)
            tag_key_list.extend(_ for _ in response['Tags'].keys())
            while 'NextToken' in response:
                response = self.backup_client.list_tags(ResourceArn=backup_resource_arn, NextToken=response['NextToken'])
                tag_key_list.extend(_ for _ in response['Tags'].keys())
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""

    @DecoratorClass.my_decorator   
    def backup_one(self) -> None:
        result_list = self.recovery_point()
        if not result_list:
            self.backup_list.append(self.create_backup_item(
                'Backup.1',
                'AWS Backup recovery points should be encrypted at rest',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for recovery_point in result_list:
            if recovery_point['IsEncrypted'] != True:
                self.backup_list.append(self.create_backup_item(
                    'Backup.1',
                    'AWS Backup recovery points should be encrypted at rest',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    recovery_point['RecoveryPointArn']
                ))
            else:
                self.backup_list.append(self.create_backup_item(
                    'Backup.1',
                    'AWS Backup recovery points should be encrypted at rest',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    recovery_point['RecoveryPointArn']
                ))

    @DecoratorClass.my_decorator   
    def backup_two(self) -> None:
        result_list = self.recovery_point()
        if not result_list:
            self.backup_list.append(self.create_backup_item(
                'Backup.2',
                'AWS Backup recovery points should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.backup_tag(response_detail['RecoveryPointArn'])
            self.backup_list.append(self.create_backup_item(
                'Backup.2',
                'AWS Backup recovery points should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['RecoveryPointArn']
            ))

    @DecoratorClass.my_decorator   
    def backup_three(self) -> None:
        result_list = self.backup_vault()
        if not result_list:
            self.backup_list.append(self.create_backup_item(
                'Backup.3',
                'AWS Backup vaults should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.backup_tag(response_detail['BackupVaultArn'])
            self.backup_list.append(self.create_backup_item(
                'Backup.3',
                'AWS Backup vaults should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['BackupVaultArn']
            ))

    @DecoratorClass.my_decorator   
    def backup_four(self) -> None:
        result_list = self.report_plan()
        if not result_list:
            self.backup_list.append(self.create_backup_item(
                'Backup.4',
                'AWS Backup report plans should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.backup_tag(response_detail['ReportPlanArn'])
            self.backup_list.append(self.create_backup_item(
                'Backup.4',
                'AWS Backup report plans should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['ReportPlanArn']
            ))

    @DecoratorClass.my_decorator   
    def backup_five(self) -> None:
        result_list = self.backup_plan()
        if not result_list:
            self.backup_list.append(self.create_backup_item(
                'Backup.5',
                'AWS Backup backup plans should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.backup_tag(response_detail['BackupPlanArn'])
            self.backup_list.append(self.create_backup_item(
                'Backup.5',
                'AWS Backup backup plans should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['BackupPlanArn']
            ))

class CrossAccountBackupComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.backup_client = UseCrossAccount().client('backup')
        self.backup_list = compliance_check_list

    def create_backup_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("Backup", control_id, compliance, severity, auto_remediation):
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
    
    def backup_vault(self) -> list[dict]:
        next_token = None # type: ignore
        backup_vault_list: list[dict] = []
        while True:
            try:
                response_iterator = self.backup_client.get_paginator('list_backup_vaults').paginate(
                    PaginationConfig={
                        'StartingToken': next_token
                        }
                    )
                for page in response_iterator:
                    vault_list = page['BackupVaultList']
                    backup_vault_list.extend(_ for _ in vault_list)
                    if 'NextToken' in page:
                        next_token = page['NextToken']
                    else:
                        return backup_vault_list
            except ClientError as e:
                print(f"Error: {e}")
                return []

    def recovery_point(self) -> list[dict]:
        result_list = self.backup_vault()
        next_token = None
        recovery_point_list: list[dict] = []
        for response_detail in result_list:
            while True:
                try:
                    response_iterator = self.backup_client.get_paginator('list_recovery_points_by_backup_vault').paginate(
                        BackupVaultName=response_detail['BackupVaultName'],
                        PaginationConfig={
                            'StartingToken': next_token
                            }
                        )
                    for page in response_iterator:
                        recovery_points_list = page['RecoveryPoints']
                        recovery_point_list.extend(_ for _ in recovery_points_list)
                        if 'NextToken' in page:
                            next_token = page['NextToken']
                        else:
                            return recovery_point_list
                except ClientError as e:
                    print(f"Error: {e}")
                    return []
        return recovery_point_list
    
    def report_plan(self) -> list[dict]:
        report_plan_list: list[dict] = []
        try:
            response = self.backup_client.list_report_plans()
            report_plan_list.extend(_ for _ in response['ReportPlans'])
            while 'NextToken' in response:
                response = self.backup_client.list_report_plans(NextToken=response['NextToken'])
                report_plan_list.extend(_ for _ in response['ReportPlans'])
            return report_plan_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def backup_plan(self) -> list[dict]:
        next_token = None # type: ignore
        backup_plan_list: list[dict] = []
        while True:
            try:
                response_iterator = self.backup_client.get_paginator('list_backup_plans').paginate(
                    PaginationConfig={
                        'StartingToken': next_token
                        }
                    )
                for page in response_iterator:
                    vault_list = page['BackupPlansList']
                    backup_plan_list.extend(_ for _ in vault_list)
                    if 'NextToken' in page:
                        next_token = page['NextToken']
                    else:
                        return backup_plan_list
            except ClientError as e:
                print(f"Error: {e}")
                return []

    def backup_tag(self, backup_resource_arn:str) -> str:
        try:
            compliant_status = "passed"
            tag_key_list: list[str] = []
            response = self.backup_client.list_tags(ResourceArn=backup_resource_arn)
            tag_key_list.extend(_ for _ in response['Tags'].keys())
            while 'NextToken' in response:
                response = self.backup_client.list_tags(ResourceArn=backup_resource_arn, NextToken=response['NextToken'])
                tag_key_list.extend(_ for _ in response['Tags'].keys())
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""

    @DecoratorClass.my_decorator   
    def backup_one(self) -> None:
        result_list = self.recovery_point()
        if not result_list:
            self.backup_list.append(self.create_backup_item(
                'Backup.1',
                'AWS Backup recovery points should be encrypted at rest',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for recovery_point in result_list:
            if recovery_point['IsEncrypted'] != True:
                self.backup_list.append(self.create_backup_item(
                    'Backup.1',
                    'AWS Backup recovery points should be encrypted at rest',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    recovery_point['RecoveryPointArn']
                ))
            else:
                self.backup_list.append(self.create_backup_item(
                    'Backup.1',
                    'AWS Backup recovery points should be encrypted at rest',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    recovery_point['RecoveryPointArn']
                ))

    @DecoratorClass.my_decorator   
    def backup_two(self) -> None:
        result_list = self.recovery_point()
        if not result_list:
            self.backup_list.append(self.create_backup_item(
                'Backup.2',
                'AWS Backup recovery points should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.backup_tag(response_detail['RecoveryPointArn'])
            self.backup_list.append(self.create_backup_item(
                'Backup.2',
                'AWS Backup recovery points should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['RecoveryPointArn']
            ))

    @DecoratorClass.my_decorator   
    def backup_three(self) -> None:
        result_list = self.backup_vault()
        if not result_list:
            self.backup_list.append(self.create_backup_item(
                'Backup.3',
                'AWS Backup vaults should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.backup_tag(response_detail['BackupVaultArn'])
            self.backup_list.append(self.create_backup_item(
                'Backup.3',
                'AWS Backup vaults should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['BackupVaultArn']
            ))

    @DecoratorClass.my_decorator   
    def backup_four(self) -> None:
        result_list = self.report_plan()
        if not result_list:
            self.backup_list.append(self.create_backup_item(
                'Backup.4',
                'AWS Backup report plans should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.backup_tag(response_detail['ReportPlanArn'])
            self.backup_list.append(self.create_backup_item(
                'Backup.4',
                'AWS Backup report plans should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['ReportPlanArn']
            ))

    @DecoratorClass.my_decorator   
    def backup_five(self) -> None:
        result_list = self.backup_plan()
        if not result_list:
            self.backup_list.append(self.create_backup_item(
                'Backup.5',
                'AWS Backup backup plans should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.backup_tag(response_detail['BackupPlanArn'])
            self.backup_list.append(self.create_backup_item(
                'Backup.5',
                'AWS Backup backup plans should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['BackupPlanArn']
            ))