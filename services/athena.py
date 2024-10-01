'''
Class name AthenaComplianceChecker
Create functions to check compliants and return as 
'control_id': security contorl id,
'control_title': security control title,
'compliance': passed, failed or not_found,
'severity': CRITICAL, HIGH, MEDIUM or LOW,
'auto_remediation': available or not_available,
'resource_id': account id, resource arn or not_found

Class name AthenaAutoRemediation
Autoremediate Athena one by update encryption type to SSE_S3
'''

import boto3 # type: ignore
from botocore.exceptions import ClientError # type: ignore
from utils.decorator_class import DecoratorClass # type: ignore
from utils.validate import ParameterValidation # type: ignore
from utils.cross_account import UseCrossAccount # type: ignore
from utils.global_data import compliance_check_list # type: ignore

class AthenaComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        # Get region and account id to use for arn parameter
        self.session_region = boto3.session.Session().region_name
        self.session_account = boto3.client('sts').get_caller_identity().get('Account')
        self.athena_client = boto3.client('athena')
        self.athena_list = compliance_check_list

    def create_athena_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("Athena", control_id, compliance, severity, auto_remediation):
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
    
    def get_athena_list(self) -> list[dict]:
        athena_list: list[dict] = []
        try:
            response = self.athena_client.list_work_groups()
            for response_detail in response['WorkGroups']:
                workgroup_response = self.athena_client.get_work_group(WorkGroup=response_detail['Name'])
                athena_list.append(workgroup_response)
            while 'NextToken' in response:
                response = self.athena_client.list_work_groups(NextToken=response['NextToken'])
                for response_detail in response['WorkGroups']:
                    workgroup_response = self.athena_client.get_work_group(WorkGroup=response_detail['Name'])
                    athena_list.append(workgroup_response)
            return athena_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def get_athena_catalog_list(self) -> list[str]:
        athena_list: list[str] = []
        try:
            response = self.athena_client.list_data_catalogs()
            for response_detail in response['DataCatalogsSummary']:
                if response_detail['Type'] != "GLUE":
                    athena_list.append(response_detail['CatalogName'])
            while 'NextToken' in response:
                response = self.athena_client.list_data_catalogs(NextToken=response['NextToken'])
                for response_detail in response['DataCatalogsSummary']:
                    if response_detail['Type'] != "GLUE":
                        athena_list.append(response_detail['CatalogName'])
            return athena_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def get_athena_tag_list(self, athena_arn:str) -> str:
        try:
            compliant_status = "passed"
            tag_key_list: list[str] = []
            response = self.athena_client.list_tags_for_resource(ResourceARN=athena_arn)
            tag_key_list.extend(_['Key'] for _ in response['Tags'])
            while 'NextToken' in response:
                response = self.athena_client.list_tags_for_resource(ResourceARN=athena_arn, NextToken=response['NextToken'])
                tag_key_list.extend(_['Key'] for _ in response['Tags'])
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""

    @DecoratorClass.my_decorator
    def athena_one(self) -> None:
        result_list = self.get_athena_list()
        if not result_list:
            self.athena_list.append(self.create_athena_item(
                'Athena.1',
                'Athena workgroups should be encrypted at rest',
                'not_found',
                'MEDIUM',
                'available',
                'not_found'
            ))
        for response_detail in result_list:
            if 'EncryptionConfiguration' not in response_detail['WorkGroup']['Configuration']['ResultConfiguration']:
                self.athena_list.append(self.create_athena_item(
                    'Athena.1',
                    'Athena workgroups should be encrypted at rest',
                    'failed',
                    'MEDIUM',
                    'available',
                    f"arn:aws:athena:{self.session_region}:{self.session_account}:workgroup/{response_detail['WorkGroup']['Name']}"
                ))
            else:
                self.athena_list.append(self.create_athena_item(
                    'Athena.1',
                    'Athena workgroups should be encrypted at rest',
                    'passed',
                    'MEDIUM',
                    'available',
                    f"arn:aws:athena:{self.session_region}:{self.session_account}:workgroup/{response_detail['WorkGroup']['Name']}"
                ))

    @DecoratorClass.my_decorator
    def athena_two(self) -> None:
        result_list = self.get_athena_catalog_list()
        if not result_list:
            self.athena_list.append(self.create_athena_item(
                'Athena.2',
                'Athena data catalogs should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.get_athena_tag_list(f"arn:aws:athena:{self.session_region}:{self.session_account}:datacatalog/{response_detail}")
            self.athena_list.append(self.create_athena_item(
                'Athena.2',
                'Athena data catalogs should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                f"arn:aws:athena:{self.session_region}:{self.session_account}:datacatalog/{response_detail}"
            ))

    @DecoratorClass.my_decorator
    def athena_three(self) -> None:
        result_list = self.get_athena_list()
        if not result_list:
            self.athena_list.append(self.create_athena_item(
                'Athena.3',
                'Athena workgroups should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.get_athena_tag_list(f"arn:aws:athena:{self.session_region}:{self.session_account}:workgroup/{response_detail['WorkGroup']['Name']}")
            self.athena_list.append(self.create_athena_item(
                'Athena.3',
                'Athena workgroups should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                f"arn:aws:athena:{self.session_region}:{self.session_account}:workgroup/{response_detail['WorkGroup']['Name']}"
            ))

    @DecoratorClass.my_decorator
    def athena_four(self) -> None:
        result_list = self.get_athena_list()
        if not result_list:
            self.athena_list.append(self.create_athena_item(
                'Athena.4',
                'Athena workgroups should have logging enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['WorkGroup'].get('Configuration', {}).get('ResultConfiguration', {}).get('OutputLocation', '') == "":
                self.athena_list.append(self.create_athena_item(
                    'Athena.4',
                    'Athena workgroups should have logging enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    f"arn:aws:athena:{self.session_region}:{self.session_account}:workgroup/{response_detail['WorkGroup']['Name']}"
                ))
            else:
                self.athena_list.append(self.create_athena_item(
                    'Athena.4',
                    'Athena workgroups should have logging enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    f"arn:aws:athena:{self.session_region}:{self.session_account}:workgroup/{response_detail['WorkGroup']['Name']}"
                ))

class AthenaAutoRemediation:
    def __init__(self) -> None:
        self.athena_client = boto3.client('athena')
        self.remediate_athena_one()

    def remediate_athena_one(self) -> None:
        try:
            response = self.athena_client.list_work_groups()
            for response_detail in response['WorkGroups']:
                workgroup_response = self.athena_client.get_work_group(WorkGroup=response_detail['Name'])
                if 'EncryptionConfiguration' not in workgroup_response['WorkGroup']['Configuration']['ResultConfiguration']:
                    response = self.athena_client.update_work_group(WorkGroup=response_detail['Name'], \
                                                        ConfigurationUpdates={
                                                            'ResultConfigurationUpdates':{
                                                                'EncryptionConfiguration':{
                                                                    'EncryptionOption': 'SSE_S3'
                                                                }
                                                            }
                                                        })
        except ClientError as e:
            print(f"Error: {e}")

class CrossAccountAthenaComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        # Get region and account id to use for arn parameter
        self.session_region = UseCrossAccount().session_region_name
        self.session_account = UseCrossAccount().client('sts').get_caller_identity().get('Account')
        self.athena_client = UseCrossAccount().client('athena')
        self.athena_list = compliance_check_list

    def create_athena_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("Athena", control_id, compliance, severity, auto_remediation):
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
    
    def get_athena_list(self) -> list[dict]:
        athena_list: list[dict] = []
        try:
            response = self.athena_client.list_work_groups()
            for response_detail in response['WorkGroups']:
                workgroup_response = self.athena_client.get_work_group(WorkGroup=response_detail['Name'])
                athena_list.append(workgroup_response)
            while 'NextToken' in response:
                response = self.athena_client.list_work_groups(NextToken=response['NextToken'])
                for response_detail in response['WorkGroups']:
                    workgroup_response = self.athena_client.get_work_group(WorkGroup=response_detail['Name'])
                    athena_list.append(workgroup_response)
            return athena_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def get_athena_catalog_list(self) -> list[str]:
        athena_list: list[str] = []
        try:
            response = self.athena_client.list_data_catalogs()
            for response_detail in response['DataCatalogsSummary']:
                if response_detail['Type'] != "GLUE":
                    athena_list.append(response_detail['CatalogName'])
            while 'NextToken' in response:
                response = self.athena_client.list_data_catalogs(NextToken=response['NextToken'])
                for response_detail in response['DataCatalogsSummary']:
                    if response_detail['Type'] != "GLUE":
                        athena_list.append(response_detail['CatalogName'])
            return athena_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def get_athena_tag_list(self, athena_arn:str) -> str:
        try:
            compliant_status = "passed"
            tag_key_list: list[str] = []
            response = self.athena_client.list_tags_for_resource(ResourceARN=athena_arn)
            tag_key_list.extend(_['Key'] for _ in response['Tags'])
            while 'NextToken' in response:
                response = self.athena_client.list_work_groups(ResourceARN=athena_arn, NextToken=response['NextToken'])
                tag_key_list.extend(_['Key'] for _ in response['Tags'])
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                return "failed"
            else:
                print(f"Error: {e}")
                return ""

    @DecoratorClass.my_decorator
    def athena_two(self) -> None:
        result_list = self.get_athena_catalog_list()
        if not result_list:
            self.athena_list.append(self.create_athena_item(
                'Athena.2',
                'Athena data catalogs should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.get_athena_tag_list(f"arn:aws:athena:{self.session_region}:{self.session_account}:datacatalog/{response_detail}")
            self.athena_list.append(self.create_athena_item(
                'Athena.2',
                'Athena data catalogs should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                f"arn:aws:athena:{self.session_region}:{self.session_account}:datacatalog/{response_detail}"
            ))

    @DecoratorClass.my_decorator
    def athena_three(self) -> None:
        result_list = self.get_athena_list()
        if not result_list:
            self.athena_list.append(self.create_athena_item(
                'Athena.3',
                'Athena workgroups should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.get_athena_tag_list(f"arn:aws:athena:{self.session_region}:{self.session_account}:workgroup/{response_detail['WorkGroup']['Name']}")
            self.athena_list.append(self.create_athena_item(
                'Athena.3',
                'Athena workgroups should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                f"arn:aws:athena:{self.session_region}:{self.session_account}:workgroup/{response_detail['WorkGroup']['Name']}"
            ))

    @DecoratorClass.my_decorator
    def athena_four(self) -> None:
        result_list = self.get_athena_list()
        if not result_list:
            self.athena_list.append(self.create_athena_item(
                'Athena.4',
                'Athena workgroups should have logging enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['WorkGroup'].get('Configuration', {}).get('ResultConfiguration', {}).get('OutputLocation', '') == "":
                self.athena_list.append(self.create_athena_item(
                    'Athena.4',
                    'Athena workgroups should have logging enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    f"arn:aws:athena:{self.session_region}:{self.session_account}:workgroup/{response_detail['WorkGroup']['Name']}"
                ))
            else:
                self.athena_list.append(self.create_athena_item(
                    'Athena.4',
                    'Athena workgroups should have logging enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    f"arn:aws:athena:{self.session_region}:{self.session_account}:workgroup/{response_detail['WorkGroup']['Name']}"
                ))

class CrossAccountAthenaAutoRemediation:
    def __init__(self) -> None:
        self.athena_client = UseCrossAccount().client('athena')
        self.remediate_athena_one()

    def remediate_athena_one(self) -> None:
        try:
            response = self.athena_client.list_work_groups()
            for response_detail in response['WorkGroups']:
                workgroup_response = self.athena_client.get_work_group(WorkGroup=response_detail['Name'])
                if 'EncryptionConfiguration' not in workgroup_response['WorkGroup']['Configuration']['ResultConfiguration']:
                    response = self.athena_client.update_work_group(WorkGroup=response_detail['Name'], \
                                                        ConfigurationUpdates={
                                                            'ResultConfigurationUpdates':{
                                                                'EncryptionConfiguration':{
                                                                    'EncryptionOption': 'SSE_S3'
                                                                }
                                                            }
                                                        })
        except ClientError as e:
            print(f"Error: {e}")