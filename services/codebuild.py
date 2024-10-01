'''
Class name CodeBuildComplianceChecker
Create functions to check compliants and return as 
'control_id': security contorl id,
'control_title': security control title,
'compliance': passed, failed or not_found,
'severity': CRITICAL, HIGH, MEDIUM or LOW,
'auto_remediation': available or not_available,
'resource_id': account id, resource arn or not_found

Unable to autoremediate CodeBuild one becuase it require approval from developer to delete sensitive credentials
Unable to autoremediate CodeBuild two becuase it require approval from developer to delete text credentials
CodeBuild three should be autoremediate by S3 seventeen
'''

import boto3 # type: ignore
from botocore.exceptions import ClientError # type: ignore
from utils.decorator_class import DecoratorClass # type: ignore
from utils.validate import ParameterValidation # type: ignore
from utils.cross_account import UseCrossAccount # type: ignore
from utils.global_data import compliance_check_list # type: ignore

class CodeBuildComplianceChecker:
    def __init__(self) -> None:
        self.codebuild_client = boto3.client('codebuild')
        self.codebuild_list = compliance_check_list

    def create_codebuild_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("CodeBuild", control_id, compliance, severity, auto_remediation):
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
    
    def code_build_project_name_list(self) -> list[dict]:
        codebuild_list: list[dict] = []
        try:
            response = self.codebuild_client.list_projects()
            for _ in response['projects']:
                codebuild_list.append(_)
            while 'nextToken' in response:
                response = self.codebuild_client.list_projects(nextToken=response['nextToken'])
                for _ in response['projects']:
                    codebuild_list.append(_)
            return codebuild_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def code_build_project_list(self) -> list[dict]:
        result_list = self.code_build_project_name_list()
        codebuild_list: list[dict] = []
        if not result_list:
            return codebuild_list
        try:
            response = self.codebuild_client.batch_get_projects(names=result_list)
            codebuild_list.extend(_ for _ in response['projects'])
            return codebuild_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    @DecoratorClass.my_decorator
    def codebuild_one(self) -> None:
        result_list = self.code_build_project_list()
        if not result_list:
            self.codebuild_list.append(self.create_codebuild_item(
                'CodeBuild.1',
                'CodeBuild Bitbucket source repository URLs should not contain sensitive credentials',
                'not_found',
                'CRITICAL',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['source']['auth']['type'] != "OAUTH" \
            or response_detail['secondarySources']['auth']['type'] != "OAUTH":
                self.codebuild_list.append(self.create_codebuild_item(
                    'CodeBuild.1',
                    'CodeBuild Bitbucket source repository URLs should not contain sensitive credentials',
                    'failed',
                    'CRITICAL',
                    'not_available',
                    response_detail['arn']
                ))
            else:
                self.codebuild_list.append(self.create_codebuild_item(
                    'CodeBuild.1',
                    'CodeBuild Bitbucket source repository URLs should not contain sensitive credentials',
                    'passed',
                    'CRITICAL',
                    'not_available',
                    response_detail['arn']
                ))

    @DecoratorClass.my_decorator
    def codebuild_two(self) -> None:
        result_list = self.code_build_project_list()
        if not result_list:
            self.codebuild_list.append(self.create_codebuild_item(
                'CodeBuild.2',
                'CodeBuild project environment variables should not contain clear text credentials',
                'not_found',
                'CRITICAL',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if any('AWS_ACCESS_KEY_ID' in _.keys() or 'AWS_SECRET_ACCESS_KEY' in _.keys() \
                for _ in response_detail['environment']['environmentVariables']):
                self.codebuild_list.append(self.create_codebuild_item(
                    'CodeBuild.2',
                    'CodeBuild project environment variables should not contain clear text credentials',
                    'failed',
                    'CRITICAL',
                    'not_available',
                    response_detail['arn']
                ))
            else:
                self.codebuild_list.append(self.create_codebuild_item(
                    'CodeBuild.2',
                    'CodeBuild project environment variables should not contain clear text credentials',
                    'passed',
                    'CRITICAL',
                    'not_available',
                    response_detail['arn']
                ))

    @DecoratorClass.my_decorator
    def codebuild_three(self) -> None:
        result_list = self.code_build_project_list()
        if not result_list:
            self.codebuild_list.append(self.create_codebuild_item(
                'CodeBuild.3',
                'CodeBuild S3 logs should be encrypted',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['logsConfig']['s3Logs']['encryptionDisabled'] == False:
                self.codebuild_list.append(self.create_codebuild_item(
                    'CodeBuild.3',
                    'CodeBuild S3 logs should be encrypted',
                    'failed',
                    'LOW',
                    'not_available',
                    response_detail['arn']
                ))
            else:
                self.codebuild_list.append(self.create_codebuild_item(
                    'CodeBuild.3',
                    'CodeBuild S3 logs should be encrypted',
                    'passed',
                    'LOW',
                    'not_available',
                    response_detail['arn']
                ))

    @DecoratorClass.my_decorator
    def codebuild_four(self) -> None:
        result_list = self.code_build_project_list()
        if not result_list:
            self.codebuild_list.append(self.create_codebuild_item(
                'CodeBuild.4',
                'CodeBuild project environments should have a logging AWS Configuration',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['logsConfig']['cloudWatchLogs']['status'] == 'DISABLED':
                self.codebuild_list.append(self.create_codebuild_item(
                    'CodeBuild.4',
                    'CodeBuild project environments should have a logging AWS Configuration',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['arn']
                ))
            else:
                self.codebuild_list.append(self.create_codebuild_item(
                    'CodeBuild.4',
                    'CodeBuild project environments should have a logging AWS Configuration',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['arn']
                ))

class CrossAccountCodeBuildComplianceChecker:
    def __init__(self) -> None:
        self.codebuild_client = UseCrossAccount().client('codebuild')
        self.codebuild_list = compliance_check_list

    def create_codebuild_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("CodeBuild", control_id, compliance, severity, auto_remediation):
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
    
    def code_build_project_name_list(self) -> list[dict]:
        codebuild_list: list[dict] = []
        try:
            response = self.codebuild_client.list_projects()
            for _ in response['projects']:
                codebuild_list.append(_)
            while 'nextToken' in response:
                response = self.codebuild_client.list_projects(nextToken=response['nextToken'])
                for _ in response['projects']:
                    codebuild_list.append(_)
            return codebuild_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def code_build_project_list(self) -> list[dict]:
        result_list = self.code_build_project_name_list()
        codebuild_list: list[dict] = []
        if not result_list:
            return codebuild_list
        try:
            response = self.codebuild_client.batch_get_projects(names=result_list)
            codebuild_list.extend(_ for _ in response['projects'])
            return codebuild_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    @DecoratorClass.my_decorator
    def codebuild_one(self) -> None:
        result_list = self.code_build_project_list()
        if not result_list:
            self.codebuild_list.append(self.create_codebuild_item(
                'CodeBuild.1',
                'CodeBuild Bitbucket source repository URLs should not contain sensitive credentials',
                'not_found',
                'CRITICAL',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['source']['auth']['type'] != "OAUTH" \
            or response_detail['secondarySources']['auth']['type'] != "OAUTH":
                self.codebuild_list.append(self.create_codebuild_item(
                    'CodeBuild.1',
                    'CodeBuild Bitbucket source repository URLs should not contain sensitive credentials',
                    'failed',
                    'CRITICAL',
                    'not_available',
                    response_detail['arn']
                ))
            else:
                self.codebuild_list.append(self.create_codebuild_item(
                    'CodeBuild.1',
                    'CodeBuild Bitbucket source repository URLs should not contain sensitive credentials',
                    'passed',
                    'CRITICAL',
                    'not_available',
                    response_detail['arn']
                ))

    @DecoratorClass.my_decorator
    def codebuild_two(self) -> None:
        result_list = self.code_build_project_list()
        if not result_list:
            self.codebuild_list.append(self.create_codebuild_item(
                'CodeBuild.2',
                'CodeBuild project environment variables should not contain clear text credentials',
                'not_found',
                'CRITICAL',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if any('AWS_ACCESS_KEY_ID' in _.keys() or 'AWS_SECRET_ACCESS_KEY' in _.keys() \
                for _ in response_detail['environment']['environmentVariables']):
                self.codebuild_list.append(self.create_codebuild_item(
                    'CodeBuild.2',
                    'CodeBuild project environment variables should not contain clear text credentials',
                    'failed',
                    'CRITICAL',
                    'not_available',
                    response_detail['arn']
                ))
            else:
                self.codebuild_list.append(self.create_codebuild_item(
                    'CodeBuild.2',
                    'CodeBuild project environment variables should not contain clear text credentials',
                    'passed',
                    'CRITICAL',
                    'not_available',
                    response_detail['arn']
                ))

    @DecoratorClass.my_decorator
    def codebuild_three(self) -> None:
        result_list = self.code_build_project_list()
        if not result_list:
            self.codebuild_list.append(self.create_codebuild_item(
                'CodeBuild.3',
                'CodeBuild S3 logs should be encrypted',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['logsConfig']['s3Logs']['encryptionDisabled'] == False:
                self.codebuild_list.append(self.create_codebuild_item(
                    'CodeBuild.3',
                    'CodeBuild S3 logs should be encrypted',
                    'failed',
                    'LOW',
                    'not_available',
                    response_detail['arn']
                ))
            else:
                self.codebuild_list.append(self.create_codebuild_item(
                    'CodeBuild.3',
                    'CodeBuild S3 logs should be encrypted',
                    'passed',
                    'LOW',
                    'not_available',
                    response_detail['arn']
                ))

    @DecoratorClass.my_decorator
    def codebuild_four(self) -> None:
        result_list = self.code_build_project_list()
        if not result_list:
            self.codebuild_list.append(self.create_codebuild_item(
                'CodeBuild.4',
                'CodeBuild project environments should have a logging AWS Configuration',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['logsConfig']['cloudWatchLogs']['status'] == 'DISABLED':
                self.codebuild_list.append(self.create_codebuild_item(
                    'CodeBuild.4',
                    'CodeBuild project environments should have a logging AWS Configuration',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['arn']
                ))
            else:
                self.codebuild_list.append(self.create_codebuild_item(
                    'CodeBuild.4',
                    'CodeBuild project environments should have a logging AWS Configuration',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['arn']
                ))