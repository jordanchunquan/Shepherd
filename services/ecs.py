'''
Class name ECSComplianceChecker
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

class ECSComplianceChecker:
    def __init__(self) -> None:
        self.ecs_latest_version = "1.4.0"
        self.failed_environment_name_list = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "ECS_ENGINE_AUTH_DATA"]
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.ecs_client = boto3.client('ecs')
        self.ecs_list = compliance_check_list

    def create_ecs_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("ECS", control_id, compliance, severity, auto_remediation):
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
    
    def ecs_task_definition_list(self) -> list[str]:
        task_definition_list: list[str] = []
        try:
            response = self.ecs_client.list_task_definitions()
            task_definition_list.extend(_ for _ in response['taskDefinitionArns'])
            while 'nextToken' in response:
                response = self.ecs_client.list_task_definitions(nextToken=response['nextToken'])
                task_definition_list.extend(_ for _ in response['taskDefinitionArns'])
            return task_definition_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def ecs_describe_task_definition_list(self) -> list[dict]:
        result_list = self.ecs_task_definition_list()
        describe_task_definition_list: list[dict] = []
        for response_detail in result_list:
            try:
                response = self.ecs_client.describe_task_definition(taskDefinition=response_detail)
                describe_task_definition_list.append(response['taskDefinition'])
            except ClientError as e:
                print(f"Error: {e}")
                return []
        return describe_task_definition_list
    
    def ecs_cluster_list(self) -> list[str]:
        cluster_list: list[str] = []
        try:
            response = self.ecs_client.list_clusters()
            cluster_list.extend(_ for _ in response['clusterArns'])
            while 'nextToken' in response:
                response = self.ecs_client.list_clusters(nextToken=response['nextToken'])
                cluster_list.extend(_ for _ in response['clusterArns'])
            return cluster_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def ecs_describe_cluster_list(self) -> list[dict]:
        result_list = self.ecs_cluster_list()
        describe_cluster_list: list[dict] = []
        try:
            response = self.ecs_client.describe_clusters(clusters=result_list)
            describe_cluster_list.extend(_ for _ in response['clusters'])
        except ClientError as e:
            print(f"Error: {e}")
            return []
        return describe_cluster_list
    
    def ecs_describe_service_list(self) -> list[dict]:
        result_list = self.ecs_cluster_list()
        describe_service_list: list[dict] = []
        for response_detail in result_list:
            try:
                service_response = self.ecs_client.list_services(cluster=response_detail)
                response = self.ecs_client.describe_services(cluster=response_detail, services=service_response['serviceArns'])
                describe_service_list.extend(_ for _ in response['services'])
                while 'nextToken' in response:
                    service_response = self.ecs_client.list_services(cluster=response_detail, nextToken=service_response['nextToken'])
                    response = self.ecs_client.describe_services(cluster=response_detail, services=service_response['serviceArns'])
                    describe_service_list.extend(_ for _ in response['services'])
            except ClientError as e:
                print(f"Error: {e}")
                return []
        return describe_service_list
    
    def ecs_describe_task_list(self) -> list[dict]:
        result_list = self.ecs_cluster_list()
        describe_task_list: list[dict] = []
        for response_detail in result_list:
            try:
                task_response = self.ecs_client.list_tasks(cluster=response_detail)
                if task_response['taskArns']:
                    response = self.ecs_client.describe_tasks(cluster=response_detail, tasks=task_response['taskArns'])
                    describe_task_list.extend(_ for _ in response['tasks'])
                    while 'nextToken' in response:
                        task_response = self.ecs_client.list_tasks(cluster=response_detail, nextToken=task_response['nextToken'])
                        response = self.ecs_client.describe_tasks(cluster=response_detail, tasks=task_response['taskArns'])
                        describe_task_list.extend(_ for _ in response['tasks'])
            except ClientError as e:
                print(f"Error: {e}")
                return []
        return describe_task_list
    
    @DecoratorClass.my_decorator
    def ecs_one(self) -> None:
        result_list = self.ecs_describe_task_definition_list()
        if not result_list:
            self.ecs_list.append(self.create_ecs_item(
                'ECS.1',
                'Amazon ECS task definitions should have secure networking modes and user definitions',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if 'networkMode' in response_detail:
                if response_detail['networkMode'] == "host":
                    for container in response_detail['containerDefinitions']:
                        if all(['user' in container, 'privileged' in container]):
                            if all([
                                any([container['user'] == "root", container['user'] == ""]),
                                any([container['privileged'] == False, container['privileged'] == ""])
                            ]):
                                compliant_status = "failed"
            self.ecs_list.append(self.create_ecs_item(
                'ECS.1',
                'Amazon ECS task definitions should have secure networking modes and user definitions',
                compliant_status,
                'HIGH',
                'not_available',
                response_detail['taskDefinitionArn']
            ))
    
    @DecoratorClass.my_decorator
    def ecs_two(self) -> None:
        result_list = self.ecs_describe_service_list()
        if not result_list:
            self.ecs_list.append(self.create_ecs_item(
                'ECS.2',
                'ECS services should not have public IP addresses assigned to them automatically',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if 'networkConfiguration' in response_detail:
                if response_detail['networkConfiguration']['awsvpcConfiguration']['assignPublicIp'] == "ENABLED":
                    compliant_status = "failed"
            self.ecs_list.append(self.create_ecs_item(
                'ECS.2',
                'ECS services should not have public IP addresses assigned to them automatically',
                compliant_status,
                'HIGH',
                'not_available',
                response_detail['serviceArn']
            ))
    
    @DecoratorClass.my_decorator
    def ecs_three(self) -> None:
        result_list = self.ecs_describe_task_definition_list()
        if not result_list:
            self.ecs_list.append(self.create_ecs_item(
                'ECS.3',
                "ECS task definitions should not share the host's process namespace",
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if response_detail.get('pidMode') == "host":
                compliant_status = "failed"
            self.ecs_list.append(self.create_ecs_item(
                'ECS.3',
                "ECS task definitions should not share the host's process namespace",
                compliant_status,
                'HIGH',
                'not_available',
                response_detail['taskDefinitionArn']
            ))
    
    @DecoratorClass.my_decorator
    def ecs_four(self) -> None:
        result_list = self.ecs_describe_task_definition_list()
        if not result_list:
            self.ecs_list.append(self.create_ecs_item(
                'ECS.4',
                'ECS containers should run as non-privileged',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            for container in response_detail['containerDefinitions']:
                if container.get('privileged'):
                    compliant_status = "failed"
            self.ecs_list.append(self.create_ecs_item(
                'ECS.4',
                'ECS containers should run as non-privileged',
                compliant_status,
                'HIGH',
                'not_available',
                response_detail['taskDefinitionArn']
            ))
    
    @DecoratorClass.my_decorator
    def ecs_five(self) -> None:
        result_list = self.ecs_describe_task_definition_list()
        if not result_list:
            self.ecs_list.append(self.create_ecs_item(
                'ECS.5',
                'ECS containers should be limited to read-only access to root filesystems',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            for container in response_detail['containerDefinitions']:
                if not container.get('readonlyRootFilesystem'):
                    compliant_status = "failed"
            self.ecs_list.append(self.create_ecs_item(
                'ECS.5',
                'ECS containers should be limited to read-only access to root filesystems',
                compliant_status,
                'HIGH',
                'not_available',
                response_detail['taskDefinitionArn']
            ))
    
    @DecoratorClass.my_decorator
    def ecs_eight(self) -> None:
        result_list = self.ecs_describe_task_definition_list()
        if not result_list:
            self.ecs_list.append(self.create_ecs_item(
                'ECS.8',
                'Secrets should not be passed as container environment variables',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            for container in response_detail['containerDefinitions']:
                if any([
                        environment['name'] in self.failed_environment_name_list
                        for environment in container['environment']
                    ]):
                    compliant_status = "failed"
            self.ecs_list.append(self.create_ecs_item(
                'ECS.8',
                'Secrets should not be passed as container environment variables',
                compliant_status,
                'HIGH',
                'not_available',
                response_detail['taskDefinitionArn']
            ))
    
    @DecoratorClass.my_decorator
    def ecs_nine(self) -> None:
        result_list = self.ecs_describe_task_definition_list()
        if not result_list:
            self.ecs_list.append(self.create_ecs_item(
                'ECS.9',
                'ECS task definitions should have a logging configuration',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            for container in response_detail['containerDefinitions']:
                if 'logConfiguration' not in container:
                    compliant_status = "failed"
                elif 'logDriver' not in container['logConfiguration']:
                    compliant_status = "failed"
            self.ecs_list.append(self.create_ecs_item(
                'ECS.9',
                'ECS task definitions should have a logging configuration',
                compliant_status,
                'HIGH',
                'not_available',
                response_detail['taskDefinitionArn']
            ))
    
    @DecoratorClass.my_decorator
    def ecs_ten(self) -> None:
        result_list = self.ecs_describe_task_list()
        if not result_list:
            self.ecs_list.append(self.create_ecs_item(
                'ECS.10',
                'ECS Fargate services should run on the latest Fargate platform version',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if 'platformVersion' in response_detail:
                if response_detail['platformVersion'] != self.ecs_latest_version:
                    compliant_status = "failed"
            self.ecs_list.append(self.create_ecs_item(
                'ECS.10',
                'ECS Fargate services should run on the latest Fargate platform version',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['taskArn']
            ))
    
    @DecoratorClass.my_decorator
    def ecs_twelve(self) -> None:
        result_list = self.ecs_describe_cluster_list()
        if not result_list:
            self.ecs_list.append(self.create_ecs_item(
                'ECS.12',
                'ECS clusters should use Container Insights',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if 'settings' not in response_detail:
                compliant_status = "failed"
            else:
                for setting in response_detail['settings']:
                    if setting['name'] == 'containerInsights' and setting['value'] != 'enabled':
                        compliant_status = "failed"
            self.ecs_list.append(self.create_ecs_item(
                'ECS.12',
                'ECS clusters should use Container Insights',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['clusterArn']
            ))
    
    @DecoratorClass.my_decorator
    def ecs_thirteen(self) -> None:
        result_list = self.ecs_describe_service_list()
        if not result_list:
            self.ecs_list.append(self.create_ecs_item(
                'ECS.13',
                'ECS services should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if 'taskSets' not in response_detail:
                compliant_status = "failed"
            else:
                for task_set in response_detail['taskSets']:
                    if 'tags' not in task_set:
                        compliant_status = "failed"
                    else:
                        tag_key_list = [tag['key'] for tag in response_detail['tags']]
                        if list(set(self.require_tag_keys) - set(tag_key_list)):
                            compliant_status = "failed"
            self.ecs_list.append(self.create_ecs_item(
                'ECS.13',
                'ECS services should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['serviceArn']
            ))
    
    @DecoratorClass.my_decorator
    def ecs_fourteen(self) -> None:
        result_list = self.ecs_describe_cluster_list()
        if not result_list:
            self.ecs_list.append(self.create_ecs_item(
                'ECS.14',
                'ECS clusters should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if 'tags' not in compliant_status:
                compliant_status = "failed"
            else:
                tag_key_list = [tag['key'] for tag in response_detail['tags']]
                if list(set(self.require_tag_keys) - set(tag_key_list)):
                    compliant_status = "failed"
            self.ecs_list.append(self.create_ecs_item(
                'ECS.14',
                'ECS clusters should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['clusterArn']
            ))
    
    @DecoratorClass.my_decorator
    def ecs_fifteen(self) -> None:
        result_list = self.ecs_describe_task_definition_list()
        if not result_list:
            self.ecs_list.append(self.create_ecs_item(
                'ECS.15',
                'ECS task definitions should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if 'tags' not in compliant_status:
                compliant_status = "failed"
            else:
                tag_key_list = [tag['key'] for tag in response_detail['tags']]
                if list(set(self.require_tag_keys) - set(tag_key_list)):
                    compliant_status = "failed"
            self.ecs_list.append(self.create_ecs_item(
                'ECS.15',
                'ECS task definitions should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['taskDefinitionArn']
            ))

class CrossAccountECSComplianceChecker:
    def __init__(self) -> None:
        self.ecs_latest_version = "1.4.0"
        self.failed_environment_name_list = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "ECS_ENGINE_AUTH_DATA"]
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.ecs_client = UseCrossAccount().client('ecs')
        self.ecs_list = compliance_check_list

    def create_ecs_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("ECS", control_id, compliance, severity, auto_remediation):
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
    
    def ecs_task_definition_list(self) -> list[str]:
        task_definition_list: list[str] = []
        try:
            response = self.ecs_client.list_task_definitions()
            task_definition_list.extend(_ for _ in response['taskDefinitionArns'])
            while 'nextToken' in response:
                response = self.ecs_client.list_task_definitions(nextToken=response['nextToken'])
                task_definition_list.extend(_ for _ in response['taskDefinitionArns'])
            return task_definition_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def ecs_describe_task_definition_list(self) -> list[dict]:
        result_list = self.ecs_task_definition_list()
        describe_task_definition_list: list[dict] = []
        for response_detail in result_list:
            try:
                response = self.ecs_client.describe_task_definition(taskDefinition=response_detail)
                describe_task_definition_list.append(response['taskDefinition'])
            except ClientError as e:
                print(f"Error: {e}")
                return []
        return describe_task_definition_list
    
    def ecs_cluster_list(self) -> list[str]:
        cluster_list: list[str] = []
        try:
            response = self.ecs_client.list_clusters()
            cluster_list.extend(_ for _ in response['clusterArns'])
            while 'nextToken' in response:
                response = self.ecs_client.list_clusters(nextToken=response['nextToken'])
                cluster_list.extend(_ for _ in response['clusterArns'])
            return cluster_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def ecs_describe_cluster_list(self) -> list[dict]:
        result_list = self.ecs_cluster_list()
        describe_cluster_list: list[dict] = []
        try:
            response = self.ecs_client.describe_clusters(clusters=result_list)
            describe_cluster_list.extend(_ for _ in response['clusters'])
        except ClientError as e:
            print(f"Error: {e}")
            return []
        return describe_cluster_list
    
    def ecs_describe_service_list(self) -> list[dict]:
        result_list = self.ecs_cluster_list()
        describe_service_list: list[dict] = []
        for response_detail in result_list:
            try:
                service_response = self.ecs_client.list_services(cluster=response_detail)
                response = self.ecs_client.describe_services(cluster=response_detail, services=service_response['serviceArns'])
                describe_service_list.extend(_ for _ in response['services'])
                while 'nextToken' in response:
                    service_response = self.ecs_client.list_services(cluster=response_detail, nextToken=service_response['nextToken'])
                    response = self.ecs_client.describe_services(cluster=response_detail, services=service_response['serviceArns'])
                    describe_service_list.extend(_ for _ in response['services'])
            except ClientError as e:
                print(f"Error: {e}")
                return []
        return describe_service_list
    
    def ecs_describe_task_list(self) -> list[dict]:
        result_list = self.ecs_cluster_list()
        describe_task_list: list[dict] = []
        for response_detail in result_list:
            try:
                task_response = self.ecs_client.list_tasks(cluster=response_detail)
                if task_response['taskArns']:
                    response = self.ecs_client.describe_tasks(cluster=response_detail, tasks=task_response['taskArns'])
                    describe_task_list.extend(_ for _ in response['tasks'])
                    while 'nextToken' in response:
                        task_response = self.ecs_client.list_tasks(cluster=response_detail, nextToken=task_response['nextToken'])
                        response = self.ecs_client.describe_tasks(cluster=response_detail, tasks=task_response['taskArns'])
                        describe_task_list.extend(_ for _ in response['tasks'])
            except ClientError as e:
                print(f"Error: {e}")
                return []
        return describe_task_list
    
    @DecoratorClass.my_decorator
    def ecs_one(self) -> None:
        result_list = self.ecs_describe_task_definition_list()
        if not result_list:
            self.ecs_list.append(self.create_ecs_item(
                'ECS.1',
                'Amazon ECS task definitions should have secure networking modes and user definitions',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if 'networkMode' in response_detail:
                if response_detail['networkMode'] == "host":
                    for container in response_detail['containerDefinitions']:
                        if all(['user' in container, 'privileged' in container]):
                            if all([
                                any([container['user'] == "root", container['user'] == ""]),
                                any([container['privileged'] == False, container['privileged'] == ""])
                            ]):
                                compliant_status = "failed"
            self.ecs_list.append(self.create_ecs_item(
                'ECS.1',
                'Amazon ECS task definitions should have secure networking modes and user definitions',
                compliant_status,
                'HIGH',
                'not_available',
                response_detail['taskDefinitionArn']
            ))
    
    @DecoratorClass.my_decorator
    def ecs_two(self) -> None:
        result_list = self.ecs_describe_service_list()
        if not result_list:
            self.ecs_list.append(self.create_ecs_item(
                'ECS.2',
                'ECS services should not have public IP addresses assigned to them automatically',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if 'networkConfiguration' in response_detail:
                if response_detail['networkConfiguration']['awsvpcConfiguration']['assignPublicIp'] == "ENABLED":
                    compliant_status = "failed"
            self.ecs_list.append(self.create_ecs_item(
                'ECS.2',
                'ECS services should not have public IP addresses assigned to them automatically',
                compliant_status,
                'HIGH',
                'not_available',
                response_detail['serviceArn']
            ))
    
    @DecoratorClass.my_decorator
    def ecs_three(self) -> None:
        result_list = self.ecs_describe_task_definition_list()
        if not result_list:
            self.ecs_list.append(self.create_ecs_item(
                'ECS.3',
                "ECS task definitions should not share the host's process namespace",
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if response_detail.get('pidMode') == "host":
                compliant_status = "failed"
            self.ecs_list.append(self.create_ecs_item(
                'ECS.3',
                "ECS task definitions should not share the host's process namespace",
                compliant_status,
                'HIGH',
                'not_available',
                response_detail['taskDefinitionArn']
            ))
    
    @DecoratorClass.my_decorator
    def ecs_four(self) -> None:
        result_list = self.ecs_describe_task_definition_list()
        if not result_list:
            self.ecs_list.append(self.create_ecs_item(
                'ECS.4',
                'ECS containers should run as non-privileged',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            for container in response_detail['containerDefinitions']:
                if container.get('privileged'):
                    compliant_status = "failed"
            self.ecs_list.append(self.create_ecs_item(
                'ECS.4',
                'ECS containers should run as non-privileged',
                compliant_status,
                'HIGH',
                'not_available',
                response_detail['taskDefinitionArn']
            ))
    
    @DecoratorClass.my_decorator
    def ecs_five(self) -> None:
        result_list = self.ecs_describe_task_definition_list()
        if not result_list:
            self.ecs_list.append(self.create_ecs_item(
                'ECS.5',
                'ECS containers should be limited to read-only access to root filesystems',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            for container in response_detail['containerDefinitions']:
                if not container.get('readonlyRootFilesystem'):
                    compliant_status = "failed"
            self.ecs_list.append(self.create_ecs_item(
                'ECS.5',
                'ECS containers should be limited to read-only access to root filesystems',
                compliant_status,
                'HIGH',
                'not_available',
                response_detail['taskDefinitionArn']
            ))
    
    @DecoratorClass.my_decorator
    def ecs_eight(self) -> None:
        failed_environment_name_list = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "ECS_ENGINE_AUTH_DATA"]
        result_list = self.ecs_describe_task_definition_list()
        if not result_list:
            self.ecs_list.append(self.create_ecs_item(
                'ECS.8',
                'Secrets should not be passed as container environment variables',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            for container in response_detail['containerDefinitions']:
                if any([
                        environment['name'] in self.failed_environment_name_list
                        for environment in container['environment']
                    ]):
                    compliant_status = "failed"
            self.ecs_list.append(self.create_ecs_item(
                'ECS.8',
                'Secrets should not be passed as container environment variables',
                compliant_status,
                'HIGH',
                'not_available',
                response_detail['taskDefinitionArn']
            ))
    
    @DecoratorClass.my_decorator
    def ecs_nine(self) -> None:
        result_list = self.ecs_describe_task_definition_list()
        if not result_list:
            self.ecs_list.append(self.create_ecs_item(
                'ECS.9',
                'ECS task definitions should have a logging configuration',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            for container in response_detail['containerDefinitions']:
                if 'logConfiguration' not in container:
                    compliant_status = "failed"
                elif 'logDriver' not in container['logConfiguration']:
                    compliant_status = "failed"
            self.ecs_list.append(self.create_ecs_item(
                'ECS.9',
                'ECS task definitions should have a logging configuration',
                compliant_status,
                'HIGH',
                'not_available',
                response_detail['taskDefinitionArn']
            ))
    
    @DecoratorClass.my_decorator
    def ecs_ten(self) -> None:
        result_list = self.ecs_describe_task_list()
        if not result_list:
            self.ecs_list.append(self.create_ecs_item(
                'ECS.10',
                'ECS Fargate services should run on the latest Fargate platform version',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if 'platformVersion' in response_detail:
                if response_detail['platformVersion'] != self.ecs_latest_version:
                    compliant_status = "failed"
            self.ecs_list.append(self.create_ecs_item(
                'ECS.10',
                'ECS Fargate services should run on the latest Fargate platform version',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['taskArn']
            ))
    
    @DecoratorClass.my_decorator
    def ecs_twelve(self) -> None:
        result_list = self.ecs_describe_cluster_list()
        if not result_list:
            self.ecs_list.append(self.create_ecs_item(
                'ECS.12',
                'ECS clusters should use Container Insights',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if 'settings' not in response_detail:
                compliant_status = "failed"
            else:
                for setting in response_detail['settings']:
                    if setting['name'] == 'containerInsights' and setting['value'] != 'enabled':
                        compliant_status = "failed"
            self.ecs_list.append(self.create_ecs_item(
                'ECS.12',
                'ECS clusters should use Container Insights',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['clusterArn']
            ))
    
    @DecoratorClass.my_decorator
    def ecs_thirteen(self) -> None:
        result_list = self.ecs_describe_service_list()
        if not result_list:
            self.ecs_list.append(self.create_ecs_item(
                'ECS.13',
                'ECS services should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if 'taskSets' not in response_detail:
                compliant_status = "failed"
            else:
                for task_set in response_detail['taskSets']:
                    if 'tags' not in task_set:
                        compliant_status = "failed"
                    else:
                        tag_key_list = [tag['key'] for tag in response_detail['tags']]
                        if list(set(self.require_tag_keys) - set(tag_key_list)):
                            compliant_status = "failed"
            self.ecs_list.append(self.create_ecs_item(
                'ECS.13',
                'ECS services should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['serviceArn']
            ))
    
    @DecoratorClass.my_decorator
    def ecs_fourteen(self) -> None:
        result_list = self.ecs_describe_cluster_list()
        if not result_list:
            self.ecs_list.append(self.create_ecs_item(
                'ECS.14',
                'ECS clusters should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if 'tags' not in compliant_status:
                compliant_status = "failed"
            else:
                tag_key_list = [tag['key'] for tag in response_detail['tags']]
                if list(set(self.require_tag_keys) - set(tag_key_list)):
                    compliant_status = "failed"
            self.ecs_list.append(self.create_ecs_item(
                'ECS.14',
                'ECS clusters should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['clusterArn']
            ))
    
    @DecoratorClass.my_decorator
    def ecs_fifteen(self) -> None:
        result_list = self.ecs_describe_task_definition_list()
        if not result_list:
            self.ecs_list.append(self.create_ecs_item(
                'ECS.15',
                'ECS task definitions should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if 'tags' not in compliant_status:
                compliant_status = "failed"
            else:
                tag_key_list = [tag['key'] for tag in response_detail['tags']]
                if list(set(self.require_tag_keys) - set(tag_key_list)):
                    compliant_status = "failed"
            self.ecs_list.append(self.create_ecs_item(
                'ECS.15',
                'ECS task definitions should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['taskDefinitionArn']
            ))