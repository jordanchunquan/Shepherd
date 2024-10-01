'''
Class name EventBridgeComplianceChecker
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

class EventBridgeComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.eventbridge_client = boto3.client('events')
        self.eventbridge_list = compliance_check_list

    def create_eventbridge_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("EventBridge", control_id, compliance, severity, auto_remediation):
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
    
    def event_bus_list(self) -> list[dict]:
        bus_list: list[dict] = []
        try:
            response = self.eventbridge_client.describe_event_bus()
            bus_list.append(response)
            return bus_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def eventbridge_tag_list(self, eventbridge_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.eventbridge_client.list_tags_for_resource(ResourceARN=eventbridge_arn)
            tag_key_list = [_['Key'] for _ in response['Tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        
    def global_endpoint_list(self) -> list[dict]:
        endpoint_list: list[dict] = []
        try:
            response = self.eventbridge_client.list_endpoints()
            endpoint_list.extend(_ for _ in response['Endpoints'])
            while 'NextToken' in response:
                response = self.eventbridge_client.list_endpoints(NextToken=response['NextToken'])
                endpoint_list.extend(_ for _ in response['Endpoints'])
            return endpoint_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def describe_global_endpoint_list(self) -> list[dict]:
        result_list = self.global_endpoint_list()
        result_list = [_['Name'] for _ in result_list]
        global_endpoint_list: list[dict] = []
        try:
            for result in result_list:
                response = self.eventbridge_client.describe_endpoint(Name=result)
                global_endpoint_list.append(response)
            return global_endpoint_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    @DecoratorClass.my_decorator
    def eventbridge_two(self) -> None:
        result_list = self.event_bus_list()
        if not result_list:
            self.eventbridge_list.append(self.create_eventbridge_item(
                'EventBridge.2',
                'EventBridge event buses should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for result in result_list:
            compliant_status = self.eventbridge_tag_list(result['Arn'])
            self.eventbridge_list.append(self.create_eventbridge_item(
                'EventBridge.2',
                'EventBridge event buses should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                result['Arn']
            ))
    
    @DecoratorClass.my_decorator
    def eventbridge_three(self) -> None:
        result_list = self.event_bus_list()
        result_list = [_ for _ in result_list if _['Name'] != "default" and "/" not in _['Name']]
        if not result_list:
            self.eventbridge_list.append(self.create_eventbridge_item(
                'EventBridge.3',
                'EventBridge custom event buses should have a resource-based policy attached',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for result in result_list:
            compliant_status = "passed"
            if result.get('Policy') == None:
                compliant_status = "failed"
            self.eventbridge_list.append(self.create_eventbridge_item(
                'EventBridge.3',
                'EventBridge custom event buses should have a resource-based policy attached',
                compliant_status,
                'LOW',
                'not_available',
                result['Arn']
            ))
    
    @DecoratorClass.my_decorator
    def eventbridge_four(self) -> None:
        result_list = self.describe_global_endpoint_list()
        if not result_list:
            self.eventbridge_list.append(self.create_eventbridge_item(
                'EventBridge.4',
                'EventBridge global endpoints should have event replication enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for result in result_list:
            if result.get('ReplicationConfig') != "ENABLED":
                self.eventbridge_list.append(self.create_eventbridge_item(
                    'EventBridge.4',
                    'EventBridge global endpoints should have event replication enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    result['Arn']
                ))
            else:
                self.eventbridge_list.append(self.create_eventbridge_item(
                    'EventBridge.4',
                    'EventBridge global endpoints should have event replication enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    result['Arn']
                ))

class CrossAccountEventBridgeComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.eventbridge_client = UseCrossAccount().client('events')
        self.eventbridge_list = compliance_check_list

    def create_eventbridge_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("EventBridge", control_id, compliance, severity, auto_remediation):
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
    
    def event_bus_list(self) -> list[dict]:
        bus_list: list[dict] = []
        try:
            response = self.eventbridge_client.describe_event_bus()
            bus_list.append(response)
            return bus_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def eventbridge_tag_list(self, eventbridge_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.eventbridge_client.list_tags_for_resource(ResourceARN=eventbridge_arn)
            tag_key_list = [_['Key'] for _ in response['Tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        
    def global_endpoint_list(self) -> list[dict]:
        endpoint_list: list[dict] = []
        try:
            response = self.eventbridge_client.list_endpoints()
            endpoint_list.extend(_ for _ in response['Endpoints'])
            while 'NextToken' in response:
                response = self.eventbridge_client.list_endpoints(NextToken=response['NextToken'])
                endpoint_list.extend(_ for _ in response['Endpoints'])
            return endpoint_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def describe_global_endpoint_list(self) -> list[dict]:
        result_list = self.global_endpoint_list()
        result_list = [_['Name'] for _ in result_list]
        global_endpoint_list: list[dict] = []
        try:
            for result in result_list:
                response = self.eventbridge_client.describe_endpoint(Name=result)
                global_endpoint_list.append(response)
            return global_endpoint_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    @DecoratorClass.my_decorator
    def eventbridge_two(self) -> None:
        result_list = self.event_bus_list()
        if not result_list:
            self.eventbridge_list.append(self.create_eventbridge_item(
                'EventBridge.2',
                'EventBridge event buses should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for result in result_list:
            compliant_status = self.eventbridge_tag_list(result['Arn'])
            self.eventbridge_list.append(self.create_eventbridge_item(
                'EventBridge.2',
                'EventBridge event buses should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                result['Arn']
            ))
    
    @DecoratorClass.my_decorator
    def eventbridge_three(self) -> None:
        result_list = self.event_bus_list()
        result_list = [_ for _ in result_list if _['Name'] != "default" and "/" not in _['Name']]
        if not result_list:
            self.eventbridge_list.append(self.create_eventbridge_item(
                'EventBridge.3',
                'EventBridge custom event buses should have a resource-based policy attached',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for result in result_list:
            compliant_status = "passed"
            if result.get('Policy') == None:
                compliant_status = "failed"
            self.eventbridge_list.append(self.create_eventbridge_item(
                'EventBridge.3',
                'EventBridge custom event buses should have a resource-based policy attached',
                compliant_status,
                'LOW',
                'not_available',
                result['Arn']
            ))
    
    @DecoratorClass.my_decorator
    def eventbridge_four(self) -> None:
        result_list = self.describe_global_endpoint_list()
        if not result_list:
            self.eventbridge_list.append(self.create_eventbridge_item(
                'EventBridge.4',
                'EventBridge global endpoints should have event replication enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for result in result_list:
            if result.get('ReplicationConfig') != "ENABLED":
                self.eventbridge_list.append(self.create_eventbridge_item(
                    'EventBridge.4',
                    'EventBridge global endpoints should have event replication enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    result['Arn']
                ))
            else:
                self.eventbridge_list.append(self.create_eventbridge_item(
                    'EventBridge.4',
                    'EventBridge global endpoints should have event replication enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    result['Arn']
                ))