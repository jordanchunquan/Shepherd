'''
Class name ServiceComplianceChecker
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
from datetime import datetime

class ServiceComplianceChecker:
    def __init__(self) -> None:
        self.service_client = boto3.client('')
        self.service_list = compliance_check_list # type: ignore

    def create_service_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("Service Name", control_id, compliance, severity, auto_remediation):
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
    
    def service_list(self) -> list[dict]:
        service_list: list[dict] = []
        try:
            response = boto3.client('').function()
            service_list.append(response)
            return service_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def service_list(self) -> list[dict]: # type: ignore
        next_token: str = None # type: ignore
        service_list: list[dict] = []
        while True:
            try:
                response_iterator = boto3.client('').get_paginator('').paginate(
                    PaginationConfig={
                        'StartingToken': next_token
                        }
                    )
                for page in response_iterator:
                    service_page_list = page['']
                    service_list.extend(service[''] for service in service_page_list)
                    if 'NextToken' in page:
                        next_token = page['NextToken']
                    else:
                        return service_list
            except ClientError as e:
                print(f"Error: {e}")
                return []
    
    @DecoratorClass.my_decorator
    def service_number(self) -> None:
        result_list = self.service_list()
        if not result_list:
            self.service_list.append(self.create_service_item( # type: ignore
                'Service.number',
                'Control Title',
                'not_found',
                'SEVERITY',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if statement: # type: ignore
                self.service_list.append(self.create_service_item( # type: ignore
                    'Service.number',
                    'Control Title',
                    'failed',
                    'SEVERITY',
                    'not_available',
                    response_detail['Arn']
                ))
            self.service_list.append(self.create_service_item( # type: ignore
                'Service.number',
                'Control Title',
                'passed',
                'SEVERITY',
                'not_available',
                response_detail['Arn']
            ))