'''
Class name GuardDutyComplianceChecker
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

class GuardDutyComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.guardduty_client = boto3.client('guardduty')
        self.session_account = boto3.client('sts').get_caller_identity().get('Account')
        self.session_region = boto3.session.Session().region_name
        self.guardduty_list = compliance_check_list

    def create_guardduty_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("GuardDuty", control_id, compliance, severity, auto_remediation):
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
    
    def guardduty_detector_list(self) -> list[str]:
        detector_list: list[str] = []
        try:
            response = self.guardduty_client.list_detectors()
            detector_list.extend(_ for _ in response['DetectorIds'])
            while 'NextToken' in response:
                response = self.guardduty_client.list_detectors(NextToken=response['NextToken'])
                detector_list.extend(_ for _ in response['DetectorIds'])
            return detector_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def guardduty_filter_list(self) -> list[str]:
        filter_arn_list: list[str] = []
        result_list = self.guardduty_detector_list()
        for detector in result_list:
            try:
                response = self.guardduty_client.list_filters(DetectorId=detector)
                for response_detail in response['FilterNames']:
                    filter_arn_list.append(f"arn:aws:guardduty:{self.session_region}:{self.session_account}:detector/{detector}/filter/{response_detail}")
                while 'NextToken' in response:
                    response = self.guardduty_client.list_filters(DetectorId=detector, NextToken=response['NextToken'])
                    for response_detail in response['FilterNames']:
                        filter_arn_list.append(f"arn:aws:guardduty:{self.session_region}:{self.session_account}:detector/{detector}/filter/{response_detail}")
            except ClientError as e:
                print(f"Error: {e}")
                return []
        return filter_arn_list
    
    def guardduty_ipset_list(self) -> list[str]:
        ipset_arn_list: list[str] = []
        result_list = self.guardduty_detector_list()
        for detector in result_list:
            try:
                response = self.guardduty_client.list_ip_sets(DetectorId=detector)
                for response_detail in response['IpSetIds']:
                    ipset_arn_list.append(f"arn:aws:guardduty:{self.session_region}:{self.session_account}:detector/{detector}/ipset/{response_detail}")
                while 'NextToken' in response:
                    response = self.guardduty_client.list_ip_sets(DetectorId=detector, NextToken=response['NextToken'])
                    for response_detail in response['IpSetIds']:
                        ipset_arn_list.append(f"arn:aws:guardduty:{self.session_region}:{self.session_account}:detector/{detector}/ipset/{response_detail}")
            except ClientError as e:
                print(f"Error: {e}")
                return []
        return ipset_arn_list
    
    def guardduty_tag_compliant(self, guardduty_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.guardduty_client.list_tags_for_resource(ResourceArn=guardduty_arn)
            tag_key_list = [tag['Key'] for tag in response['Tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""

    @DecoratorClass.my_decorator
    def guardduty_one(self) -> None:
        result_list = self.guardduty_detector_list()
        if not result_list:
            self.guardduty_list.append(self.create_guardduty_item(
                'GuardDuty.1',
                'GuardDuty should be enabled',
                'failed',
                'HIGH',
                'not_available',
                self.session_account
            ))
        else:
            self.guardduty_list.append(self.create_guardduty_item(
                'GuardDuty.1',
                'GuardDuty should be enabled',
                'passed',
                'HIGH',
                'not_available',
                self.session_account
            ))

    @DecoratorClass.my_decorator
    def guardduty_two(self) -> None:
        result_list = self.guardduty_filter_list()
        if not result_list:
            self.guardduty_list.append(self.create_guardduty_item(
                'GuardDuty.2',
                'GuardDuty filters should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.guardduty_tag_compliant(response_detail)
            self.guardduty_list.append(self.create_guardduty_item(
                'GuardDuty.2',
                'GuardDuty filters should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail
            ))

    @DecoratorClass.my_decorator
    def guardduty_three(self) -> None:
        result_list = self.guardduty_ipset_list()
        if not result_list:
            self.guardduty_list.append(self.create_guardduty_item(
                'GuardDuty.3',
                'GuardDuty IPSets should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.guardduty_tag_compliant(response_detail)
            self.guardduty_list.append(self.create_guardduty_item(
                'GuardDuty.3',
                'GuardDuty IPSets should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail
            ))

    @DecoratorClass.my_decorator
    def guardduty_four(self) -> None:
        result_list = self.guardduty_ipset_list()
        if not result_list:
            self.guardduty_list.append(self.create_guardduty_item(
                'GuardDuty.4',
                'GuardDuty detectors should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        result_list = [f"arn:aws:guardduty:{self.session_region}:{self.session_account}:detector/{_}" for _ in result_list]
        for response_detail in result_list:
            compliant_status = self.guardduty_tag_compliant(response_detail)
            self.guardduty_list.append(self.create_guardduty_item(
                'GuardDuty.3',
                'GuardDuty detectors should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail
            ))

class CrossAccountGuardDutyComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.guardduty_client = UseCrossAccount().client('guardduty')
        self.session_account = UseCrossAccount().client('sts').get_caller_identity().get('Account')
        self.session_region = UseCrossAccount().session_region_name
        self.guardduty_list = compliance_check_list

    def create_guardduty_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("GuardDuty", control_id, compliance, severity, auto_remediation):
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
    
    def guardduty_detector_list(self) -> list[str]:
        detector_list: list[str] = []
        try:
            response = self.guardduty_client.list_detectors()
            detector_list.extend(_ for _ in response['DetectorIds'])
            while 'NextToken' in response:
                response = self.guardduty_client.list_detectors(NextToken=response['NextToken'])
                detector_list.extend(_ for _ in response['DetectorIds'])
            return detector_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def guardduty_filter_list(self) -> list[str]:
        filter_arn_list: list[str] = []
        result_list = self.guardduty_detector_list()
        for detector in result_list:
            try:
                response = self.guardduty_client.list_filters(DetectorId=detector)
                for response_detail in response['FilterNames']:
                    filter_arn_list.append(f"arn:aws:guardduty:{self.session_region}:{self.session_account}:detector/{detector}/filter/{response_detail}")
                while 'NextToken' in response:
                    response = self.guardduty_client.list_filters(DetectorId=detector, NextToken=response['NextToken'])
                    for response_detail in response['FilterNames']:
                        filter_arn_list.append(f"arn:aws:guardduty:{self.session_region}:{self.session_account}:detector/{detector}/filter/{response_detail}")
            except ClientError as e:
                print(f"Error: {e}")
                return []
        return filter_arn_list
    
    def guardduty_ipset_list(self) -> list[str]:
        ipset_arn_list: list[str] = []
        result_list = self.guardduty_detector_list()
        for detector in result_list:
            try:
                response = self.guardduty_client.list_ip_sets(DetectorId=detector)
                for response_detail in response['IpSetIds']:
                    ipset_arn_list.append(f"arn:aws:guardduty:{self.session_region}:{self.session_account}:detector/{detector}/ipset/{response_detail}")
                while 'NextToken' in response:
                    response = self.guardduty_client.list_ip_sets(DetectorId=detector, NextToken=response['NextToken'])
                    for response_detail in response['IpSetIds']:
                        ipset_arn_list.append(f"arn:aws:guardduty:{self.session_region}:{self.session_account}:detector/{detector}/ipset/{response_detail}")
            except ClientError as e:
                print(f"Error: {e}")
                return []
        return ipset_arn_list
    
    def guardduty_tag_compliant(self, guardduty_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.guardduty_client.list_tags_for_resource(ResourceArn=guardduty_arn)
            tag_key_list = [tag['Key'] for tag in response['Tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""

    @DecoratorClass.my_decorator
    def guardduty_one(self) -> None:
        result_list = self.guardduty_detector_list()
        if not result_list:
            self.guardduty_list.append(self.create_guardduty_item(
                'GuardDuty.1',
                'GuardDuty should be enabled',
                'failed',
                'HIGH',
                'not_available',
                self.session_account
            ))
        else:
            self.guardduty_list.append(self.create_guardduty_item(
                'GuardDuty.1',
                'GuardDuty should be enabled',
                'passed',
                'HIGH',
                'not_available',
                self.session_account
            ))

    @DecoratorClass.my_decorator
    def guardduty_two(self) -> None:
        result_list = self.guardduty_filter_list()
        if not result_list:
            self.guardduty_list.append(self.create_guardduty_item(
                'GuardDuty.2',
                'GuardDuty filters should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.guardduty_tag_compliant(response_detail)
            self.guardduty_list.append(self.create_guardduty_item(
                'GuardDuty.2',
                'GuardDuty filters should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail
            ))

    @DecoratorClass.my_decorator
    def guardduty_three(self) -> None:
        result_list = self.guardduty_ipset_list()
        if not result_list:
            self.guardduty_list.append(self.create_guardduty_item(
                'GuardDuty.3',
                'GuardDuty IPSets should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.guardduty_tag_compliant(response_detail)
            self.guardduty_list.append(self.create_guardduty_item(
                'GuardDuty.3',
                'GuardDuty IPSets should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail
            ))

    @DecoratorClass.my_decorator
    def guardduty_four(self) -> None:
        result_list = self.guardduty_ipset_list()
        if not result_list:
            self.guardduty_list.append(self.create_guardduty_item(
                'GuardDuty.4',
                'GuardDuty detectors should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        result_list = [f"arn:aws:guardduty:{self.session_region}:{self.session_account}:detector/{_}" for _ in result_list]
        for response_detail in result_list:
            compliant_status = self.guardduty_tag_compliant(response_detail)
            self.guardduty_list.append(self.create_guardduty_item(
                'GuardDuty.3',
                'GuardDuty detectors should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail
            ))