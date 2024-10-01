'''
Class name IoTComplianceChecker
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

class IoTComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.iot_client = boto3.client('iot')
        self.session_account = boto3.client('sts').get_caller_identity()['Account']
        self.session_region = boto3.session.Session().region_name
        self.iot_list = compliance_check_list

    def create_iot_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("IoT", control_id, compliance, severity, auto_remediation):
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
    
    def iot_security_profile_list(self) -> list[dict]:
        securityprofile_list: list[dict] = []
        try:
            response = self.iot_client.list_security_profiles()
            securityprofile_list.extend(_ for _ in response['securityProfileIdentifiers'])
            while 'nextToken' in response:
                response = self.iot_client.list_security_profiles(NextToken=response['nextToken'])
                securityprofile_list.extend(_ for _ in response['securityProfileIdentifiers'])
            return securityprofile_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def iot_mitigation_action_list(self) -> list[dict]:
        mitigationaction_list: list[dict] = []
        try:
            response = self.iot_client.list_mitigation_actions()
            mitigationaction_list.extend(_ for _ in response['actionIdentifiers'])
            while 'nextToken' in response:
                response = self.iot_client.list_mitigation_actions(NextToken=response['nextToken'])
                mitigationaction_list.extend(_ for _ in response['actionIdentifiers'])
            return mitigationaction_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def iot_dimension_list(self) -> list[str]:
        dimension_list: list[str] = []
        try:
            response = self.iot_client.list_dimensions()
            for response_detail in response['dimensionNames']:
                dimension_list.append(f"arn:aws:iot:{self.session_region}:{self.session_account}:dimension/{response_detail}")
            while 'nextToken' in response:
                response = self.iot_client.list_dimensions(NextToken=response['nextToken'])
                for response_detail in response['dimensionNames']:
                    dimension_list.append(f"arn:aws:iot:{self.session_region}:{self.session_account}:dimension/{response_detail}")
            return dimension_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def iot_authorizer_list(self) -> list[dict]:
        authorizer_list: list[dict] = []
        try:
            response = self.iot_client.list_authorizers()
            authorizer_list.extend(_ for _ in response['authorizers'])
            while 'nextMarker' in response:
                response = self.iot_client.list_authorizers(marker=response['nextMarker'])
                authorizer_list.extend(_ for _ in response['authorizers'])
            return authorizer_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def iot_role_alias_list(self) -> list[str]:
        rolealias_list: list[str] = []
        try:
            response = self.iot_client.list_role_aliases()
            for response_detail in response['roleAliases']:
                rolealias_list.append(f"arn:aws:iot:{self.session_region}:{self.session_account}:rolealias/{response_detail}")
            while 'nextMarker' in response:
                response = self.iot_client.list_role_aliases(marker=response['nextMarker'])
                for response_detail in response['roleAliases']:
                    rolealias_list.append(f"arn:aws:iot:{self.session_region}:{self.session_account}:rolealias/{response_detail}")
            return rolealias_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def iot_policy_list(self) -> list[dict]:
        policy_list: list[dict] = []
        try:
            response = self.iot_client.list_policies()
            policy_list.extend(_ for _ in response['policies'])
            while 'nextMarker' in response:
                response = self.iot_client.list_policies(marker=response['nextMarker'])
                policy_list.extend(_ for _ in response['policies'])
            return policy_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def iot_tag_compliant(self, iot_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.iot_client.list_tags_for_resource(resourceArn=iot_arn)
            tag_key_list = [tag['Key'] for tag in response['tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
    
    @DecoratorClass.my_decorator
    def iot_one(self) -> None:
        result_list = self.iot_security_profile_list()
        if not result_list:
            self.iot_list.append(self.create_iot_item(
                'IoT.1',
                'AWS IoT Core security profiles should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.iot_tag_compliant(response_detail['arn'])
            self.iot_list.append(self.create_iot_item(
                'IoT.1',
                'AWS IoT Core security profiles should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['arn']
            ))
    
    @DecoratorClass.my_decorator
    def iot_two(self) -> None:
        result_list = self.iot_mitigation_action_list()
        if not result_list:
            self.iot_list.append(self.create_iot_item(
                'IoT.2',
                'AWS IoT Core mitigation actions should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.iot_tag_compliant(response_detail['actionArn'])
            self.iot_list.append(self.create_iot_item(
                'IoT.2',
                'AWS IoT Core mitigation actions should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['actionArn']
            ))
    
    @DecoratorClass.my_decorator
    def iot_three(self) -> None:
        result_list = self.iot_dimension_list()
        if not result_list:
            self.iot_list.append(self.create_iot_item(
                'IoT.3',
                'AWS IoT Core dimensions should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.iot_tag_compliant(response_detail)
            self.iot_list.append(self.create_iot_item(
                'IoT.3',
                'AWS IoT Core dimensions should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail
            ))
    
    @DecoratorClass.my_decorator
    def iot_four(self) -> None:
        result_list = self.iot_authorizer_list()
        if not result_list:
            self.iot_list.append(self.create_iot_item(
                'IoT.4',
                'AWS IoT Core authorizers should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.iot_tag_compliant(response_detail['authorizerArn'])
            self.iot_list.append(self.create_iot_item(
                'IoT.4',
                'AWS IoT Core authorizers should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['authorizerArn']
            ))
    
    @DecoratorClass.my_decorator
    def iot_five(self) -> None:
        result_list = self.iot_role_alias_list()
        if not result_list:
            self.iot_list.append(self.create_iot_item(
                'IoT.5',
                'AWS IoT Core role aliases should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.iot_tag_compliant(response_detail)
            self.iot_list.append(self.create_iot_item(
                'IoT.5',
                'AWS IoT Core role aliases should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail
            ))
    
    @DecoratorClass.my_decorator
    def iot_six(self) -> None:
        result_list = self.iot_policy_list()
        if not result_list:
            self.iot_list.append(self.create_iot_item(
                'IoT.6',
                'AWS IoT Core policies should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.iot_tag_compliant(response_detail['policyArn'])
            self.iot_list.append(self.create_iot_item(
                'IoT.6',
                'AWS IoT Core policies should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['policyArn']
            ))

class CrossAccountIoTComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.iot_client = UseCrossAccount().client('iot')
        self.session_account = UseCrossAccount().client('sts').get_caller_identity()['Account']
        self.session_region = UseCrossAccount().session_region_name
        self.iot_list = compliance_check_list

    def create_iot_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("IoT", control_id, compliance, severity, auto_remediation):
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
    
    def iot_security_profile_list(self) -> list[dict]:
        securityprofile_list: list[dict] = []
        try:
            response = self.iot_client.list_security_profiles()
            securityprofile_list.extend(_ for _ in response['securityProfileIdentifiers'])
            while 'nextToken' in response:
                response = self.iot_client.list_security_profiles(NextToken=response['nextToken'])
                securityprofile_list.extend(_ for _ in response['securityProfileIdentifiers'])
            return securityprofile_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def iot_mitigation_action_list(self) -> list[dict]:
        mitigationaction_list: list[dict] = []
        try:
            response = self.iot_client.list_mitigation_actions()
            mitigationaction_list.extend(_ for _ in response['actionIdentifiers'])
            while 'nextToken' in response:
                response = self.iot_client.list_mitigation_actions(NextToken=response['nextToken'])
                mitigationaction_list.extend(_ for _ in response['actionIdentifiers'])
            return mitigationaction_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def iot_dimension_list(self) -> list[str]:
        dimension_list: list[str] = []
        try:
            response = self.iot_client.list_dimensions()
            for response_detail in response['dimensionNames']:
                dimension_list.append(f"arn:aws:iot:{self.session_region}:{self.session_account}:dimension/{response_detail}")
            while 'nextToken' in response:
                response = self.iot_client.list_dimensions(NextToken=response['nextToken'])
                for response_detail in response['dimensionNames']:
                    dimension_list.append(f"arn:aws:iot:{self.session_region}:{self.session_account}:dimension/{response_detail}")
            return dimension_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def iot_authorizer_list(self) -> list[dict]:
        authorizer_list: list[dict] = []
        try:
            response = self.iot_client.list_authorizers()
            authorizer_list.extend(_ for _ in response['authorizers'])
            while 'nextMarker' in response:
                response = self.iot_client.list_authorizers(marker=response['nextMarker'])
                authorizer_list.extend(_ for _ in response['authorizers'])
            return authorizer_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def iot_role_alias_list(self) -> list[str]:
        rolealias_list: list[str] = []
        try:
            response = self.iot_client.list_role_aliases()
            for response_detail in response['roleAliases']:
                rolealias_list.append(f"arn:aws:iot:{self.session_region}:{self.session_account}:rolealias/{response_detail}")
            while 'nextMarker' in response:
                response = self.iot_client.list_role_aliases(marker=response['nextMarker'])
                for response_detail in response['roleAliases']:
                    rolealias_list.append(f"arn:aws:iot:{self.session_region}:{self.session_account}:rolealias/{response_detail}")
            return rolealias_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def iot_policy_list(self) -> list[dict]:
        policy_list: list[dict] = []
        try:
            response = self.iot_client.list_policies()
            policy_list.extend(_ for _ in response['policies'])
            while 'nextMarker' in response:
                response = self.iot_client.list_policies(marker=response['nextMarker'])
                policy_list.extend(_ for _ in response['policies'])
            return policy_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def iot_tag_compliant(self, iot_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.iot_client.list_tags_for_resource(resourceArn=iot_arn)
            tag_key_list = [tag['Key'] for tag in response['tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
    
    @DecoratorClass.my_decorator
    def iot_one(self) -> None:
        result_list = self.iot_security_profile_list()
        if not result_list:
            self.iot_list.append(self.create_iot_item(
                'IoT.1',
                'AWS IoT Core security profiles should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.iot_tag_compliant(response_detail['arn'])
            self.iot_list.append(self.create_iot_item(
                'IoT.1',
                'AWS IoT Core security profiles should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['arn']
            ))
    
    @DecoratorClass.my_decorator
    def iot_two(self) -> None:
        result_list = self.iot_mitigation_action_list()
        if not result_list:
            self.iot_list.append(self.create_iot_item(
                'IoT.2',
                'AWS IoT Core mitigation actions should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.iot_tag_compliant(response_detail['actionArn'])
            self.iot_list.append(self.create_iot_item(
                'IoT.2',
                'AWS IoT Core mitigation actions should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['actionArn']
            ))
    
    @DecoratorClass.my_decorator
    def iot_three(self) -> None:
        result_list = self.iot_dimension_list()
        if not result_list:
            self.iot_list.append(self.create_iot_item(
                'IoT.3',
                'AWS IoT Core dimensions should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.iot_tag_compliant(response_detail)
            self.iot_list.append(self.create_iot_item(
                'IoT.3',
                'AWS IoT Core dimensions should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail
            ))
    
    @DecoratorClass.my_decorator
    def iot_four(self) -> None:
        result_list = self.iot_authorizer_list()
        if not result_list:
            self.iot_list.append(self.create_iot_item(
                'IoT.4',
                'AWS IoT Core authorizers should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.iot_tag_compliant(response_detail['authorizerArn'])
            self.iot_list.append(self.create_iot_item(
                'IoT.4',
                'AWS IoT Core authorizers should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['authorizerArn']
            ))
    
    @DecoratorClass.my_decorator
    def iot_five(self) -> None:
        result_list = self.iot_role_alias_list()
        if not result_list:
            self.iot_list.append(self.create_iot_item(
                'IoT.5',
                'AWS IoT Core role aliases should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.iot_tag_compliant(response_detail)
            self.iot_list.append(self.create_iot_item(
                'IoT.5',
                'AWS IoT Core role aliases should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail
            ))
    
    @DecoratorClass.my_decorator
    def iot_six(self) -> None:
        result_list = self.iot_policy_list()
        if not result_list:
            self.iot_list.append(self.create_iot_item(
                'IoT.6',
                'AWS IoT Core policies should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.iot_tag_compliant(response_detail['policyArn'])
            self.iot_list.append(self.create_iot_item(
                'IoT.6',
                'AWS IoT Core policies should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['policyArn']
            ))