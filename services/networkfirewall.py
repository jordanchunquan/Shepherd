'''
Class name NetworkFirewallComplianceChecker
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

class NetworkFirewallComplianceChecker:
    def __init__(self) -> None:
        self.networkfirewall_client = boto3.client('network-firewall')
        self.networkfirewall_list = compliance_check_list # type: ignore
        self.compliant_default_stateless_action = [ "aws:drop", "aws:forward_to_sfe" ]
        self.compliant_default_stateless_frag_action = [ "aws:drop", "aws:forward_to_sfe" ]
        self.require_tag_keys = ParameterValidation().require_tag_key()

    def create_networkfirewall_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("NetworkFirewall", control_id, compliance, severity, auto_remediation):
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
    
    def network_firewall_list(self) -> list[dict]:
        firewall_list: list[dict] = []
        try:
            response = self.networkfirewall_client.list_firewalls()
            firewall_list.extend(_ for _ in response['Firewalls'])
            if 'NextToken' in response:
                response = self.networkfirewall_client.list_firewalls(NextToken=response['NextToken'])
                firewall_list.extend(_ for _ in response['Firewalls'])
            return firewall_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def describe_firewall_list(self) -> list[dict]:
        result_list = self.network_firewall_list()
        firewall_list: list[dict] = []
        try:
            for response_detail in result_list:
                response = self.networkfirewall_client.describe_firewall(
                    FirewallName=response_detail['FirewallName'],
                    FirewallArn=response_detail['FirewallArn'])
                firewall_list.append(response)
            return firewall_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def firewall_logging_list(self) -> list[dict]:
        result_list = self.network_firewall_list()
        firewall_logging_list: list[dict] = []
        try:
            for response_detail in result_list:
                response = self.networkfirewall_client.describe_logging_configuration(
                    FirewallArn=response_detail['FirewallArn'],
                    FirewallName=response_detail['FirewallName'])
                firewall_logging_list.append(response)
            return firewall_logging_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def firewall_policy_list(self) -> list[dict]:
        result_list = self.network_firewall_list()
        firewall_policy_list: list[dict] = []
        try:
            for response_detail in result_list:
                response = self.networkfirewall_client.describe_firewall_policy(
                    FirewallPolicyName=response_detail['FirewallPolicyName'],
                    FirewallPolicyArn=response_detail['FirewallPolicyArn'])
                firewall_policy_list.append(response)
            return firewall_policy_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def firewall_tag_compliant(self, firewall_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.networkfirewall_client.list_tags_for_resource(ResourceARN=firewall_arn)
            tag_key_list = [_['Key'] for _ in response['TagList']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return "not_available"
    
    @DecoratorClass.my_decorator
    def networkfirewall_one(self) -> None:
        result_list = self.describe_firewall_list()
        if not result_list:
            self.networkfirewall_list.append(self.create_networkfirewall_item(
                'NetworkFirewall.1',
                'Network Firewall firewalls should be deployed across multiple Availability Zones',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if len(response_detail.get('FirewallStatus', {}).get('SyncStates', {})) < 2:
                self.networkfirewall_list.append(self.create_networkfirewall_item(
                    'NetworkFirewall.1',
                    'Network Firewall firewalls should be deployed across multiple Availability Zones',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['Firewall']['FirewallArn']
                ))
            else:
                self.networkfirewall_list.append(self.create_networkfirewall_item(
                    'NetworkFirewall.1',
                    'Network Firewall firewalls should be deployed across multiple Availability Zones',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['Firewall']['FirewallArn']
                ))

    @DecoratorClass.my_decorator
    def networkfirewall_two(self) -> None:
        result_list = self.firewall_logging_list()
        if not result_list:
            self.networkfirewall_list.append(self.create_networkfirewall_item(
                'NetworkFirewall.2',
                'Network Firewall logging should be enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if not response_detail.get('LoggingConfiguration', {}).get('LogDestinationConfigs'):
                self.networkfirewall_list.append(self.create_networkfirewall_item(
                    'NetworkFirewall.2',
                    'Network Firewall logging should be enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FirewallArn']
                ))
            else:
                self.networkfirewall_list.append(self.create_networkfirewall_item(
                    'NetworkFirewall.2',
                    'Network Firewall logging should be enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FirewallArn']
                ))

    @DecoratorClass.my_decorator
    def networkfirewall_three(self) -> None:
        result_list = self.firewall_policy_list()
        if not result_list:
            self.networkfirewall_list.append(self.create_networkfirewall_item(
                'NetworkFirewall.3',
                'Network Firewall policies should have at least one rule group associated',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if len(response_detail.get('FirewallPolicy', {})) < 1:
                if not response_detail.get('FirewallPolicy', {}).get('StatefulRuleGroupReferences', []) and response_detail.get('FirewallPolicy', {}).get('StatelessRuleGroupReferences', []):
                    self.networkfirewall_list.append(self.create_networkfirewall_item(
                        'NetworkFirewall.3',
                        'Network Firewall policies should have at least one rule group associated',
                        'failed',
                        'MEDIUM',
                        'not_available',
                        response_detail['FirewallPolicy']['FirewallPolicyArn']
                    ))
            else:
                self.networkfirewall_list.append(self.create_networkfirewall_item(
                    'NetworkFirewall.3',
                    'Network Firewall policies should have at least one rule group associated',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FirewallPolicy']['FirewallPolicyArn']
                ))

    @DecoratorClass.my_decorator
    def networkfirewall_four(self) -> None:
        result_list = self.firewall_policy_list()
        if not result_list:
            self.networkfirewall_list.append(self.create_networkfirewall_item(
                'NetworkFirewall.4',
                'The default stateless action for Network Firewall policies should be drop or forward for full packets',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if any([_ not in self.compliant_default_stateless_action for _ in response_detail.get('FirewallPolicy', {}).get('StatelessDefaultActions', [])]):
                self.networkfirewall_list.append(self.create_networkfirewall_item(
                    'NetworkFirewall.4',
                    'The default stateless action for Network Firewall policies should be drop or forward for full packets',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FirewallPolicy']['FirewallPolicyArn']
                ))
            else:
                self.networkfirewall_list.append(self.create_networkfirewall_item(
                    'NetworkFirewall.4',
                    'The default stateless action for Network Firewall policies should be drop or forward for full packets',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FirewallPolicy']['FirewallPolicyArn']
                ))

    @DecoratorClass.my_decorator
    def networkfirewall_five(self) -> None:
        result_list = self.firewall_policy_list()
        if not result_list:
            self.networkfirewall_list.append(self.create_networkfirewall_item(
                'NetworkFirewall.5',
                'The default stateless action for Network Firewall policies should be drop or forward for fragmented packets',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if any([_ not in self.compliant_default_stateless_action for _ in response_detail.get('FirewallPolicy', {}).get('StatelessFragmentDefaultActions', [])]):
                self.networkfirewall_list.append(self.create_networkfirewall_item(
                    'NetworkFirewall.5',
                    'The default stateless action for Network Firewall policies should be drop or forward for fragmented packets',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FirewallPolicy']['FirewallPolicyArn']
                ))
            else:
                self.networkfirewall_list.append(self.create_networkfirewall_item(
                    'NetworkFirewall.5',
                    'The default stateless action for Network Firewall policies should be drop or forward for fragmented packets',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FirewallPolicy']['FirewallPolicyArn']
                ))

    @DecoratorClass.my_decorator
    def networkfirewall_six(self) -> None:
        result_list = self.firewall_policy_list()
        if not result_list:
            self.networkfirewall_list.append(self.create_networkfirewall_item(
                'NetworkFirewall.6',
                'Stateless Network Firewall rule group should not be empty',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if not response_detail.get('FirewallPolicy', {}).get('StatelessRuleGroupReferences'):
                self.networkfirewall_list.append(self.create_networkfirewall_item(
                    'NetworkFirewall.6',
                    'Stateless Network Firewall rule group should not be empty',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FirewallPolicy']['FirewallPolicyArn']
                ))
            else:
                self.networkfirewall_list.append(self.create_networkfirewall_item(
                    'NetworkFirewall.6',
                    'Stateless Network Firewall rule group should not be empty',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FirewallPolicy']['FirewallPolicyArn']
                ))

    @DecoratorClass.my_decorator
    def networkfirewall_seven(self) -> None:
        result_list = self.network_firewall_list()
        if not result_list:
            self.networkfirewall_list.append(self.create_networkfirewall_item(
                'NetworkFirewall.7',
                'Network Firewall firewalls should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            complaint_status = self.firewall_tag_compliant(response_detail['FirewallArn'])
            self.networkfirewall_list.append(self.create_networkfirewall_item(
                'NetworkFirewall.7',
                'Network Firewall firewalls should be tagged',
                complaint_status,
                'LOW',
                'not_available',
                response_detail['FirewallArn']
            ))

    @DecoratorClass.my_decorator
    def networkfirewall_eight(self) -> None:
        result_list = self.firewall_policy_list()
        if not result_list:
            self.networkfirewall_list.append(self.create_networkfirewall_item(
                'NetworkFirewall.8',
                'Network Firewall firewall policies should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.firewall_tag_compliant(response_detail['FirewallPolicy']['FirewallPolicyArn'])
            self.networkfirewall_list.append(self.create_networkfirewall_item(
                'NetworkFirewall.8',
                'Network Firewall firewall policies should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['FirewallPolicy']['FirewallPolicyArn']
            ))

    @DecoratorClass.my_decorator
    def networkfirewall_nine(self) -> None:
        result_list = self.network_firewall_list()
        if not result_list:
            self.networkfirewall_list.append(self.create_networkfirewall_item(
                'NetworkFirewall.9',
                'Network Firewall firewalls should have deletion protection enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if not response_detail.get('DeleteProtection'):
                self.networkfirewall_list.append(self.create_networkfirewall_item(
                    'NetworkFirewall.9',
                    'Network Firewall firewalls should have deletion protection enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FirewallArn']
                ))
            else:
                self.networkfirewall_list.append(self.create_networkfirewall_item(
                    'NetworkFirewall.9',
                    'Network Firewall firewalls should have deletion protection enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FirewallArn']
                ))

class CrossAccountNetworkFirewallComplianceChecker:
    def __init__(self) -> None:
        self.networkfirewall_client = UseCrossAccount().client('network-firewall')
        self.networkfirewall_list = compliance_check_list # type: ignore
        self.compliant_default_stateless_action = [ "aws:drop", "aws:forward_to_sfe" ]
        self.compliant_default_stateless_frag_action = [ "aws:drop", "aws:forward_to_sfe" ]
        self.require_tag_keys = ParameterValidation().require_tag_key()

    def create_networkfirewall_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("NetworkFirewall", control_id, compliance, severity, auto_remediation):
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
    
    def network_firewall_list(self) -> list[dict]:
        firewall_list: list[dict] = []
        try:
            response = self.networkfirewall_client.list_firewalls()
            firewall_list.extend(_ for _ in response['Firewalls'])
            if 'NextToken' in response:
                response = self.networkfirewall_client.list_firewalls(NextToken=response['NextToken'])
                firewall_list.extend(_ for _ in response['Firewalls'])
            return firewall_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def describe_firewall_list(self) -> list[dict]:
        result_list = self.network_firewall_list()
        firewall_list: list[dict] = []
        try:
            for response_detail in result_list:
                response = self.networkfirewall_client.describe_firewall(
                    FirewallName=response_detail['FirewallName'],
                    FirewallArn=response_detail['FirewallArn'])
                firewall_list.append(response)
            return firewall_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def firewall_logging_list(self) -> list[dict]:
        result_list = self.network_firewall_list()
        firewall_logging_list: list[dict] = []
        try:
            for response_detail in result_list:
                response = self.networkfirewall_client.describe_logging_configuration(
                    FirewallArn=response_detail['FirewallArn'],
                    FirewallName=response_detail['FirewallName'])
                firewall_logging_list.append(response)
            return firewall_logging_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def firewall_policy_list(self) -> list[dict]:
        result_list = self.network_firewall_list()
        firewall_policy_list: list[dict] = []
        try:
            for response_detail in result_list:
                response = self.networkfirewall_client.describe_firewall_policy(
                    FirewallPolicyName=response_detail['FirewallPolicyName'],
                    FirewallPolicyArn=response_detail['FirewallPolicyArn'])
                firewall_policy_list.append(response)
            return firewall_policy_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def firewall_tag_compliant(self, firewall_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.networkfirewall_client.list_tags_for_resource(ResourceARN=firewall_arn)
            tag_key_list = [_['Key'] for _ in response['TagList']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return "not_available"
    
    @DecoratorClass.my_decorator
    def networkfirewall_one(self) -> None:
        result_list = self.describe_firewall_list()
        if not result_list:
            self.networkfirewall_list.append(self.create_networkfirewall_item(
                'NetworkFirewall.1',
                'Network Firewall firewalls should be deployed across multiple Availability Zones',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if len(response_detail.get('FirewallStatus', {}).get('SyncStates', {})) < 2:
                self.networkfirewall_list.append(self.create_networkfirewall_item(
                    'NetworkFirewall.1',
                    'Network Firewall firewalls should be deployed across multiple Availability Zones',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['Firewall']['FirewallArn']
                ))
            else:
                self.networkfirewall_list.append(self.create_networkfirewall_item(
                    'NetworkFirewall.1',
                    'Network Firewall firewalls should be deployed across multiple Availability Zones',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['Firewall']['FirewallArn']
                ))

    @DecoratorClass.my_decorator
    def networkfirewall_two(self) -> None:
        result_list = self.firewall_logging_list()
        if not result_list:
            self.networkfirewall_list.append(self.create_networkfirewall_item(
                'NetworkFirewall.2',
                'Network Firewall logging should be enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if not response_detail.get('LoggingConfiguration', {}).get('LogDestinationConfigs'):
                self.networkfirewall_list.append(self.create_networkfirewall_item(
                    'NetworkFirewall.2',
                    'Network Firewall logging should be enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FirewallArn']
                ))
            else:
                self.networkfirewall_list.append(self.create_networkfirewall_item(
                    'NetworkFirewall.2',
                    'Network Firewall logging should be enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FirewallArn']
                ))

    @DecoratorClass.my_decorator
    def networkfirewall_three(self) -> None:
        result_list = self.firewall_policy_list()
        if not result_list:
            self.networkfirewall_list.append(self.create_networkfirewall_item(
                'NetworkFirewall.3',
                'Network Firewall policies should have at least one rule group associated',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if len(response_detail.get('FirewallPolicy', {})) < 1:
                if not response_detail.get('FirewallPolicy', {}).get('StatefulRuleGroupReferences', []) and response_detail.get('FirewallPolicy', {}).get('StatelessRuleGroupReferences', []):
                    self.networkfirewall_list.append(self.create_networkfirewall_item(
                        'NetworkFirewall.3',
                        'Network Firewall policies should have at least one rule group associated',
                        'failed',
                        'MEDIUM',
                        'not_available',
                        response_detail['FirewallPolicy']['FirewallPolicyArn']
                    ))
            else:
                self.networkfirewall_list.append(self.create_networkfirewall_item(
                    'NetworkFirewall.3',
                    'Network Firewall policies should have at least one rule group associated',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FirewallPolicy']['FirewallPolicyArn']
                ))

    @DecoratorClass.my_decorator
    def networkfirewall_four(self) -> None:
        result_list = self.firewall_policy_list()
        if not result_list:
            self.networkfirewall_list.append(self.create_networkfirewall_item(
                'NetworkFirewall.4',
                'The default stateless action for Network Firewall policies should be drop or forward for full packets',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if any([_ not in self.compliant_default_stateless_action for _ in response_detail.get('FirewallPolicy', {}).get('StatelessDefaultActions', [])]):
                self.networkfirewall_list.append(self.create_networkfirewall_item(
                    'NetworkFirewall.4',
                    'The default stateless action for Network Firewall policies should be drop or forward for full packets',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FirewallPolicy']['FirewallPolicyArn']
                ))
            else:
                self.networkfirewall_list.append(self.create_networkfirewall_item(
                    'NetworkFirewall.4',
                    'The default stateless action for Network Firewall policies should be drop or forward for full packets',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FirewallPolicy']['FirewallPolicyArn']
                ))

    @DecoratorClass.my_decorator
    def networkfirewall_five(self) -> None:
        result_list = self.firewall_policy_list()
        if not result_list:
            self.networkfirewall_list.append(self.create_networkfirewall_item(
                'NetworkFirewall.5',
                'The default stateless action for Network Firewall policies should be drop or forward for fragmented packets',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if any([_ not in self.compliant_default_stateless_action for _ in response_detail.get('FirewallPolicy', {}).get('StatelessFragmentDefaultActions', [])]):
                self.networkfirewall_list.append(self.create_networkfirewall_item(
                    'NetworkFirewall.5',
                    'The default stateless action for Network Firewall policies should be drop or forward for fragmented packets',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FirewallPolicy']['FirewallPolicyArn']
                ))
            else:
                self.networkfirewall_list.append(self.create_networkfirewall_item(
                    'NetworkFirewall.5',
                    'The default stateless action for Network Firewall policies should be drop or forward for fragmented packets',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FirewallPolicy']['FirewallPolicyArn']
                ))

    @DecoratorClass.my_decorator
    def networkfirewall_six(self) -> None:
        result_list = self.firewall_policy_list()
        if not result_list:
            self.networkfirewall_list.append(self.create_networkfirewall_item(
                'NetworkFirewall.6',
                'Stateless Network Firewall rule group should not be empty',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if not response_detail.get('FirewallPolicy', {}).get('StatelessRuleGroupReferences'):
                self.networkfirewall_list.append(self.create_networkfirewall_item(
                    'NetworkFirewall.6',
                    'Stateless Network Firewall rule group should not be empty',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FirewallPolicy']['FirewallPolicyArn']
                ))
            else:
                self.networkfirewall_list.append(self.create_networkfirewall_item(
                    'NetworkFirewall.6',
                    'Stateless Network Firewall rule group should not be empty',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FirewallPolicy']['FirewallPolicyArn']
                ))

    @DecoratorClass.my_decorator
    def networkfirewall_seven(self) -> None:
        result_list = self.network_firewall_list()
        if not result_list:
            self.networkfirewall_list.append(self.create_networkfirewall_item(
                'NetworkFirewall.7',
                'Network Firewall firewalls should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            complaint_status = self.firewall_tag_compliant(response_detail['FirewallArn'])
            self.networkfirewall_list.append(self.create_networkfirewall_item(
                'NetworkFirewall.7',
                'Network Firewall firewalls should be tagged',
                complaint_status,
                'LOW',
                'not_available',
                response_detail['FirewallArn']
            ))

    @DecoratorClass.my_decorator
    def networkfirewall_eight(self) -> None:
        result_list = self.firewall_policy_list()
        if not result_list:
            self.networkfirewall_list.append(self.create_networkfirewall_item(
                'NetworkFirewall.8',
                'Network Firewall firewall policies should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.firewall_tag_compliant(response_detail['FirewallPolicy']['FirewallPolicyArn'])
            self.networkfirewall_list.append(self.create_networkfirewall_item(
                'NetworkFirewall.8',
                'Network Firewall firewall policies should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['FirewallPolicy']['FirewallPolicyArn']
            ))

    @DecoratorClass.my_decorator
    def networkfirewall_nine(self) -> None:
        result_list = self.network_firewall_list()
        if not result_list:
            self.networkfirewall_list.append(self.create_networkfirewall_item(
                'NetworkFirewall.9',
                'Network Firewall firewalls should have deletion protection enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if not response_detail.get('DeleteProtection'):
                self.networkfirewall_list.append(self.create_networkfirewall_item(
                    'NetworkFirewall.9',
                    'Network Firewall firewalls should have deletion protection enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FirewallArn']
                ))
            else:
                self.networkfirewall_list.append(self.create_networkfirewall_item(
                    'NetworkFirewall.9',
                    'Network Firewall firewalls should have deletion protection enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['FirewallArn']
                ))