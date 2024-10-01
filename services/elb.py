'''
Class name ELBComplianceChecker
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

class ELBComplianceChecker:
    def __init__(self) -> None:
        self.elb_client = boto3.client('elb')
        self.elbv2_client = boto3.client('elbv2')
        self.acm_client = boto3.client('acm')
        self.waf_client = boto3.client('waf-regional')
        self.wafv2_client = boto3.client('wafv2')
        self.elb_list = compliance_check_list
        self.aws_predifined_security_policy = "ELBSecurityPolicy-TLS-1-2-2017-01"

    def create_elb_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("ELB", control_id, compliance, severity, auto_remediation):
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
    
    def describe_load_balancer_v2_list(self) -> list[dict]:
        load_balancer_list: list[dict] = []
        try:
            response = self.elbv2_client.describe_load_balancers()
            load_balancer_list.extend(_ for _ in response['LoadBalancers'])
            while 'NextMarker' in response:
                response = self.elbv2_client.describe_load_balancers(Marker=response['NextMarker'])
                load_balancer_list.extend(_ for _ in response['LoadBalancers'])
            return load_balancer_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def describe_application_load_balancer_list(self) -> list[dict]:
        result_list = self.describe_load_balancer_v2_list()
        application_load_balancer_list = [_ for _ in result_list if _['Type'] == 'application']
        return application_load_balancer_list
        
    def describe_load_balancer_list(self) -> list[dict]:
        load_balancer_list: list[dict] = []
        try:
            response = self.elb_client.describe_load_balancers()
            load_balancer_list.extend(_ for _ in response['LoadBalancerDescriptions'])
            while 'NextMarker' in response:
                response = self.elb_client.describe_load_balancers(Marker=response['NextMarker'])
                load_balancer_list.extend(_ for _ in response['LoadBalancerDescriptions'])
            return load_balancer_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def load_balancer_v2_listener(self, elb_v2_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.elbv2_client.describe_listeners(LoadBalancerArn=elb_v2_arn)
            for listener in response['Listeners']:
                if listener['Port'] == 80:
                    if listener['Protocol'] == 'HTTP':
                        rule_list: list[dict] = []
                        rule_response = self.elbv2_client.describe_rules(ListenerArn=listener['ListenerArn'])
                        rule_list.extend(_ for _ in rule_response['Rules'])
                        while 'NextMarker' in rule_response:
                            rule_response = self.elbv2_client.describe_rules(ListenerArn=listener['ListenerArn'], Marker=rule_response['NextMarker'])
                            rule_list.extend(_ for _ in rule_response['Rules'])
                        if not any([_['RedirectConfig']['Protocol'] == 'HTTPS' for _ in rule_list['Actions'] if _['Type'] == 'redirect']): # type: ignore
                            compliant_status = "failed"
                        elif not any([_['Type'] == 'redirect' for _ in rule_list]):
                            compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""

    def acm_certificate_list(self) -> list[dict]:
        certificate_list: list[dict] = []
        try:
            response = self.acm_client.list_certificates()
            for response_detail in response['CertificateSummaryList']:
                certificate_list.append(response_detail['CertificateArn'])
            while 'NextToken' in response:
                response = self.acm_client.list_certificates(NextToken=response['NextToken'])
                for response_detail in response['CertificateSummaryList']:
                    certificate_list.append(response_detail['CertificateArn'])
            return certificate_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def drop_http_header_compliant(self, elb_v2_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.elbv2_client.describe_load_balancer_attributes(LoadBalancerArn=elb_v2_arn)
            for response_detail in response['Attributes']:
                if response_detail['Key'] == "drop_invalid_header_fields.enabled" and response_detail['Value'] == "false":
                    compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        
    def elbv2_access_log_compliant(self, elb_v2_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.elbv2_client.describe_load_balancer_attributes(LoadBalancerArn=elb_v2_arn)
            for response_detail in response['Attributes']:
                if response_detail['Key'] == "access_logs.s3.enabled" and response_detail['Value'] == "false":
                    compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        
    def elb_access_log_compliant(self, elb_name: str) -> str:
        try:
            compliant_status = "passed"
            response = self.elb_client.describe_load_balancer_attributes(LoadBalancerName=elb_name)
            for response_detail in response['LoadBalancerAttributes']:
                if response_detail['AccessLog']['Enabled'] == False:
                    compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        
    def elbv2_deletion_proctetion_compliant(self, elb_v2_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.elbv2_client.describe_load_balancer_attributes(LoadBalancerArn=elb_v2_arn)
            for response_detail in response['Attributes']:
                if response_detail['Key'] == "deletion_protection.enabled" and response_detail['Value'] == "false":
                    compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        
    def elb_connection_draining_compliant(self, elb_name: str) -> str:
        try:
            compliant_status = "passed"
            response = self.elb_client.describe_load_balancer_attributes(LoadBalancerName=elb_name)
            for response_detail in response['LoadBalancerAttributes']:
                if response_detail['ConnectionDraining']['Enabled'] == False:
                    compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        
    def elb_cross_zone_load_balancing_compliant(self, elb_name: str) -> str:
        try:
            compliant_status = "passed"
            response = self.elb_client.describe_load_balancer_attributes(LoadBalancerName=elb_name)
            for response_detail in response['LoadBalancerAttributes']:
                if response_detail['CrossZoneLoadBalancing']['Enabled'] == False:
                    compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        
    def routing_http_desync_mitigation_mode_compliant(self, elb_v2_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.elbv2_client.describe_load_balancer_attributes(LoadBalancerArn=elb_v2_arn)
            for response_detail in response['Attributes']:
                if response_detail['Key'] == "routing.http.desync_mitigation_mode" and response_detail['Value'] not in ["defensive", "strictest"]:
                    compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        
    def elb_http_desync_mitigation_mode_compliant(self, elb_name: str) -> str:
        try:
            compliant_status = "passed"
            response = self.elb_client.describe_load_balancer_attributes(LoadBalancerName=elb_name)
            for response_detail in response['LoadBalancerAttributes']:
                for additional_detail in response_detail['AdditionalAttributes']:
                    if additional_detail['Key'] == "HttpDesyncMitigationMode" and additional_detail['Value'] not in ["defensive", "strictest"]:
                        compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        
    def waf_compliant(self, elb_v2_arn: str) -> str:
        try:
            compliant_status = "passed"
            self.waf_client.get_web_acl_for_resource(ResourceArn=elb_v2_arn)
        except ClientError as e:
            if ClientError.response['Error']['Code'] == 'WAFNonexistentItemException':
                compliant_status = "failed"
            else:
                print(f"Error: {e}")
                return ""
        return compliant_status

    def waf_v2_compliant(self, elb_v2_arn: str) -> str:
        try:
            compliant_status = "passed"
            self.wafv2_client.get_web_acl_for_resource(ResourceArn=elb_v2_arn)
        except ClientError as e:
            if ClientError.response['Error']['Code'] == 'WAFNonexistentItemException':
                compliant_status = "failed"
            else:
                print(f"Error: {e}")
                return ""
        return compliant_status
    
    @DecoratorClass.my_decorator
    def elb_one(self) -> None:
        result_list = self.describe_application_load_balancer_list()
        if not result_list:
            self.elb_list.append(self.create_elb_item(
                'ELB.1',
                'Application Load Balancer should be configured to redirect all HTTP requests to HTTPS',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.load_balancer_v2_listener(response_detail['LoadBalancerArn'])
            self.elb_list.append(self.create_elb_item(
                'ELB.1',
                'Application Load Balancer should be configured to redirect all HTTP requests to HTTPS',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['LoadBalancerArn']
            ))

    @DecoratorClass.my_decorator
    def elb_two(self) -> None:
        result_list = self.describe_load_balancer_list()
        certificate_list = self.acm_certificate_list()
        if not result_list:
            self.elb_list.append(self.create_elb_item(
                'ELB.2',
                'Classic Load Balancers with SSL/HTTPS listeners should use a certificate provided by AWS Certificate Manager',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if response_detail['ListenerDescriptions']:
                for listener in response_detail['ListenerDescriptions']:
                    if listener['Listener']['Protocol'] in ['HTTPS', 'SSL'] and \
                        listener['Listener']['SSLCertificateId'] not in certificate_list:
                        compliant_status = "failed"
            self.elb_list.append(self.create_elb_item(
                'ELB.2',
                'Classic Load Balancers with SSL/HTTPS listeners should use a certificate provided by AWS Certificate Manager',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['LoadBalancerName']
            ))

    @DecoratorClass.my_decorator
    def elb_three(self) -> None:
        result_list = self.describe_load_balancer_list()
        if not result_list:
            self.elb_list.append(self.create_elb_item(
                'ELB.3',
                'Classic Load Balancer listeners should be configured with HTTPS or TLS termination',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if response_detail['ListenerDescriptions']:
                for listener in response_detail['ListenerDescriptions']:
                    if listener['Listener']['Protocol'] not in ['HTTPS', 'SSL']:
                        compliant_status = "failed"
            self.elb_list.append(self.create_elb_item(
                'ELB.3',
                'Classic Load Balancer listeners should be configured with HTTPS or TLS termination',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['LoadBalancerName']
            ))
    
    @DecoratorClass.my_decorator
    def elb_four(self) -> None:
        result_list = self.describe_application_load_balancer_list()
        if not result_list:
            self.elb_list.append(self.create_elb_item(
                'ELB.4',
                'Application Load Balancer should be configured to drop http headers',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.drop_http_header_compliant(response_detail['LoadBalancerArn'])
            self.elb_list.append(self.create_elb_item(
                'ELB.4',
                'Application Load Balancer should be configured to drop http headers',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['LoadBalancerArn']
            ))
    
    @DecoratorClass.my_decorator
    def elb_five(self) -> None:
        result_list = self.describe_load_balancer_list()
        application_lb_result_list = self.describe_application_load_balancer_list()
        if not result_list and not application_lb_result_list:
            self.elb_list.append(self.create_elb_item(
                'ELB.5',
                'Application and Classic Load Balancers logging should be enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.elb_access_log_compliant(response_detail['LoadBalancerName'])
            self.elb_list.append(self.create_elb_item(
                'ELB.5',
                'Application and Classic Load Balancers logging should be enabled',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['LoadBalancerName']
            ))
        for response_detail in application_lb_result_list:
            compliant_status = self.elbv2_access_log_compliant(response_detail['LoadBalancerArn'])
            self.elb_list.append(self.create_elb_item(
                'ELB.5',
                'Application and Classic Load Balancers logging should be enabled',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['LoadBalancerArn']
            ))
    
    @DecoratorClass.my_decorator
    def elb_six(self) -> None:
        result_list = self.describe_load_balancer_v2_list()
        if not result_list:
            self.elb_list.append(self.create_elb_item(
                'ELB.6',
                'Application, Gateway, and Network Load Balancers should have deletion protection enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.elbv2_deletion_proctetion_compliant(response_detail['LoadBalancerArn'])
            self.elb_list.append(self.create_elb_item(
                'ELB.6',
                'Application, Gateway, and Network Load Balancers should have deletion protection enabled',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['LoadBalancerArn']
            ))
    
    @DecoratorClass.my_decorator
    def elb_seven(self) -> None:
        result_list = self.describe_load_balancer_list()
        if not result_list:
            self.elb_list.append(self.create_elb_item(
                'ELB.7',
                'Classic Load Balancers should have connection draining enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.elb_connection_draining_compliant(response_detail['LoadBalancerName'])
            self.elb_list.append(self.create_elb_item(
                'ELB.7',
                'Classic Load Balancers should have connection draining enabled',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['LoadBalancerName']
            ))
    
    @DecoratorClass.my_decorator
    def elb_eight(self) -> None:
        result_list = self.describe_load_balancer_list()
        if not result_list:
            self.elb_list.append(self.create_elb_item(
                'ELB.8',
                'Classic Load Balancers with SSL listeners should use a predefined security policy that has strong AWS Configuration',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if response_detail['ListenerDescriptions']:
                for listener in response_detail['ListenerDescriptions']:
                    if listener['Listener']['Protocol'] in ['HTTPS', 'SSL'] and self.aws_predifined_security_policy not in listener['Listener']['PolicyNames']:
                        compliant_status = "failed"
            self.elb_list.append(self.create_elb_item(
                'ELB.8',
                'Classic Load Balancers with SSL listeners should use a predefined security policy that has strong AWS Configuration',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['LoadBalancerName']
            ))
    
    @DecoratorClass.my_decorator
    def elb_nine(self) -> None:
        result_list = self.describe_load_balancer_list()
        if not result_list:
            self.elb_list.append(self.create_elb_item(
                'ELB.9',
                'Classic Load Balancers should have cross-zone load balancing enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.elb_cross_zone_load_balancing_compliant(response_detail['LoadBalancerName'])
            self.elb_list.append(self.create_elb_item(
                'ELB.9',
                'Classic Load Balancers should have cross-zone load balancing enabled',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['LoadBalancerName']
            ))
    
    @DecoratorClass.my_decorator
    def elb_ten(self) -> None:
        result_list = self.describe_load_balancer_list()
        if not result_list:
            self.elb_list.append(self.create_elb_item(
                'ELB.10',
                'Classic Load Balancer should span multiple Availability Zones',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if len(response_detail['AvailabilityZones']) < 2:
                self.elb_list.append(self.create_elb_item(
                    'ELB.10',
                    'Classic Load Balancer should span multiple Availability Zones',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['LoadBalancerName']
                ))
            else:
                self.elb_list.append(self.create_elb_item(
                    'ELB.10',
                    'Classic Load Balancer should span multiple Availability Zones',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['LoadBalancerName']
                ))
    
    @DecoratorClass.my_decorator
    def elb_twelve(self) -> None:
        result_list = self.describe_application_load_balancer_list()
        if not result_list:
            self.elb_list.append(self.create_elb_item(
                'ELB.12',
                'Application Load Balancer should be configured with defensive or strictest desync mitigation mode',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.routing_http_desync_mitigation_mode_compliant(response_detail['LoadBalancerArn'])
            self.elb_list.append(self.create_elb_item(
                'ELB.12',
                'Application Load Balancer should be configured with defensive or strictest desync mitigation mode',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['LoadBalancerArn']
            ))
    
    @DecoratorClass.my_decorator
    def elb_thirteen(self) -> None:
        result_list = self.describe_load_balancer_v2_list()
        if not result_list:
            self.elb_list.append(self.create_elb_item(
                'ELB.13',
                'Application, Network and Gateway Load Balancers should span multiple Availability Zones',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if len(response_detail['AvailabilityZones']) < 2:
                self.elb_list.append(self.create_elb_item(
                    'ELB.13',
                    'Application, Network and Gateway Load Balancers should span multiple Availability Zones',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['LoadBalancerArn']
                ))
            else:
                self.elb_list.append(self.create_elb_item(
                    'ELB.13',
                    'Application, Network and Gateway Load Balancers should span multiple Availability Zones',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['LoadBalancerArn']
                ))
    
    @DecoratorClass.my_decorator
    def elb_fourteen(self) -> None:
        result_list = self.describe_load_balancer_list()
        if not result_list:
            self.elb_list.append(self.create_elb_item(
                'ELB.14',
                'Classic Load Balancer should be configured with defensive or strictest desync mitigation mode',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.elb_http_desync_mitigation_mode_compliant(response_detail['LoadBalancerName'])
            self.elb_list.append(self.create_elb_item(
                'ELB.14',
                'Classic Load Balancer should be configured with defensive or strictest desync mitigation mode',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['LoadBalancerName']
            ))
    
    @DecoratorClass.my_decorator
    def elb_sixteen(self) -> None:
        result_list = self.describe_application_load_balancer_list()
        if not result_list:
            self.elb_list.append(self.create_elb_item(
                'ELB.16',
                'Application Load Balancers should be associated with an AWS WAF web ACL',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            classic_waf_compliant_status = self.waf_compliant(response_detail['LoadBalancerArn'])
            waf_compliant_status = self.waf_v2_compliant(response_detail['LoadBalancerArn'])
            if all([classic_waf_compliant_status == "failed", waf_compliant_status == "failed"]):
                compliant_status = "failed"
            self.elb_list.append(self.create_elb_item(
                'ELB.16',
                'Application Load Balancers should be associated with an AWS WAF web ACL',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['LoadBalancerArn']
            ))
    
class CrossAccountELBComplianceChecker:
    def __init__(self) -> None:
        self.elb_client = UseCrossAccount().client('elb')
        self.elbv2_client = UseCrossAccount().client('elbv2')
        self.acm_client = UseCrossAccount().client('acm')
        self.waf_client = UseCrossAccount().client('waf-regional')
        self.wafv2_client = UseCrossAccount().client('wafv2')
        self.elb_list = compliance_check_list
        self.aws_predifined_security_policy = "ELBSecurityPolicy-TLS-1-2-2017-01"

    def create_elb_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("ELB", control_id, compliance, severity, auto_remediation):
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
    
    def describe_load_balancer_v2_list(self) -> list[dict]:
        load_balancer_list: list[dict] = []
        try:
            response = self.elbv2_client.describe_load_balancers()
            load_balancer_list.extend(_ for _ in response['LoadBalancers'])
            while 'NextMarker' in response:
                response = self.elbv2_client.describe_load_balancers(Marker=response['NextMarker'])
                load_balancer_list.extend(_ for _ in response['LoadBalancers'])
            return load_balancer_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def describe_application_load_balancer_list(self) -> list[dict]:
        result_list = self.describe_load_balancer_v2_list()
        application_load_balancer_list = [_ for _ in result_list if _['Type'] == 'application']
        return application_load_balancer_list
        
    def describe_load_balancer_list(self) -> list[dict]:
        load_balancer_list: list[dict] = []
        try:
            response = self.elb_client.describe_load_balancers()
            load_balancer_list.extend(_ for _ in response['LoadBalancerDescriptions'])
            while 'NextMarker' in response:
                response = self.elb_client.describe_load_balancers(Marker=response['NextMarker'])
                load_balancer_list.extend(_ for _ in response['LoadBalancerDescriptions'])
            return load_balancer_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def load_balancer_v2_listener(self, elb_v2_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.elbv2_client.describe_listeners(LoadBalancerArn=elb_v2_arn)
            for listener in response['Listeners']:
                if listener['Port'] == 80:
                    if listener['Protocol'] == 'HTTP':
                        rule_list: list[dict] = []
                        rule_response = self.elbv2_client.describe_rules(ListenerArn=listener['ListenerArn'])
                        rule_list.extend(_ for _ in rule_response['Rules'])
                        while 'NextMarker' in rule_response:
                            rule_response = self.elbv2_client.describe_rules(ListenerArn=listener['ListenerArn'], Marker=rule_response['NextMarker'])
                            rule_list.extend(_ for _ in rule_response['Rules'])
                        if not any([_['RedirectConfig']['Protocol'] == 'HTTPS' for _ in rule_list['Actions'] if _['Type'] == 'redirect']): # type: ignore
                            compliant_status = "failed"
                        elif not any([_['Type'] == 'redirect' for _ in rule_list]):
                            compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""

    def acm_certificate_list(self) -> list[dict]:
        certificate_list: list[dict] = []
        try:
            response = self.acm_client.list_certificates()
            for response_detail in response['CertificateSummaryList']:
                certificate_list.append(response_detail['CertificateArn'])
            while 'NextToken' in response:
                response = self.acm_client.list_certificates(NextToken=response['NextToken'])
                for response_detail in response['CertificateSummaryList']:
                    certificate_list.append(response_detail['CertificateArn'])
            return certificate_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def drop_http_header_compliant(self, elb_v2_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.elbv2_client.describe_load_balancer_attributes(LoadBalancerArn=elb_v2_arn)
            for response_detail in response['Attributes']:
                if response_detail['Key'] == "drop_invalid_header_fields.enabled" and response_detail['Value'] == "false":
                    compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        
    def elbv2_access_log_compliant(self, elb_v2_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.elbv2_client.describe_load_balancer_attributes(LoadBalancerArn=elb_v2_arn)
            for response_detail in response['Attributes']:
                if response_detail['Key'] == "access_logs.s3.enabled" and response_detail['Value'] == "false":
                    compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        
    def elb_access_log_compliant(self, elb_name: str) -> str:
        try:
            compliant_status = "passed"
            response = self.elb_client.describe_load_balancer_attributes(LoadBalancerName=elb_name)
            for response_detail in response['LoadBalancerAttributes']:
                if response_detail['AccessLog']['Enabled'] == False:
                    compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        
    def elbv2_deletion_proctetion_compliant(self, elb_v2_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.elbv2_client.describe_load_balancer_attributes(LoadBalancerArn=elb_v2_arn)
            for response_detail in response['Attributes']:
                if response_detail['Key'] == "deletion_protection.enabled" and response_detail['Value'] == "false":
                    compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        
    def elb_connection_draining_compliant(self, elb_name: str) -> str:
        try:
            compliant_status = "passed"
            response = self.elb_client.describe_load_balancer_attributes(LoadBalancerName=elb_name)
            for response_detail in response['LoadBalancerAttributes']:
                if response_detail['ConnectionDraining']['Enabled'] == False:
                    compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        
    def elb_cross_zone_load_balancing_compliant(self, elb_name: str) -> str:
        try:
            compliant_status = "passed"
            response = self.elb_client.describe_load_balancer_attributes(LoadBalancerName=elb_name)
            for response_detail in response['LoadBalancerAttributes']:
                if response_detail['CrossZoneLoadBalancing']['Enabled'] == False:
                    compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        
    def routing_http_desync_mitigation_mode_compliant(self, elb_v2_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.elbv2_client.describe_load_balancer_attributes(LoadBalancerArn=elb_v2_arn)
            for response_detail in response['Attributes']:
                if response_detail['Key'] == "routing.http.desync_mitigation_mode" and response_detail['Value'] not in ["defensive", "strictest"]:
                    compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        
    def elb_http_desync_mitigation_mode_compliant(self, elb_name: str) -> str:
        try:
            compliant_status = "passed"
            response = self.elb_client.describe_load_balancer_attributes(LoadBalancerName=elb_name)
            for response_detail in response['LoadBalancerAttributes']:
                for additional_detail in response_detail['AdditionalAttributes']:
                    if additional_detail['Key'] == "HttpDesyncMitigationMode" and additional_detail['Value'] not in ["defensive", "strictest"]:
                        compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
        
    def waf_compliant(self, elb_v2_arn: str) -> str:
        try:
            compliant_status = "passed"
            self.waf_client.get_web_acl_for_resource(ResourceArn=elb_v2_arn)
        except ClientError as e:
            if ClientError.response['Error']['Code'] == 'WAFNonexistentItemException':
                compliant_status = "failed"
            else:
                print(f"Error: {e}")
                return ""
        return compliant_status

    def waf_v2_compliant(self, elb_v2_arn: str) -> str:
        try:
            compliant_status = "passed"
            self.wafv2_client.get_web_acl_for_resource(ResourceArn=elb_v2_arn)
        except ClientError as e:
            if ClientError.response['Error']['Code'] == 'WAFNonexistentItemException':
                compliant_status = "failed"
            else:
                print(f"Error: {e}")
                return ""
        return compliant_status
    
    @DecoratorClass.my_decorator
    def elb_one(self) -> None:
        result_list = self.describe_application_load_balancer_list()
        if not result_list:
            self.elb_list.append(self.create_elb_item(
                'ELB.1',
                'Application Load Balancer should be configured to redirect all HTTP requests to HTTPS',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.load_balancer_v2_listener(response_detail['LoadBalancerArn'])
            self.elb_list.append(self.create_elb_item(
                'ELB.1',
                'Application Load Balancer should be configured to redirect all HTTP requests to HTTPS',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['LoadBalancerArn']
            ))

    @DecoratorClass.my_decorator
    def elb_two(self) -> None:
        result_list = self.describe_load_balancer_list()
        certificate_list = self.acm_certificate_list()
        if not result_list:
            self.elb_list.append(self.create_elb_item(
                'ELB.2',
                'Classic Load Balancers with SSL/HTTPS listeners should use a certificate provided by AWS Certificate Manager',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if response_detail['ListenerDescriptions']:
                for listener in response_detail['ListenerDescriptions']:
                    if listener['Listener']['Protocol'] in ['HTTPS', 'SSL'] and \
                        listener['Listener']['SSLCertificateId'] not in certificate_list:
                        compliant_status = "failed"
            self.elb_list.append(self.create_elb_item(
                'ELB.2',
                'Classic Load Balancers with SSL/HTTPS listeners should use a certificate provided by AWS Certificate Manager',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['LoadBalancerName']
            ))

    @DecoratorClass.my_decorator
    def elb_three(self) -> None:
        result_list = self.describe_load_balancer_list()
        if not result_list:
            self.elb_list.append(self.create_elb_item(
                'ELB.3',
                'Classic Load Balancer listeners should be configured with HTTPS or TLS termination',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if response_detail['ListenerDescriptions']:
                for listener in response_detail['ListenerDescriptions']:
                    if listener['Listener']['Protocol'] not in ['HTTPS', 'SSL']:
                        compliant_status = "failed"
            self.elb_list.append(self.create_elb_item(
                'ELB.3',
                'Classic Load Balancer listeners should be configured with HTTPS or TLS termination',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['LoadBalancerName']
            ))
    
    @DecoratorClass.my_decorator
    def elb_four(self) -> None:
        result_list = self.describe_application_load_balancer_list()
        if not result_list:
            self.elb_list.append(self.create_elb_item(
                'ELB.4',
                'Application Load Balancer should be configured to drop http headers',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.drop_http_header_compliant(response_detail['LoadBalancerArn'])
            self.elb_list.append(self.create_elb_item(
                'ELB.4',
                'Application Load Balancer should be configured to drop http headers',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['LoadBalancerArn']
            ))
    
    @DecoratorClass.my_decorator
    def elb_five(self) -> None:
        result_list = self.describe_load_balancer_list()
        application_lb_result_list = self.describe_application_load_balancer_list()
        if not result_list and not application_lb_result_list:
            self.elb_list.append(self.create_elb_item(
                'ELB.5',
                'Application and Classic Load Balancers logging should be enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.elb_access_log_compliant(response_detail['LoadBalancerName'])
            self.elb_list.append(self.create_elb_item(
                'ELB.5',
                'Application and Classic Load Balancers logging should be enabled',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['LoadBalancerName']
            ))
        for response_detail in application_lb_result_list:
            compliant_status = self.elbv2_access_log_compliant(response_detail['LoadBalancerArn'])
            self.elb_list.append(self.create_elb_item(
                'ELB.5',
                'Application and Classic Load Balancers logging should be enabled',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['LoadBalancerArn']
            ))
    
    @DecoratorClass.my_decorator
    def elb_six(self) -> None:
        result_list = self.describe_load_balancer_v2_list()
        if not result_list:
            self.elb_list.append(self.create_elb_item(
                'ELB.6',
                'Application, Gateway, and Network Load Balancers should have deletion protection enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.elbv2_deletion_proctetion_compliant(response_detail['LoadBalancerArn'])
            self.elb_list.append(self.create_elb_item(
                'ELB.6',
                'Application, Gateway, and Network Load Balancers should have deletion protection enabled',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['LoadBalancerArn']
            ))
    
    @DecoratorClass.my_decorator
    def elb_seven(self) -> None:
        result_list = self.describe_load_balancer_list()
        if not result_list:
            self.elb_list.append(self.create_elb_item(
                'ELB.7',
                'Classic Load Balancers should have connection draining enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.elb_connection_draining_compliant(response_detail['LoadBalancerName'])
            self.elb_list.append(self.create_elb_item(
                'ELB.7',
                'Classic Load Balancers should have connection draining enabled',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['LoadBalancerName']
            ))
    
    @DecoratorClass.my_decorator
    def elb_eight(self) -> None:
        result_list = self.describe_load_balancer_list()
        if not result_list:
            self.elb_list.append(self.create_elb_item(
                'ELB.8',
                'Classic Load Balancers with SSL listeners should use a predefined security policy that has strong AWS Configuration',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if response_detail['ListenerDescriptions']:
                for listener in response_detail['ListenerDescriptions']:
                    if listener['Listener']['Protocol'] in ['HTTPS', 'SSL'] and self.aws_predifined_security_policy not in listener['Listener']['PolicyNames']:
                        compliant_status = "failed"
            self.elb_list.append(self.create_elb_item(
                'ELB.8',
                'Classic Load Balancers with SSL listeners should use a predefined security policy that has strong AWS Configuration',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['LoadBalancerName']
            ))
    
    @DecoratorClass.my_decorator
    def elb_nine(self) -> None:
        result_list = self.describe_load_balancer_list()
        if not result_list:
            self.elb_list.append(self.create_elb_item(
                'ELB.9',
                'Classic Load Balancers should have cross-zone load balancing enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.elb_cross_zone_load_balancing_compliant(response_detail['LoadBalancerName'])
            self.elb_list.append(self.create_elb_item(
                'ELB.9',
                'Classic Load Balancers should have cross-zone load balancing enabled',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['LoadBalancerName']
            ))
    
    @DecoratorClass.my_decorator
    def elb_ten(self) -> None:
        result_list = self.describe_load_balancer_list()
        if not result_list:
            self.elb_list.append(self.create_elb_item(
                'ELB.10',
                'Classic Load Balancer should span multiple Availability Zones',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if len(response_detail['AvailabilityZones']) < 2:
                self.elb_list.append(self.create_elb_item(
                    'ELB.10',
                    'Classic Load Balancer should span multiple Availability Zones',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['LoadBalancerName']
                ))
            else:
                self.elb_list.append(self.create_elb_item(
                    'ELB.10',
                    'Classic Load Balancer should span multiple Availability Zones',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['LoadBalancerName']
                ))
    
    @DecoratorClass.my_decorator
    def elb_twelve(self) -> None:
        result_list = self.describe_application_load_balancer_list()
        if not result_list:
            self.elb_list.append(self.create_elb_item(
                'ELB.12',
                'Application Load Balancer should be configured with defensive or strictest desync mitigation mode',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.routing_http_desync_mitigation_mode_compliant(response_detail['LoadBalancerArn'])
            self.elb_list.append(self.create_elb_item(
                'ELB.12',
                'Application Load Balancer should be configured with defensive or strictest desync mitigation mode',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['LoadBalancerArn']
            ))
    
    @DecoratorClass.my_decorator
    def elb_thirteen(self) -> None:
        result_list = self.describe_load_balancer_v2_list()
        if not result_list:
            self.elb_list.append(self.create_elb_item(
                'ELB.13',
                'Application, Network and Gateway Load Balancers should span multiple Availability Zones',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if len(response_detail['AvailabilityZones']) < 2:
                self.elb_list.append(self.create_elb_item(
                    'ELB.13',
                    'Application, Network and Gateway Load Balancers should span multiple Availability Zones',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['LoadBalancerArn']
                ))
            else:
                self.elb_list.append(self.create_elb_item(
                    'ELB.13',
                    'Application, Network and Gateway Load Balancers should span multiple Availability Zones',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['LoadBalancerArn']
                ))
    
    @DecoratorClass.my_decorator
    def elb_fourteen(self) -> None:
        result_list = self.describe_load_balancer_list()
        if not result_list:
            self.elb_list.append(self.create_elb_item(
                'ELB.14',
                'Classic Load Balancer should be configured with defensive or strictest desync mitigation mode',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = self.elb_http_desync_mitigation_mode_compliant(response_detail['LoadBalancerName'])
            self.elb_list.append(self.create_elb_item(
                'ELB.14',
                'Classic Load Balancer should be configured with defensive or strictest desync mitigation mode',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['LoadBalancerName']
            ))
    
    @DecoratorClass.my_decorator
    def elb_sixteen(self) -> None:
        result_list = self.describe_application_load_balancer_list()
        if not result_list:
            self.elb_list.append(self.create_elb_item(
                'ELB.16',
                'Application Load Balancers should be associated with an AWS WAF web ACL',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            classic_waf_compliant_status = self.waf_compliant(response_detail['LoadBalancerArn'])
            waf_compliant_status = self.waf_v2_compliant(response_detail['LoadBalancerArn'])
            if all([classic_waf_compliant_status == "failed", waf_compliant_status == "failed"]):
                compliant_status = "failed"
            self.elb_list.append(self.create_elb_item(
                'ELB.16',
                'Application Load Balancers should be associated with an AWS WAF web ACL',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['LoadBalancerArn']
            ))