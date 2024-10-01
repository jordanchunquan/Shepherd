'''
Class name AutoScalingComplianceChecker
Create functions to check compliants and return as 
'control_id': security contorl id,
'control_title': security control title,
'compliance': passed, failed or not_found,
'severity': CRITICAL, HIGH, MEDIUM or LOW,
'auto_remediation': available or not_available,
'resource_id': account id, resource arn or not_found

Not recommend to autoremediate AutoScalingGroup should configure on launch template following best practices
'''

import boto3 # type: ignore
from botocore.exceptions import ClientError # type: ignore
from utils.decorator_class import DecoratorClass # type: ignore
from utils.validate import ParameterValidation # type: ignore
from utils.cross_account import UseCrossAccount # type: ignore
from utils.global_data import compliance_check_list # type: ignore

class AutoScalingComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.auto_scaling_client = boto3.client('autoscaling')
        self.elb_client = boto3.client('elb')
        self.autoscaling_list = compliance_check_list

    def create_autoscaling_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("AutoScaling", control_id, compliance, severity, auto_remediation):
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
    
    def auto_scaling(self) -> list[dict]:
        autoscaling_list: list[dict] = []
        try:
            response = self.auto_scaling_client.describe_auto_scaling_groups()
            autoscaling_list.extend(_ for _ in response['AutoScalingGroups'])
            while 'NextToken' in response:
                response = self.auto_scaling_client.describe_auto_scaling_groups(NextToken=response['NextToken'])
                autoscaling_list.extend(_ for _ in response['AutoScalingGroups'])
            return autoscaling_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    def launch_configuration(self) -> list[dict]:
        autoscaling_list: list[dict] = []
        try:
            response = self.auto_scaling_client.describe_launch_configurations()
            autoscaling_list.extend(_ for _ in response['LaunchConfigurations'])
            while 'NextToken' in response:
                response = self.auto_scaling_client.describe_launch_configurations(NextToken=response['NextToken'])
                autoscaling_list.extend(_ for _ in response['LaunchConfigurations'])
            return autoscaling_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    def elb_name_list(self) -> list[str]:
        elb_list: list[str] = []
        try:
            response = self.elb_client.describe_load_balancers()
            elb_list.extend(_['LoadBalancerName'] for _ in response['LoadBalancerDescriptions'])
            while 'NextMarker' in response:
                response = self.elb_client.describe_load_balancers(Marker=response['NextMarker'])
                elb_list.extend(_['LoadBalancerName'] for _ in response['LoadBalancerDescriptions'])
            return elb_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    @DecoratorClass.my_decorator
    def autoscaling_one(self) -> None:
        name_list = self.elb_name_list()
        result_list = self.auto_scaling()
        if not result_list:
            self.autoscaling_list.append(self.create_autoscaling_item(
                'AutoScaling.1',
                'Auto scaling groups associated with a Classic Load Balancer should use load balancer health checks',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if any([_ in name_list for _ in response['LoadBalancerNames']]) and response['HealthCheckType'] != "ELB":
                self.autoscaling_list.append(self.create_autoscaling_item(
                    'AutoScaling.1',
                    'Auto scaling groups associated with a Classic Load Balancer should use load balancer health checks',
                    'failed',
                    'LOW',
                    'not_available',
                    response['AutoScalingGroupARN']
                ))
            else:
                self.autoscaling_list.append(self.create_autoscaling_item(
                    'AutoScaling.1',
                    'Auto scaling groups associated with a Classic Load Balancer should use load balancer health checks',
                    'passed',
                    'LOW',
                    'not_available',
                    response['AutoScalingGroupARN']
                ))
    
    @DecoratorClass.my_decorator
    def autoscaling_two(self) -> None:
        result_list = self.auto_scaling()
        if not result_list:
            self.autoscaling_list.append(self.create_autoscaling_item(
                'AutoScaling.2',
                'Amazon EC2 Auto Scaling group should cover multiple Availability Zones',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if len(response['AvailabilityZones']) <= 1:
                self.autoscaling_list.append(self.create_autoscaling_item(
                    'AutoScaling.2',
                    'Amazon EC2 Auto Scaling group should cover multiple Availability Zones',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response['AutoScalingGroupARN']
                ))
            else:
                self.autoscaling_list.append(self.create_autoscaling_item(
                    'AutoScaling.2',
                    'Amazon EC2 Auto Scaling group should cover multiple Availability Zones',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response['AutoScalingGroupARN']
                ))

    @DecoratorClass.my_decorator
    def autoscaling_three(self) -> None:
        result_list = self.launch_configuration()
        if not result_list:
            self.autoscaling_list.append(self.create_autoscaling_item(
                'AutoScaling.3',
                'Auto Scaling group launch configurations should configure EC2 instances to require Instance Metadata Service Version 2 (IMDSv2)',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if response.get('MetadataOptions', {}).get('HttpTokens', "") != "required":
                self.autoscaling_list.append(self.create_autoscaling_item(
                    'AutoScaling.3',
                    'Auto Scaling group launch configurations should configure EC2 instances to require Instance Metadata Service Version 2 (IMDSv2)',
                    'failed',
                    'HIGH',
                    'not_available',
                    response['LaunchConfigurationARN']
                ))
            else:
                self.autoscaling_list.append(self.create_autoscaling_item(
                    'AutoScaling.3',
                    'Auto Scaling group launch configurations should configure EC2 instances to require Instance Metadata Service Version 2 (IMDSv2)',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response['LaunchConfigurationARN']
                ))

    @DecoratorClass.my_decorator
    def autoscaling_four(self) -> None:
        result_list = self.launch_configuration()
        if not result_list:
            self.autoscaling_list.append(self.create_autoscaling_item(
                'AutoScaling.4',
                'Auto Scaling group launch configuration should not have a metadata response hop limit greater than 1',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if response.get('MetadataOptions', {}).get('HttpPutResponseHopLimit', 2) > 1:
                self.autoscaling_list.append(self.create_autoscaling_item(
                    'AutoScaling.4',
                    'Auto Scaling group launch configuration should not have a metadata response hop limit greater than 1',
                    'failed',
                    'HIGH',
                    'not_available',
                    response['LaunchConfigurationARN']
                ))
            else:
                self.autoscaling_list.append(self.create_autoscaling_item(
                    'AutoScaling.4',
                    'Auto Scaling group launch configuration should not have a metadata response hop limit greater than 1',
                    'passed',
                    'HIGH',
                    'not_available',
                    response['LaunchConfigurationARN']
                ))

    @DecoratorClass.my_decorator
    def autoscaling_five(self) -> None:
        result_list = self.launch_configuration()
        if not result_list:
            self.autoscaling_list.append(self.create_autoscaling_item(
                'AutoScaling.5',
                'Amazon EC2 instances launched using Auto Scaling group launch configurations should not have Public IP addresses',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if response.get('AssociatePublicIpAddress') == True:
                self.autoscaling_list.append(self.create_autoscaling_item(
                    'AutoScaling.5',
                    'Amazon EC2 instances launched using Auto Scaling group launch configurations should not have Public IP addresses',
                    'failed',
                    'HIGH',
                    'not_available',
                    response['LaunchConfigurationARN']
                ))
            else:
                self.autoscaling_list.append(self.create_autoscaling_item(
                    'AutoScaling.5',
                    'Amazon EC2 instances launched using Auto Scaling group launch configurations should not have Public IP addresses',
                    'passed',
                    'HIGH',
                    'not_available',
                    response['LaunchConfigurationARN']
                ))

    @DecoratorClass.my_decorator
    def autoscaling_six(self) -> None:
        result_list = self.auto_scaling()
        if not result_list:
            self.autoscaling_list.append(self.create_autoscaling_item(
                'AutoScaling.6',
                'Auto Scaling groups should use multiple instance types in multiple Availability Zones',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if len(set(response['AvailabilityZones'])) <= 1:
                self.autoscaling_list.append(self.create_autoscaling_item(
                    'AutoScaling.6',
                    'Auto Scaling groups should use multiple instance types in multiple Availability Zones',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response['AutoScalingGroupARN']
                ))
            else:
                self.autoscaling_list.append(self.create_autoscaling_item(
                    'AutoScaling.6',
                    'Auto Scaling groups should use multiple instance types in multiple Availability Zones',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response['AutoScalingGroupARN']
                ))
    
    @DecoratorClass.my_decorator
    def autoscaling_nine(self) -> None:
        result_list = self.auto_scaling()
        if not result_list:
            self.autoscaling_list.append(self.create_autoscaling_item(
                'AutoScaling.9',
                'EC2 Auto Scaling groups should use EC2 launch templates',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if 'LaunchTemplate' not in response:
                self.autoscaling_list.append(self.create_autoscaling_item(
                    'AutoScaling.9',
                    'EC2 Auto Scaling groups should use EC2 launch templates',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response['AutoScalingGroupARN']
                ))
            else:
                self.autoscaling_list.append(self.create_autoscaling_item(
                    'AutoScaling.9',
                    'EC2 Auto Scaling groups should use EC2 launch templates',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response['AutoScalingGroupARN']
                ))
    
    @DecoratorClass.my_decorator
    def autoscaling_ten(self) -> None:
        result_list = self.auto_scaling()
        if not result_list:
            self.autoscaling_list.append(self.create_autoscaling_item(
                'AutoScaling.10',
                'EC2 Auto Scaling groups should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            compliant_status = "passed"
            tag_key_list = [tag['Key'] for tag in response['Tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.autoscaling_list.append(self.create_autoscaling_item(
                'AutoScaling.10',
                'EC2 Auto Scaling groups should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response['AutoScalingGroupARN']
            ))

class CrossAccountAutoScalingComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.auto_scaling_client = UseCrossAccount().client('autoscaling')
        self.elb_client = UseCrossAccount().client('elb')
        self.autoscaling_list = compliance_check_list

    def create_autoscaling_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("AutoScaling", control_id, compliance, severity, auto_remediation):
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
    
    def auto_scaling(self) -> list[dict]:
        autoscaling_list: list[dict] = []
        try:
            response = self.auto_scaling_client.describe_auto_scaling_groups()
            autoscaling_list.extend(_ for _ in response['AutoScalingGroups'])
            while 'NextToken' in response:
                response = self.auto_scaling_client.describe_auto_scaling_groups(NextToken=response['NextToken'])
                autoscaling_list.extend(_ for _ in response['AutoScalingGroups'])
            return autoscaling_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    def launch_configuration(self) -> list[dict]:
        autoscaling_list: list[dict] = []
        try:
            response = self.auto_scaling_client.describe_launch_configurations()
            autoscaling_list.extend(_ for _ in response['LaunchConfigurations'])
            while 'NextToken' in response:
                response = self.auto_scaling_client.describe_launch_configurations(NextToken=response['NextToken'])
                autoscaling_list.extend(_ for _ in response['LaunchConfigurations'])
            return autoscaling_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    def elb_name_list(self) -> list[str]:
        elb_list: list[str] = []
        try:
            response = self.elb_client.describe_load_balancers()
            elb_list.extend(_['LoadBalancerName'] for _ in response['LoadBalancerDescriptions'])
            while 'NextMarker' in response:
                response = self.elb_client.describe_load_balancers(Marker=response['NextMarker'])
                elb_list.extend(_['LoadBalancerName'] for _ in response['LoadBalancerDescriptions'])
            return elb_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    @DecoratorClass.my_decorator
    def autoscaling_one(self) -> None:
        name_list = self.elb_name_list()
        result_list = self.auto_scaling()
        if not result_list:
            self.autoscaling_list.append(self.create_autoscaling_item(
                'AutoScaling.1',
                'Auto scaling groups associated with a Classic Load Balancer should use load balancer health checks',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if any([_ in name_list for _ in response['LoadBalancerNames']]) and response['HealthCheckType'] != "ELB":
                self.autoscaling_list.append(self.create_autoscaling_item(
                    'AutoScaling.1',
                    'Auto scaling groups associated with a Classic Load Balancer should use load balancer health checks',
                    'failed',
                    'LOW',
                    'not_available',
                    response['AutoScalingGroupARN']
                ))
            else:
                self.autoscaling_list.append(self.create_autoscaling_item(
                    'AutoScaling.1',
                    'Auto scaling groups associated with a Classic Load Balancer should use load balancer health checks',
                    'passed',
                    'LOW',
                    'not_available',
                    response['AutoScalingGroupARN']
                ))
    
    @DecoratorClass.my_decorator
    def autoscaling_two(self) -> None:
        result_list = self.auto_scaling()
        if not result_list:
            self.autoscaling_list.append(self.create_autoscaling_item(
                'AutoScaling.2',
                'Amazon EC2 Auto Scaling group should cover multiple Availability Zones',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if len(response['AvailabilityZones']) <= 1:
                self.autoscaling_list.append(self.create_autoscaling_item(
                    'AutoScaling.2',
                    'Amazon EC2 Auto Scaling group should cover multiple Availability Zones',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response['AutoScalingGroupARN']
                ))
            else:
                self.autoscaling_list.append(self.create_autoscaling_item(
                    'AutoScaling.2',
                    'Amazon EC2 Auto Scaling group should cover multiple Availability Zones',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response['AutoScalingGroupARN']
                ))

    @DecoratorClass.my_decorator
    def autoscaling_three(self) -> None:
        result_list = self.launch_configuration()
        if not result_list:
            self.autoscaling_list.append(self.create_autoscaling_item(
                'AutoScaling.3',
                'Auto Scaling group launch configurations should configure EC2 instances to require Instance Metadata Service Version 2 (IMDSv2)',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if response.get('MetadataOptions', {}).get('HttpTokens', "") != "required":
                self.autoscaling_list.append(self.create_autoscaling_item(
                    'AutoScaling.3',
                    'Auto Scaling group launch configurations should configure EC2 instances to require Instance Metadata Service Version 2 (IMDSv2)',
                    'failed',
                    'HIGH',
                    'not_available',
                    response['LaunchConfigurationARN']
                ))
            else:
                self.autoscaling_list.append(self.create_autoscaling_item(
                    'AutoScaling.3',
                    'Auto Scaling group launch configurations should configure EC2 instances to require Instance Metadata Service Version 2 (IMDSv2)',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response['LaunchConfigurationARN']
                ))

    @DecoratorClass.my_decorator
    def autoscaling_four(self) -> None:
        result_list = self.launch_configuration()
        if not result_list:
            self.autoscaling_list.append(self.create_autoscaling_item(
                'AutoScaling.4',
                'Auto Scaling group launch configuration should not have a metadata response hop limit greater than 1',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if response.get('MetadataOptions', {}).get('HttpPutResponseHopLimit', 2) > 1:
                self.autoscaling_list.append(self.create_autoscaling_item(
                    'AutoScaling.4',
                    'Auto Scaling group launch configuration should not have a metadata response hop limit greater than 1',
                    'failed',
                    'HIGH',
                    'not_available',
                    response['LaunchConfigurationARN']
                ))
            else:
                self.autoscaling_list.append(self.create_autoscaling_item(
                    'AutoScaling.4',
                    'Auto Scaling group launch configuration should not have a metadata response hop limit greater than 1',
                    'passed',
                    'HIGH',
                    'not_available',
                    response['LaunchConfigurationARN']
                ))

    @DecoratorClass.my_decorator
    def autoscaling_five(self) -> None:
        result_list = self.launch_configuration()
        if not result_list:
            self.autoscaling_list.append(self.create_autoscaling_item(
                'AutoScaling.5',
                'Amazon EC2 instances launched using Auto Scaling group launch configurations should not have Public IP addresses',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if response.get('AssociatePublicIpAddress') == True:
                self.autoscaling_list.append(self.create_autoscaling_item(
                    'AutoScaling.5',
                    'Amazon EC2 instances launched using Auto Scaling group launch configurations should not have Public IP addresses',
                    'failed',
                    'HIGH',
                    'not_available',
                    response['LaunchConfigurationARN']
                ))
            else:
                self.autoscaling_list.append(self.create_autoscaling_item(
                    'AutoScaling.5',
                    'Amazon EC2 instances launched using Auto Scaling group launch configurations should not have Public IP addresses',
                    'passed',
                    'HIGH',
                    'not_available',
                    response['LaunchConfigurationARN']
                ))

    @DecoratorClass.my_decorator
    def autoscaling_six(self) -> None:
        result_list = self.auto_scaling()
        if not result_list:
            self.autoscaling_list.append(self.create_autoscaling_item(
                'AutoScaling.6',
                'Auto Scaling groups should use multiple instance types in multiple Availability Zones',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if len(set(response['AvailabilityZones'])) <= 1:
                self.autoscaling_list.append(self.create_autoscaling_item(
                    'AutoScaling.6',
                    'Auto Scaling groups should use multiple instance types in multiple Availability Zones',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response['AutoScalingGroupARN']
                ))
            else:
                self.autoscaling_list.append(self.create_autoscaling_item(
                    'AutoScaling.6',
                    'Auto Scaling groups should use multiple instance types in multiple Availability Zones',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response['AutoScalingGroupARN']
                ))
    
    @DecoratorClass.my_decorator
    def autoscaling_nine(self) -> None:
        result_list = self.auto_scaling()
        if not result_list:
            self.autoscaling_list.append(self.create_autoscaling_item(
                'AutoScaling.9',
                'EC2 Auto Scaling groups should use EC2 launch templates',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if 'LaunchTemplate' not in response:
                self.autoscaling_list.append(self.create_autoscaling_item(
                    'AutoScaling.9',
                    'EC2 Auto Scaling groups should use EC2 launch templates',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response['AutoScalingGroupARN']
                ))
            else:
                self.autoscaling_list.append(self.create_autoscaling_item(
                    'AutoScaling.9',
                    'EC2 Auto Scaling groups should use EC2 launch templates',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response['AutoScalingGroupARN']
                ))
    
    @DecoratorClass.my_decorator
    def autoscaling_ten(self) -> None:
        result_list = self.auto_scaling()
        if not result_list:
            self.autoscaling_list.append(self.create_autoscaling_item(
                'AutoScaling.10',
                'EC2 Auto Scaling groups should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            compliant_status = "passed"
            tag_key_list = [tag['Key'] for tag in response['Tags']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.autoscaling_list.append(self.create_autoscaling_item(
                'AutoScaling.10',
                'EC2 Auto Scaling groups should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response['AutoScalingGroupARN']
            ))