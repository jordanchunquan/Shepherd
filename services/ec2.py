'''
Class name EC2ComplianceChecker
Create functions to check compliants and return as 
'control_id': security contorl id,
'control_title': security control title,
'compliance': passed, failed or not_found,
'severity': CRITICAL, HIGH, MEDIUM or LOW,
'auto_remediation': available or not_available,
'resource_id': account id, resource arn or not_found

Autoremediate EC2 seven by enbling EBS default encryption
'''

import json, boto3 # type: ignore
from botocore.exceptions import ClientError # type: ignore
from utils.decorator_class import DecoratorClass # type: ignore
from utils.validate import ParameterValidation # type: ignore
from utils.cross_account import UseCrossAccount # type: ignore
from utils.global_data import compliance_check_list # type: ignore
from services.cloudwatch import CloudWatchAutoRemediation, CrossAccountCloudWatchAutoRemediation # type: ignore
from services.kms import KMSAutoRemediation, CrossAccountKMSAutoRemediation # type: ignore
from services.iam import IAMAutoRemediation, CrossAccountIAMAutoRemediation # type: ignore
from datetime import datetime, timezone

class EC2ComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.current_datetime = datetime.now().replace(tzinfo=timezone.utc)
        self.ec2_client = boto3.client('ec2')
        self.backup_client = boto3.client('backup')
        self.session_account = boto3.client('sts').get_caller_identity().get('Account')
        self.ec2_list = compliance_check_list

    def create_ec2_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("EC2", control_id, compliance, severity, auto_remediation):
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
    
    def ebs_snapshot_list(self) -> tuple:
        all_ebs_list: list[str] = []
        public_ebs_list: list[str] = []
        try:
            response = self.ec2_client.describe_snapshots(OwnerIds=['self'], RestorableByUserIds=['self'])
            for _ in response['Snapshots']:
                all_ebs_list.append(_['SnapshotId'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_snapshots(OwnerIds=['self'], RestorableByUserIds=['self'], \
                                                                NextToken=response['NextToken'])
                for _ in response['Snapshots']:
                    all_ebs_list.append(_['SnapshotId'])
            response = self.ec2_client.describe_snapshots(OwnerIds=['self'], RestorableByUserIds=['all'])
            for _ in response['Snapshots']:
                public_ebs_list.append(_['SnapshotId'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_snapshots(OwnerIds=['self'], RestorableByUserIds=['all'], \
                                                                NextToken=response['NextToken'])
                for _ in response['Snapshots']:
                    public_ebs_list.append(_['SnapshotId'])
            return all_ebs_list, public_ebs_list
        except ClientError as e:
            print(f"Error: {e}")
            return [], []
    
    def security_group_list(self) -> list[dict]:
        security_group_list: list[dict] = []
        try:
            response = self.ec2_client.describe_security_groups()
            security_group_list.extend(_ for _ in response['SecurityGroups'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_security_groups(NextToken=response['NextToken'])
                security_group_list.extend(_ for _ in response['SecurityGroups'])
            return security_group_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def ebs_list(self) -> list[dict]:
        ebs_list: list[dict] = []
        try:
            response = self.ec2_client.describe_volumes()
            ebs_list.extend(_ for _ in response['Volumes'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_volumes(NextToken=response['NextToken'])
                ebs_list.extend(_ for _ in response['Volumes'])
            return ebs_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    def ec2_instance_list(self) -> list[dict]:
        ec2_list: list[dict] = []
        try:
            response = self.ec2_client.describe_instances()
            ec2_list.extend(_ for reservation in response['Reservations'] for _ in reservation['Instances'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_instances(NextToken=response['NextToken'])
                ec2_list.extend(_ for reservation in response['Reservations'] for _ in reservation['Instances'])
            return ec2_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    def vpc_list(self) -> list[dict]:
        vpc_list: list[dict] = []
        try:
            response = self.ec2_client.describe_vpcs()
            vpc_list.extend(_ for _ in response['Vpcs'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_vpcs(NextToken=response['NextToken'])
                vpc_list.extend(_ for _ in response['Vpcs'])
            return vpc_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    def vpc_flow_log_list(self) -> list[dict]:
        log_list: list[dict] = []
        try:
            response = self.ec2_client.describe_flow_logs()
            log_list.extend(_ for _ in response['FlowLogs'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_flow_logs(NextToken=response['NextToken'])
                log_list.extend(_ for _ in response['FlowLogs'])
            return log_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    def is_ebs_encryption_by_default_enable(self) -> bool:
        try:
            response = self.ec2_client.get_ebs_encryption_by_default()
            return response['EbsEncryptionByDefault']
        except ClientError as e:
            print(f"Error: {e}")
            return False

    def vpc_endpoint_list(self) -> list[dict]:
        endpoint_list: list[dict] = []
        try:
            response = self.ec2_client.describe_vpc_endpoints()
            endpoint_list.extend(_ for _ in response['VpcEndpoints'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_vpc_endpoints(NextToken=response['NextToken'])
                endpoint_list.extend(_ for _ in response['VpcEndpoints'])
            return endpoint_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    def eip_list(self) -> list[dict]:
        try:
            address_list = [address for address in self.ec2_client.describe_addresses()['Addresses']] 
            return address_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def subnet_list(self) -> list[dict]:
        ec2_subnet_list: list[dict] = []
        try:
            response = self.ec2_client.describe_subnets()
            ec2_subnet_list.extend(_ for _ in response['Subnets'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_subnets(NextToken=response['NextToken'])
                ec2_subnet_list.extend(_ for _ in response['Subnets'])
            return ec2_subnet_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def nacl_list(self) -> list[dict]:
        network_acl_list: list[dict] = []
        try:
            response = self.ec2_client.describe_network_acls()
            network_acl_list.extend(_ for _ in response['NetworkAcls'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_network_acls(NextToken=response['NextToken'])
                network_acl_list.extend(_ for _ in response['NetworkAcls'])
            return network_acl_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def vpn_list(self) -> list[dict]:
        client_vpn_list: list[dict] = []
        try:
            response = self.ec2_client.describe_vpn_connections()
            client_vpn_list.extend(_ for _ in response['VpnConnections'])
            return client_vpn_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def tgw_list(self) -> list[dict]:
        transit_gateway_list: list[dict] = []
        try:
            response = self.ec2_client.describe_transit_gateways()
            transit_gateway_list.extend(_ for _ in response['TransitGateways'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_transit_gateways(NextToken=response['NextToken'])
                transit_gateway_list.extend(_ for _ in response['TransitGateways'])
            return transit_gateway_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def launch_temp_list(self) -> list[dict]:
        launch_template_list: list[dict] = []
        try:
            response = self.ec2_client.describe_launch_templates()
            launch_template_list.extend(_ for _ in response['LaunchTemplates'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_launch_templates(NextToken=response['NextToken'])
                launch_template_list.extend(_ for _ in response['LaunchTemplates'])
            return launch_template_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def launch_temp_ver_list(self) -> list[dict]:
        result_list = self.launch_temp_list()
        launch_template_version_list: list[dict] = []
        for response_detail in result_list:
            try:
                response = self.ec2_client.describe_launch_template_versions(
                    LaunchTemplateId=response_detail['LaunchTemplateId']
                )
                launch_template_version_list.extend(_ for _ in response['LaunchTemplateVersions'])
                while 'NextToken' in response:
                    response = self.ec2_client.describe_launch_template_versions(
                        LaunchTemplateId=response_detail['LaunchTemplateId'],
                        NextToken=response['NextToken']
                    )
                    launch_template_version_list.extend(_ for _ in response['LaunchTemplateVersions'])
            except ClientError as e:
                print(f"Error: {e}")
                return []
        return launch_template_version_list
    
    def clientvpn_list(self) -> list[dict]:
        client_vpn_list: list[dict] = []
        try:
            response = self.ec2_client.describe_client_vpn_endpoints()
            client_vpn_list.extend(_ for _ in response['ClientVpnEndpoints'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_client_vpn_endpoints(NextToken=response['NextToken'])
                client_vpn_list.extend(_ for _ in response['ClientVpnEndpoints'])
            return client_vpn_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def backup_recovery_point_list(self) -> list[str]:
        recovery_point_list: list[str] = []
        try:
            backup_vault_response = self.backup_client.list_backup_vaults()
            for backup_vault in backup_vault_response['BackupVaultList']:
                recovery_point_response = self.backup_client.list_recovery_points_by_backup_vault(
                    BackupVaultName=backup_vault['BackupVaultArn'].split(':')[-1]
                )
                for recovery_point in recovery_point_response['RecoveryPoints']:
                    recovery_point_list.append(recovery_point['ResourceArn'].split(':')[-1].split('/')[-1])
            while 'NextToken' in backup_vault_response:
                backup_vault_response = self.backup_client.describe_config_rules(NextToken=backup_vault_response['NextToken'])
                for backup_vault in backup_vault_response['BackupVaultList']:
                    recovery_point_response = self.backup_client.list_recovery_points_by_backup_vault(
                        BackupVaultName=backup_vault['BackupVaultArn'].split(':')[-1]
                    )
                    for recovery_point in recovery_point_response['RecoveryPoints']:
                        recovery_point_list.append(recovery_point['ResourceArn'].split(':')[-1].split('/')[-1])
            return list(set(recovery_point_list))
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def is_security_group_in_use(self, group_id: str) -> bool:
        try:
            response = self.ec2_client.describe_network_interfaces(Filters=[{'Name': 'group-id', 'Values': [group_id]}])
            return bool(response['NetworkInterfaces'])
        except ClientError as e:
            print(f"Error: {e}")
            return False
        
    def transit_gateway_attachment_list(self) -> list[dict]:
        transit_gateway_attachment_list: list[dict] = []
        try:
            response = self.ec2_client.describe_transit_gateway_attachments()
            transit_gateway_attachment_list.extend(_ for _ in response['TransitGatewayAttachments'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_transit_gateway_attachments(NextToken=response['NextToken'])
                transit_gateway_attachment_list.extend(_ for _ in response['TransitGatewayAttachments'])
            return transit_gateway_attachment_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def transit_gateway_route_table_list(self) -> list[dict]:
        transit_gateway_route_table_list: list[dict] = []
        try:
            response = self.ec2_client.describe_transit_gateway_route_tables()
            transit_gateway_route_table_list.extend(_ for _ in response['TransitGatewayRouteTables'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_transit_gateway_route_tables(NextToken=response['NextToken'])
                transit_gateway_route_table_list.extend(_ for _ in response['TransitGatewayRouteTables'])
            return transit_gateway_route_table_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def network_interface_list(self) -> list[dict]:
        network_interface_list: list[dict] = []
        try:
            response = self.ec2_client.describe_network_interfaces()
            network_interface_list.extend(_ for _ in response['NetworkInterfaces'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_network_interfaces(NextToken=response['NextToken'])
                network_interface_list.extend(_ for _ in response['NetworkInterfaces'])
            return network_interface_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def customer_gateway_list(self) -> list[dict]:
        customer_gateway_list: list[dict] = []
        try:
            response = self.ec2_client.describe_customer_gateways()
            customer_gateway_list.extend(_ for _ in response['CustomerGateways'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_customer_gateways(NextToken=response['NextToken'])
                customer_gateway_list.extend(_ for _ in response['CustomerGateways'])
            return customer_gateway_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def elastic_ip_list(self) -> list[dict]:
        elastic_ip_list: list[dict] = []
        try:
            response = self.ec2_client.describe_addresses()
            elastic_ip_list.extend(_ for _ in response['Addresses'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_addresses(NextToken=response['NextToken'])
                elastic_ip_list.extend(_ for _ in response['Addresses'])
            return elastic_ip_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def internet_gateway_list(self) -> list[dict]:
        internet_gateway_list: list[dict] = []
        try:
            response = self.ec2_client.describe_internet_gateways()
            internet_gateway_list.extend(_ for _ in response['InternetGateways'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_internet_gateways(NextToken=response['NextToken'])
                internet_gateway_list.extend(_ for _ in response['InternetGateways'])
            return internet_gateway_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def nat_gateway_list(self) -> list[dict]:
        nat_gateway_list: list[dict] = []
        try:
            response = self.ec2_client.describe_nat_gateways()
            nat_gateway_list.extend(_ for _ in response['NatGateways'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_nat_gateways(NextToken=response['NextToken'])
                nat_gateway_list.extend(_ for _ in response['NatGateways'])
            return nat_gateway_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def route_table_list(self) -> list[dict]:
        route_table_list: list[dict] = []
        try:
            response = self.ec2_client.describe_route_tables()
            route_table_list.extend(_ for _ in response['RouteTables'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_route_tables(NextToken=response['NextToken'])
                route_table_list.extend(_ for _ in response['RouteTables'])
            return route_table_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def volume_list(self) -> list[dict]:
        volume_list: list[dict] = []
        try:
            response = self.ec2_client.describe_volumes()
            volume_list.extend(_ for _ in response['Volumes'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_volumes(NextToken=response['NextToken'])
                volume_list.extend(_ for _ in response['Volumes'])
            return volume_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def vpc_peering_list(self) -> list[dict]:
        vpc_peering_list: list[dict] = []
        try:
            response = self.ec2_client.describe_vpc_peering_connections()
            vpc_peering_list.extend(_ for _ in response['VpcPeeringConnections'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_vpc_peering_connections(NextToken=response['NextToken'])
                vpc_peering_list.extend(_ for _ in response['VpcPeeringConnections'])
            return vpc_peering_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def vpn_gateway_list(self) -> list[dict]:
        vpn_gateway_list: list[dict] = []
        try:
            response = self.ec2_client.describe_vpn_gateways()
            vpn_gateway_list.extend(_ for _ in response['VpnGateways'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_vpn_gateways(NextToken=response['NextToken'])
                vpn_gateway_list.extend(_ for _ in response['VpnGateways'])
            return vpn_gateway_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    @DecoratorClass.my_decorator
    def ec2_one(self) -> None:
        result_list, public_result_list = self.ebs_snapshot_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.1',
                'Amazon EBS snapshots should not be publicly restorable',
                'not_found',
                'CRITICAL',
                'not_available',
                'not_found'
            ))
        if result_list:
            for response_detail in result_list:
                if response_detail in public_result_list:
                    self.ec2_list.append(self.create_ec2_item(
                        'EC2.1',
                        'Amazon EBS snapshots should not be publicly restorable',
                        'failed',
                        'CRITICAL',
                        'not_available',
                        response_detail
                    ))
                else:
                    self.ec2_list.append(self.create_ec2_item(
                        'EC2.1',
                        'Amazon EBS snapshots should not be publicly restorable',
                        'passed',
                        'CRITICAL',
                        'not_available',
                        response_detail
                    ))
    
    @DecoratorClass.my_decorator
    def ec2_two(self) -> None:
        result_list = self.security_group_list()
        if not any([_['GroupName'] == "default" for _ in result_list]):
            self.ec2_list.append(self.create_ec2_item(
                'EC2.2',
                'VPC default security groups should not allow inbound or outbound traffic',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['GroupName'] == "default":
                if any([response_detail['IpPermissions'] != [], \
                        response_detail['IpPermissionsEgress'] != []]):
                    self.ec2_list.append(self.create_ec2_item(
                        'EC2.2',
                        'VPC default security groups should not allow inbound or outbound traffic',
                        'failed',
                        'HIGH',
                        'not_available',
                        response_detail['GroupId']
                    ))
                else:
                    self.ec2_list.append(self.create_ec2_item(
                        'EC2.2',
                        'VPC default security groups should not allow inbound or outbound traffic',
                        'passed',
                        'HIGH',
                        'not_available',
                        response_detail['GroupId']
                    ))
    
    @DecoratorClass.my_decorator
    def ec2_three(self) -> None:
        result_list = self.ebs_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.3',
                'Attached Amazon EBS volumes should be encrypted at-rest',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['Encrypted'] != True:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.3',
                    'Attached Amazon EBS volumes should be encrypted at-rest',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['VolumeId']
                    ))
            else:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.3',
                    'Attached Amazon EBS volumes should be encrypted at-rest',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['VolumeId']
                ))
    
    @DecoratorClass.my_decorator
    def ec2_four(self) -> None:
        result_list = self.ec2_instance_list()
        if not result_list \
            or all([_['State']['Name'] != 'stopped' for _ in result_list]):
            self.ec2_list.append(self.create_ec2_item(
                'EC2.4',
                'Stopped EC2 instances should be removed after a specified time period',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['State']['Name'] == 'stopped':
                if (self.current_datetime - response_detail['LaunchTime']).days > 30:
                    self.ec2_list.append(self.create_ec2_item(
                        'EC2.4',
                        'Stopped EC2 instances should be removed after a specified time period',
                        'failed',
                        'MEDIUM',
                        'not_available',
                        response_detail['InstanceId']
                        ))
                else:
                    self.ec2_list.append(self.create_ec2_item(
                        'EC2.4',
                        'Stopped EC2 instances should be removed after a specified time period',
                        'passed',
                        'MEDIUM',
                        'not_available',
                        response_detail['InstanceId']
                    ))
    
    @DecoratorClass.my_decorator
    def ec2_six(self) -> None:
        result_list = self.vpc_list()
        log_list = self.vpc_flow_log_list()
        log_list = [_['ResourceId'] for _ in log_list]
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.6',
                'VPC flow logging should be enabled in all VPCs',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['VpcId'] not in log_list:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.6',
                    'VPC flow logging should be enabled in all VPCs',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['VpcId']
                    ))
            else:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.6',
                    'VPC flow logging should be enabled in all VPCs',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['VpcId']
                ))
    
    @DecoratorClass.my_decorator
    def ec2_seven(self) -> None:
        result_list = self.is_ebs_encryption_by_default_enable()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.7',
                'EBS default encryption should be enabled',
                'failed',
                'MEDIUM',
                'available',
                self.session_account
            ))
        else:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.7',
                'EBS default encryption should be enabled',
                'passed',
                'MEDIUM',
                'available',
                self.session_account
            ))
    
    @DecoratorClass.my_decorator
    def ec2_eight(self) -> None:
        result_list = self.ec2_instance_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.8',
                'EC2 instances should use Instance Metadata Service Version 2 (IMDSv2)',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['MetadataOptions']['HttpTokens'] != 'required':
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.8',
                    'EC2 instances should use Instance Metadata Service Version 2 (IMDSv2)',
                    'failed',
                    'HIGH',
                    'not_available',
                    response_detail['InstanceId']
                    ))
            else:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.8',
                    'EC2 instances should use Instance Metadata Service Version 2 (IMDSv2)',
                    'passed',
                    'HIGH',
                    'not_available',
                    response_detail['InstanceId']
                ))
    
    @DecoratorClass.my_decorator
    def ec2_nine(self) -> None:
        result_list = self.ec2_instance_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.9',
                'EC2 instances should not have a public IPv4 address',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if 'PublicIpAddress' in response_detail:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.9',
                    'EC2 instances should not have a public IPv4 address',
                    'failed',
                    'HIGH',
                    'not_available',
                    response_detail['InstanceId']
                    ))
            else:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.9',
                    'EC2 instances should not have a public IPv4 address',
                    'passed',
                    'HIGH',
                    'not_available',
                    response_detail['InstanceId']
                ))
    
    @DecoratorClass.my_decorator
    def ec2_ten(self) -> None:
        result_list = self.vpc_endpoint_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.10',
                'Amazon EC2 should be configured to use VPC endpoints that are created for the Amazon EC2 service',
                'failed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))
        else:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.10',
                'Amazon EC2 should be configured to use VPC endpoints that are created for the Amazon EC2 service',
                'passed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))
    
    @DecoratorClass.my_decorator
    def ec2_twelve(self) -> None:
        result_list = self.eip_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.12',
                'Unused Amazon EC2 EIPs should be removed',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if 'InstanceId' not in response_detail:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.12',
                    'Unused Amazon EC2 EIPs should be removed',
                    'failed',
                    'LOW',
                    'not_available',
                    response_detail['AllocationId']
                ))
            else:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.12',
                    'Unused Amazon EC2 EIPs should be removed',
                    'passed',
                    'LOW',
                    'not_available',
                    response_detail['AllocationId']
                ))
    
    @DecoratorClass.my_decorator
    def ec2_thirteen(self) -> None:
        result_list = self.security_group_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.13',
                'Security groups should not allow ingress from 0.0.0.0/0 or ::/0 to port 22',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
            return None
        for response_detail in result_list:
            compliant_status = "passed"
            for inbound_rule in response_detail['IpPermissions']:
                if inbound_rule.get('FromPort') == 22 and \
                    inbound_rule.get('IpProtocol') == 'tcp':
                    for ip_range in inbound_rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            compliant_status = "failed"
                            break
                    for ip_v6_range in inbound_rule.get('Ipv6Ranges', []):
                        if ip_v6_range.get('CidrIpv6') == '::/0':
                            compliant_status = "failed"
                            break
            self.ec2_list.append(self.create_ec2_item(
                'EC2.13',
                'Security groups should not allow ingress from 0.0.0.0/0 or ::/0 to port 22',
                compliant_status,
                'HIGH',
                'not_available',
                response_detail['GroupId']
            ))
    
    @DecoratorClass.my_decorator
    def ec2_fourteen(self) -> None:
        result_list = self.security_group_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.14',
                'Security groups should not allow ingress from 0.0.0.0/0 or ::/0 to port 3389',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            for inbound_rule in response_detail['IpPermissions']:
                if inbound_rule.get('FromPort') == 3389 and \
                    inbound_rule.get('IpProtocol') == 'tcp':
                    for ip_range in inbound_rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            compliant_status = "failed"
                            break
                    for ip_v6_range in inbound_rule.get('Ipv6Ranges', []):
                        if ip_v6_range.get('CidrIpv6') == '::/0':
                            compliant_status = "failed"
                            break
            self.ec2_list.append(self.create_ec2_item(
                'EC2.14',
                'Security groups should not allow ingress from 0.0.0.0/0 or ::/0 to port 3389',
                compliant_status,
                'HIGH',
                'not_available',
                response_detail['GroupId']
            ))
    
    @DecoratorClass.my_decorator
    def ec2_fifteen(self) -> None:
        result_list = self.subnet_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.15',
                'Amazon EC2 subnets should not automatically assign public IP addresses',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['MapPublicIpOnLaunch'] != False:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.15',
                    'Amazon EC2 subnets should not automatically assign public IP addresses',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['SubnetId']
                ))
            else:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.15',
                    'Amazon EC2 subnets should not automatically assign public IP addresses',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['SubnetId']
                ))
    
    @DecoratorClass.my_decorator
    def ec2_sixteen(self) -> None:
        result_list = self.nacl_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.16',
                'Unused Network Access Control Lists should be removed',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliance_status = "passed"
            if not response_detail['Associations']:
                compliance_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.16',
                'Unused Network Access Control Lists should be removed',
                compliance_status,
                'LOW',
                'not_available',
                response_detail['NetworkAclId']
            ))
    
    @DecoratorClass.my_decorator
    def ec2_seventeen(self) -> None:
        result_list = self.ec2_instance_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.17',
                'Amazon EC2 instances should not use multiple ENIs',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if len(response_detail['NetworkInterfaces']) > 1:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.17',
                    'Amazon EC2 instances should not use multiple ENIs',
                    'failed',
                    'LOW',
                    'not_available',
                    response_detail['InstanceId']
                ))
            else:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.17',
                    'Amazon EC2 instances should not use multiple ENIs',
                    'passed',
                    'LOW',
                    'not_available',
                    response_detail['InstanceId']
                ))
    
    @DecoratorClass.my_decorator
    def ec2_eighteen(self) -> None:
        result_list = self.security_group_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.18',
                'Security groups should only allow unrestricted incoming traffic for authorized ports',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            for inbound_rule in response_detail['IpPermissions']:
                if any([inbound_rule.get('FromPort') == 80 and \
                    inbound_rule.get('IpProtocol') == 'tcp', \
                    inbound_rule.get('FromPort') == 443 and \
                    inbound_rule.get('IpProtocol') == 'tcp']):
                    compliant_status = "failed"
                    break
            self.ec2_list.append(self.create_ec2_item(
                'EC2.18',
                'Security groups should only allow unrestricted incoming traffic for authorized ports',
                compliant_status,
                'HIGH',
                'not_available',
                response_detail['GroupId']
            ))
    
    @DecoratorClass.my_decorator
    def ec2_nineteen(self) -> None:
        result_list = self.security_group_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.19',
                'Security groups should not allow unrestricted access to ports with high risk',
                'not_found',
                'CRITICAL',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            for inbound_rule in response_detail['IpPermissions']:
                if all([inbound_rule.get('FromPort') in (20,21,22,23,25,110,135,143,445,1433,1434,3000,3306,3389,4333,5000,5432,5500,5601,8080,8088,8888,9200,9300), \
                    inbound_rule.get('IpProtocol') == 'tcp']):
                    for ip_range in inbound_rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            compliant_status = "failed"
                            break
                    for ip_v6_range in inbound_rule.get('Ipv6Ranges', []):
                        if ip_v6_range.get('CidrIpv6') == '::/0':
                            compliant_status = "failed"
                            break
            self.ec2_list.append(self.create_ec2_item(
                'EC2.19',
                'Security groups should not allow unrestricted access to ports with high risk',
                compliant_status,
                'CRITICAL',
                'not_available',
                response_detail['GroupId']
            ))
    
    @DecoratorClass.my_decorator
    def ec2_twenty(self) -> None:
        result_list = self.vpn_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.20',
                'Both VPN tunnels for an AWS Site-to-Site VPN connection should be up',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if all(vgw_telemetry['Status'] == "DOWN" for vgw_telemetry in response_detail['VgwTelemetry']):
                compliant_status = "failed"
                break
            self.ec2_list.append(self.create_ec2_item(
                'EC2.20',
                'Both VPN tunnels for an AWS Site-to-Site VPN connection should be up',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['VpnConnectionId']
            ))
    
    @DecoratorClass.my_decorator
    def ec2_twentyone(self) -> None:
        result_list = self.security_group_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.21',
                'Network ACLs should not allow ingress from 0.0.0.0/0 to port 22 or port 3389',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            for inbound_rule in response_detail['IpPermissions']:
                if all([inbound_rule.get('FromPort') in (22,3389), \
                    inbound_rule.get('IpProtocol') == 'tcp']):
                    for ip_range in inbound_rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            compliant_status = "failed"
                            break
                    for ip_v6_range in inbound_rule.get('Ipv6Ranges', []):
                        if ip_v6_range.get('CidrIpv6') == '::/0':
                            compliant_status = "failed"
                            break
            else:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.21',
                    'Network ACLs should not allow ingress from 0.0.0.0/0 to port 22 or port 3389',
                    compliant_status,
                    'MEDIUM',
                    'not_available',
                    response_detail['GroupId']
                ))

    @DecoratorClass.my_decorator
    def ec2_twentytwo(self) -> None:
        result_list = self.security_group_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.22',
                'Unused EC2 security groups should be removed',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if not self.is_security_group_in_use(response_detail['GroupId']):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.22',
                'Unused EC2 security groups should be removed',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['GroupId']
            ))
    
    @DecoratorClass.my_decorator
    def ec2_twentythree(self) -> None:
        result_list = self.tgw_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.23',
                'Amazon EC2 Transit Gateways should not automatically accept VPC attachment requests',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['Options'].get('DefaultRouteTableAssociation') == "enable":
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.23',
                    'Amazon EC2 Transit Gateways should not automatically accept VPC attachment requests',
                    'failed',
                    'HIGH',
                    'not_available',
                    response_detail['TransitGatewayId']
                ))
            else:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.23',
                    'Amazon EC2 Transit Gateways should not automatically accept VPC attachment requests',
                    'passed',
                    'HIGH',
                    'not_available',
                    response_detail['TransitGatewayId']
                ))
    
    @DecoratorClass.my_decorator
    def ec2_twentyfour(self) -> None:
        result_list = self.ec2_instance_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.24',
                'Amazon EC2 paravirtual instance types should not be used',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['VirtualizationType'] == "paravirtual":
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.24',
                    'Amazon EC2 paravirtual instance types should not be used',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['InstanceId']
                ))
            else:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.24',
                    'Amazon EC2 paravirtual instance types should not be used',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['InstanceId']
                ))
    
    @DecoratorClass.my_decorator
    def ec2_twentyfive(self) -> None:
        result_list = self.launch_temp_ver_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.25',
                'Amazon EC2 launch templates should not assign public IPs to network interfaces',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if 'NetworkInterfaces' in response_detail['LaunchTemplateData']:
                for network_interface in response_detail['LaunchTemplateData']['NetworkInterfaces']:
                    if network_interface.get('AssociatePublicIpAddress') == True:
                        compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.25',
                'Amazon EC2 launch templates should not assign public IPs to network interfaces',
                compliant_status,
                'HIGH',
                'not_available',
                response_detail['LaunchTemplateId']
            ))
    
    @DecoratorClass.my_decorator
    def ec2_twentyeight(self) -> None:
        result_list = self.ebs_list()
        recovery_point_list = self.backup_recovery_point_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.28',
                'EBS volumes should be covered by a backup plan',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if recovery_point_list:
                compliant_status = "passed"
                if not response_detail['Attachments']:
                    if response_detail['VolumeId'] not in recovery_point_list:
                        compliant_status = "failed"
                for attachment in response_detail['Attachments']:
                    if attachment['InstanceId'] not in recovery_point_list:
                        if response_detail['VolumeId'] not in recovery_point_list:
                            compliant_status = "failed"
            else:
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.28',
                'EBS volumes should be covered by a backup plan',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['VolumeId']
            ))
    
    @DecoratorClass.my_decorator
    def ec2_thirtythree(self) -> None:
        result_list = self.transit_gateway_attachment_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.33',
                'EC2 transit gateway attachments should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.33',
                'EC2 transit gateway attachments should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['TransitGatewayAttachmentId']
            ))
    
    @DecoratorClass.my_decorator
    def ec2_thirtyfour(self) -> None:
        result_list = self.transit_gateway_route_table_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.34',
                'EC2 transit gateway route tables should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.34',
                'EC2 transit gateway route tables should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['TransitGatewayRouteTableId']
            ))
    
    @DecoratorClass.my_decorator
    def ec2_thirtyfive(self) -> None:
        result_list = self.network_interface_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.35',
                'EC2 network interfaces should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag['Key'] for tag in response_detail['TagSet']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.35',
                'EC2 network interfaces should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['NetworkInterfaceId']
            ))

    @DecoratorClass.my_decorator
    def ec2_thirtysix(self) -> None:
        result_list = self.customer_gateway_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.36',
                'EC2 customer gateways should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.36',
                'EC2 customer gateways should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['CustomerGatewayId']
            ))

    @DecoratorClass.my_decorator
    def ec2_thirtyseven(self) -> None:
        result_list = self.elastic_ip_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.37',
                'EC2 Elastic IP addresses should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.37',
                'EC2 Elastic IP addresses should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['PublicIp']
            ))

    @DecoratorClass.my_decorator
    def ec2_thirtyeight(self) -> None:
        result_list = self.ec2_instance_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.38',
                'EC2 instances should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.38',
                'EC2 instances should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['InstanceId']
            ))

    @DecoratorClass.my_decorator
    def ec2_thirtynine(self) -> None:
        result_list = self.internet_gateway_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.39',
                'EC2 internet gateways should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.39',
                'EC2 internet gateways should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['InternetGatewayId']
            ))

    @DecoratorClass.my_decorator
    def ec2_forty(self) -> None:
        result_list = self.nat_gateway_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.40',
                'EC2 NAT gateways should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.40',
                'EC2 NAT gateways should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['NatGatewayId']
            ))

    @DecoratorClass.my_decorator
    def ec2_fortyone(self) -> None:
        result_list = self.nacl_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.41',
                'EC2 network ACLs should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.41',
                'EC2 network ACLs should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['NetworkAclId']
            ))

    @DecoratorClass.my_decorator
    def ec2_fortytwo(self) -> None:
        result_list = self.route_table_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.42',
                'EC2 route tables should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.42',
                'EC2 route tables should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['RouteTableId']
            ))

    @DecoratorClass.my_decorator
    def ec2_fortythree(self) -> None:
        result_list = self.security_group_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.43',
                'EC2 security groups should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.43',
                'EC2 security groups should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['GroupId']
            ))

    @DecoratorClass.my_decorator
    def ec2_fortyfour(self) -> None:
        result_list = self.subnet_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.44',
                'EC2 subnets should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.44',
                'EC2 subnets should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['SubnetId']
            ))

    @DecoratorClass.my_decorator
    def ec2_fortyfive(self) -> None:
        result_list = self.volume_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.45',
                'EC2 volumes should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.45',
                'EC2 volumes should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['VolumeId']
            ))

    @DecoratorClass.my_decorator
    def ec2_fortysix(self) -> None:
        result_list = self.vpc_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.46',
                'Amazon VPCs should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.46',
                'Amazon VPCs should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['VpcId']
            ))

    @DecoratorClass.my_decorator
    def ec2_fortyseven(self) -> None:
        result_list = self.vpc_endpoint_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.47',
                'Amazon VPC endpoint services should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.47',
                'Amazon VPC endpoint services should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['VpcEndpointId']
            ))

    @DecoratorClass.my_decorator
    def ec2_fortyeight(self) -> None:
        result_list = self.vpc_flow_log_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.48',
                'Amazon VPC flow logs should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.48',
                'Amazon VPC flow logs should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['FlowLogId']
            ))

    @DecoratorClass.my_decorator
    def ec2_fortynine(self) -> None:
        result_list = self.vpc_peering_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.49',
                'Amazon VPC peering connections should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.49',
                'Amazon VPC peering connections should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['VpcPeeringConnectionId']
            ))

    @DecoratorClass.my_decorator
    def ec2_fifty(self) -> None:
        result_list = self.vpn_gateway_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.50',
                'EC2 VPN gateways should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.50',
                'EC2 VPN gateways should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['VpnGatewayId']
            ))
    
    @DecoratorClass.my_decorator
    def ec2_fiftyone(self) -> None:
        result_list = self.clientvpn_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.51',
                'EC2 Client VPN endpoints should have client connection logging enabled',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['ConnectionLogOptions']['Enabled'] != True:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.51',
                    'EC2 Client VPN endpoints should have client connection logging enabled',
                    'failed',
                    'LOW',
                    'not_available',
                    response_detail['ClientVpnEndpointId']
                ))
            else:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.51',
                    'EC2 Client VPN endpoints should have client connection logging enabled',
                    'passed',
                    'LOW',
                    'not_available',
                    response_detail['ClientVpnEndpointId']
                ))

    @DecoratorClass.my_decorator
    def ec2_fiftytwo(self) -> None:
        result_list = self.tgw_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.52',
                'EC2 transit gateways should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.52',
                'EC2 transit gateways should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['TransitGatewayId']
            ))

    @DecoratorClass.my_decorator
    def ec2_fiftythree(self) -> None:
        result_list = self.security_group_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.53',
                'EC2 security groups should not allow ingress from 0.0.0.0/0 to remote server administration ports',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            for inbound_rule in response_detail['IpPermissions']:
                if all([inbound_rule.get('FromPort') in (22,3389), \
                    inbound_rule.get('IpProtocol') == 'tcp']):
                    for ip_range in inbound_rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.53',
                'EC2 security groups should not allow ingress from 0.0.0.0/0 to remote server administration ports',
                compliant_status,
                'HIGH',
                'not_available',
                response_detail['GroupId']
            ))

    @DecoratorClass.my_decorator
    def ec2_fiftyfour(self) -> None:
        result_list = self.security_group_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.54',
                'EC2 security groups should not allow ingress from ::/0 to remote server administration ports',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            for inbound_rule in response_detail['IpPermissions']:
                if all([inbound_rule.get('FromPort') in (22,3389), \
                    inbound_rule.get('IpProtocol') == 'tcp']):
                    for ip_v6_range in inbound_rule.get('Ipv6Ranges', []):
                        if ip_v6_range.get('CidrIpv6') == '::/0':
                            compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.54',
                'EC2 security groups should not allow ingress from ::/0 to remote server administration ports',
                compliant_status,
                'HIGH',
                'not_available',
                response_detail['GroupId']
            ))

class EC2AutoRemediation:
    def __init__(self) -> None:
        self.ec2_client = boto3.client('ec2')
        self.logs_client = boto3.client('logs')
        self.iam_client = boto3.client('iam')
        self.session_account = boto3.client('sts').get_caller_identity().get('Account')
        self.session_region = boto3.session.Session().region_name
        self.kms_key_arn = KMSAutoRemediation().get_kms_key_arn()
        self.log_group_retention = 30
        self.vpc_cloudwatch_policy_name = 'automate-vpc-push-to-cloudwatch-policy'
        self.vpc_cloudwatch_role_name = 'automate-vpc-push-to-cloudwatch-role'
        self.vpc_log_group_name = f"VPC/AutomateLogGroup{self.session_account}"
        self.assume_role_policy_document = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "vpc-flow-logs.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        })
        self.vpc_cloudwatch_policy_document = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "logs:CreateLogStream",
                    "Resource": f"arn:aws:logs:{self.session_region}:{self.session_account}:log-group:{self.vpc_log_group_name}:*",
                    "Effect": "Allow"
                },
                {
                    "Action": "logs:PutLogEvents",
                    "Resource": f"arn:aws:logs:{self.session_region}:{self.session_account}:log-group:{self.vpc_log_group_name}:*",
                    "Effect": "Allow"
                }
            ]
        })
        self.remediate_ec2_six()
        self.remediate_ec2_seven()

    def is_ebs_encryption_by_default_enable(self) -> bool:
        try:
            response = self.ec2_client.get_ebs_encryption_by_default()
            return response['EbsEncryptionByDefault']
        except ClientError as e:
            print(f"Error: {e}")
            return False
        
    def get_vpc_list(self) -> list[str]:
        try:
            vpc_list: list[str] = []
            response = self.ec2_client.describe_vpcs()
            vpc_list.extend(_['VpcId'] for _ in response['Vpcs'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_vpcs(NextToken=response['NextToken'])
                vpc_list.extend(_['VpcId'] for _ in response['Vpcs'])
            return vpc_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def get_vpc_flow_log_list(self) -> list[str]:
        try:
            log_list: list[str] = []
            response = self.ec2_client.describe_flow_logs()
            log_list.extend(_ for _ in response['FlowLogs'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_flow_logs(NextToken=response['NextToken'])
                log_list.extend(_ for _ in response['FlowLogs'])
            return log_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def get_vpc_flow_log_unable_list(self, vpc_list: list[str]) -> list[str]:
        flow_log_list = self.get_vpc_flow_log_list()
        flow_log_list = [_['ResourceId'] for _ in flow_log_list]
        unable_flow_log_list = list(set(vpc_list) - set(flow_log_list))
        return unable_flow_log_list

    def verify_log_group(self) -> None:
        try:
            response = self.logs_client.describe_log_groups(logGroupNamePrefix=self.vpc_log_group_name)
            if not response['logGroups']:
                CloudWatchAutoRemediation().create_cloudwatch_log_group(self.vpc_log_group_name, self.kms_key_arn, self.log_group_retention)
        except ClientError as e:
            CloudWatchAutoRemediation().create_cloudwatch_log_group(self.vpc_log_group_name, self.kms_key_arn, self.log_group_retention)

    def verify_vpc_cloudwatch_policy(self) -> None:
        try:
            self.iam_client.get_policy(PolicyArn=f"arn:aws:iam::{self.session_account}:policy/{self.vpc_cloudwatch_policy_name}")
        except ClientError as e:
            IAMAutoRemediation().create_iam_policy(self.vpc_cloudwatch_policy_name, self.vpc_cloudwatch_policy_document)

    def verify_vpc_cloudwatch_role(self) -> None:
        try:
            self.iam_client.get_role(RoleName=self.vpc_cloudwatch_role_name)
        except ClientError as e:
            IAMAutoRemediation().create_iam_role(self.vpc_cloudwatch_role_name, self.assume_role_policy_document)
            IAMAutoRemediation().attach_policy_to_role(self.vpc_cloudwatch_role_name, f"arn:aws:iam::{self.session_account}:policy/{self.vpc_cloudwatch_policy_name}")
    
    def remediate_ec2_six(self) -> None:
        vpc_list = self.get_vpc_list()
        unable_flow_log_list = self.get_vpc_flow_log_unable_list(vpc_list)
        if unable_flow_log_list:
            try:
                self.verify_log_group()
                self.verify_vpc_cloudwatch_policy()
                self.verify_vpc_cloudwatch_role()
                self.ec2_client.create_flow_logs(
                    ResourceIds=unable_flow_log_list,
                    ResourceType='VPC',
                    TrafficType='ALL',
                    LogDestinationType='cloud-watch-logs',
                    DeliverLogsPermissionArn=f"arn:aws:iam::{self.session_account}:role/{self.vpc_cloudwatch_role_name}",
                    LogGroupName=self.vpc_log_group_name
                )
                print(f"Auto remediated for EC2.6: {unable_flow_log_list}")
            except ClientError as e:
                print(f"Error: {e}")
        
    def remediate_ec2_seven(self) -> None:
        if not self.is_ebs_encryption_by_default_enable():
            try:
                self.ec2_client.enable_ebs_encryption_by_default()
                print(f"Auto remediated for EC2.7: {self.session_account}")
            except ClientError as e:
                print(f"Error: {e}")

class CrossAccountEC2ComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.current_datetime = datetime.now().replace(tzinfo=timezone.utc)
        self.ec2_client = UseCrossAccount().client('ec2')
        self.backup_client = UseCrossAccount().client('backup')
        self.config_client = UseCrossAccount().client('config')
        self.session_account = UseCrossAccount().client('sts').get_caller_identity().get('Account')
        self.ec2_list = compliance_check_list
    
    def create_ec2_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("EC2", control_id, compliance, severity, auto_remediation):
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
    
    def ebs_snapshot_list(self) -> tuple:
        all_ebs_list: list[str] = []
        public_ebs_list: list[str] = []
        try:
            response = self.ec2_client.describe_snapshots(OwnerIds=['self'], RestorableByUserIds=['self'])
            for _ in response['Snapshots']:
                all_ebs_list.append(_['SnapshotId'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_snapshots(OwnerIds=['self'], RestorableByUserIds=['self'], \
                                                                NextToken=response['NextToken'])
                for _ in response['Snapshots']:
                    all_ebs_list.append(_['SnapshotId'])
            response = self.ec2_client.describe_snapshots(OwnerIds=['self'], RestorableByUserIds=['all'])
            for _ in response['Snapshots']:
                public_ebs_list.append(_['SnapshotId'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_snapshots(OwnerIds=['self'], RestorableByUserIds=['all'], \
                                                                NextToken=response['NextToken'])
                for _ in response['Snapshots']:
                    public_ebs_list.append(_['SnapshotId'])
            return all_ebs_list, public_ebs_list
        except ClientError as e:
            print(f"Error: {e}")
            return [], []
    
    def security_group_list(self) -> list[dict]:
        security_group_list: list[dict] = []
        try:
            response = self.ec2_client.describe_security_groups()
            security_group_list.extend(_ for _ in response['SecurityGroups'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_security_groups(NextToken=response['NextToken'])
                security_group_list.extend(_ for _ in response['SecurityGroups'])
            return security_group_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def ebs_list(self) -> list[dict]:
        ebs_list: list[dict] = []
        try:
            response = self.ec2_client.describe_volumes()
            ebs_list.extend(_ for _ in response['Volumes'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_volumes(NextToken=response['NextToken'])
                ebs_list.extend(_ for _ in response['Volumes'])
            return ebs_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    def ec2_instance_list(self) -> list[dict]:
        ec2_list: list[dict] = []
        try:
            response = self.ec2_client.describe_instances()
            ec2_list.extend(_ for reservation in response['Reservations'] for _ in reservation['Instances'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_instances(NextToken=response['NextToken'])
                ec2_list.extend(_ for reservation in response['Reservations'] for _ in reservation['Instances'])
            return ec2_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    def vpc_list(self) -> list[dict]:
        vpc_list: list[dict] = []
        try:
            response = self.ec2_client.describe_vpcs()
            vpc_list.extend(_ for _ in response['Vpcs'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_vpcs(NextToken=response['NextToken'])
                vpc_list.extend(_ for _ in response['Vpcs'])
            return vpc_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    def vpc_flow_log_list(self) -> list[dict]:
        log_list: list[dict] = []
        try:
            response = self.ec2_client.describe_flow_logs()
            log_list.extend(_ for _ in response['FlowLogs'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_flow_logs(NextToken=response['NextToken'])
                log_list.extend(_ for _ in response['FlowLogs'])
            return log_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    def is_ebs_encryption_by_default_enable(self) -> bool:
        try:
            response = self.ec2_client.get_ebs_encryption_by_default()
            return response['EbsEncryptionByDefault']
        except ClientError as e:
            print(f"Error: {e}")
            return False

    def vpc_endpoint_list(self) -> list[dict]:
        endpoint_list: list[dict] = []
        try:
            response = self.ec2_client.describe_vpc_endpoints()
            endpoint_list.extend(_ for _ in response['VpcEndpoints'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_vpc_endpoints(NextToken=response['NextToken'])
                endpoint_list.extend(_ for _ in response['VpcEndpoints'])
            return endpoint_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    def eip_list(self) -> list[dict]:
        try:
            address_list = [address for address in self.ec2_client.describe_addresses()['Addresses']] 
            return address_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def subnet_list(self) -> list[dict]:
        ec2_subnet_list: list[dict] = []
        try:
            response = self.ec2_client.describe_subnets()
            ec2_subnet_list.extend(_ for _ in response['Subnets'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_subnets(NextToken=response['NextToken'])
                ec2_subnet_list.extend(_ for _ in response['Subnets'])
            return ec2_subnet_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def nacl_list(self) -> list[dict]:
        network_acl_list: list[dict] = []
        try:
            response = self.ec2_client.describe_network_acls()
            network_acl_list.extend(_ for _ in response['NetworkAcls'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_network_acls(NextToken=response['NextToken'])
                network_acl_list.extend(_ for _ in response['NetworkAcls'])
            return network_acl_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def vpn_list(self) -> list[dict]:
        client_vpn_list: list[dict] = []
        try:
            response = self.ec2_client.describe_vpn_connections()
            client_vpn_list.extend(_ for _ in response['VpnConnections'])
            return client_vpn_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def tgw_list(self) -> list[dict]:
        transit_gateway_list: list[dict] = []
        try:
            response = self.ec2_client.describe_transit_gateways()
            transit_gateway_list.extend(_ for _ in response['TransitGateways'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_transit_gateways(NextToken=response['NextToken'])
                transit_gateway_list.extend(_ for _ in response['TransitGateways'])
            return transit_gateway_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def launch_temp_list(self) -> list[dict]:
        launch_template_list: list[dict] = []
        try:
            response = self.ec2_client.describe_launch_templates()
            launch_template_list.extend(_ for _ in response['LaunchTemplates'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_launch_templates(NextToken=response['NextToken'])
                launch_template_list.extend(_ for _ in response['LaunchTemplates'])
            return launch_template_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def launch_temp_ver_list(self) -> list[dict]:
        result_list = self.launch_temp_list()
        launch_template_version_list: list[dict] = []
        for response_detail in result_list:
            try:
                response = self.ec2_client.describe_launch_template_versions(
                    LaunchTemplateId=response_detail['LaunchTemplateId']
                )
                launch_template_version_list.extend(_ for _ in response['LaunchTemplateVersions'])
                while 'NextToken' in response:
                    response = self.ec2_client.describe_launch_template_versions(
                        LaunchTemplateId=response_detail['LaunchTemplateId'],
                        NextToken=response['NextToken']
                    )
                    launch_template_version_list.extend(_ for _ in response['LaunchTemplateVersions'])
            except ClientError as e:
                print(f"Error: {e}")
                return []
        return launch_template_version_list
    
    def clientvpn_list(self) -> list[dict]:
        client_vpn_list: list[dict] = []
        try:
            response = self.ec2_client.describe_client_vpn_endpoints()
            client_vpn_list.extend(_ for _ in response['ClientVpnEndpoints'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_client_vpn_endpoints(NextToken=response['NextToken'])
                client_vpn_list.extend(_ for _ in response['ClientVpnEndpoints'])
            return client_vpn_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
    
    def backup_recovery_point_list(self) -> list[str]:
        recovery_point_list: list[str] = []
        try:
            backup_vault_response = self.backup_client.list_backup_vaults()
            for backup_vault in backup_vault_response['BackupVaultList']:
                recovery_point_response = self.backup_client.list_recovery_points_by_backup_vault(
                    BackupVaultName=backup_vault['BackupVaultArn'].split(':')[-1]
                )
                for recovery_point in recovery_point_response['RecoveryPoints']:
                    recovery_point_list.append(recovery_point['ResourceArn'].split(':')[-1].split('/')[-1])
            while 'NextToken' in backup_vault_response:
                backup_vault_response = self.backup_client.describe_config_rules(NextToken=backup_vault_response['NextToken'])
                for backup_vault in backup_vault_response['BackupVaultList']:
                    recovery_point_response = self.backup_client.list_recovery_points_by_backup_vault(
                        BackupVaultName=backup_vault['BackupVaultArn'].split(':')[-1]
                    )
                    for recovery_point in recovery_point_response['RecoveryPoints']:
                        recovery_point_list.append(recovery_point['ResourceArn'].split(':')[-1].split('/')[-1])
            return list(set(recovery_point_list))
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def is_security_group_in_use(self, group_id: str) -> bool:
        try:
            response = self.ec2_client.describe_network_interfaces(Filters=[{'Name': 'group-id', 'Values': [group_id]}])
            return bool(response['NetworkInterfaces'])
        except ClientError as e:
            print(f"Error: {e}")
            return False
        
    def transit_gateway_attachment_list(self) -> list[dict]:
        transit_gateway_attachment_list: list[dict] = []
        try:
            response = self.ec2_client.describe_transit_gateway_attachments()
            transit_gateway_attachment_list.extend(_ for _ in response['TransitGatewayAttachments'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_transit_gateway_attachments(NextToken=response['NextToken'])
                transit_gateway_attachment_list.extend(_ for _ in response['TransitGatewayAttachments'])
            return transit_gateway_attachment_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def transit_gateway_route_table_list(self) -> list[dict]:
        transit_gateway_route_table_list: list[dict] = []
        try:
            response = self.ec2_client.describe_transit_gateway_route_tables()
            transit_gateway_route_table_list.extend(_ for _ in response['TransitGatewayRouteTables'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_transit_gateway_route_tables(NextToken=response['NextToken'])
                transit_gateway_route_table_list.extend(_ for _ in response['TransitGatewayRouteTables'])
            return transit_gateway_route_table_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def network_interface_list(self) -> list[dict]:
        network_interface_list: list[dict] = []
        try:
            response = self.ec2_client.describe_network_interfaces()
            network_interface_list.extend(_ for _ in response['NetworkInterfaces'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_network_interfaces(NextToken=response['NextToken'])
                network_interface_list.extend(_ for _ in response['NetworkInterfaces'])
            return network_interface_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def customer_gateway_list(self) -> list[dict]:
        customer_gateway_list: list[dict] = []
        try:
            response = self.ec2_client.describe_customer_gateways()
            customer_gateway_list.extend(_ for _ in response['CustomerGateways'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_customer_gateways(NextToken=response['NextToken'])
                customer_gateway_list.extend(_ for _ in response['CustomerGateways'])
            return customer_gateway_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def elastic_ip_list(self) -> list[dict]:
        elastic_ip_list: list[dict] = []
        try:
            response = self.ec2_client.describe_addresses()
            elastic_ip_list.extend(_ for _ in response['Addresses'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_addresses(NextToken=response['NextToken'])
                elastic_ip_list.extend(_ for _ in response['Addresses'])
            return elastic_ip_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def internet_gateway_list(self) -> list[dict]:
        internet_gateway_list: list[dict] = []
        try:
            response = self.ec2_client.describe_internet_gateways()
            internet_gateway_list.extend(_ for _ in response['InternetGateways'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_internet_gateways(NextToken=response['NextToken'])
                internet_gateway_list.extend(_ for _ in response['InternetGateways'])
            return internet_gateway_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def nat_gateway_list(self) -> list[dict]:
        nat_gateway_list: list[dict] = []
        try:
            response = self.ec2_client.describe_nat_gateways()
            nat_gateway_list.extend(_ for _ in response['NatGateways'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_nat_gateways(NextToken=response['NextToken'])
                nat_gateway_list.extend(_ for _ in response['NatGateways'])
            return nat_gateway_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def route_table_list(self) -> list[dict]:
        route_table_list: list[dict] = []
        try:
            response = self.ec2_client.describe_route_tables()
            route_table_list.extend(_ for _ in response['RouteTables'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_route_tables(NextToken=response['NextToken'])
                route_table_list.extend(_ for _ in response['RouteTables'])
            return route_table_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def volume_list(self) -> list[dict]:
        volume_list: list[dict] = []
        try:
            response = self.ec2_client.describe_volumes()
            volume_list.extend(_ for _ in response['Volumes'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_volumes(NextToken=response['NextToken'])
                volume_list.extend(_ for _ in response['Volumes'])
            return volume_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def vpc_peering_list(self) -> list[dict]:
        vpc_peering_list: list[dict] = []
        try:
            response = self.ec2_client.describe_vpc_peering_connections()
            vpc_peering_list.extend(_ for _ in response['VpcPeeringConnections'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_vpc_peering_connections(NextToken=response['NextToken'])
                vpc_peering_list.extend(_ for _ in response['VpcPeeringConnections'])
            return vpc_peering_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def vpn_gateway_list(self) -> list[dict]:
        vpn_gateway_list: list[dict] = []
        try:
            response = self.ec2_client.describe_vpn_gateways()
            vpn_gateway_list.extend(_ for _ in response['VpnGateways'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_vpn_gateways(NextToken=response['NextToken'])
                vpn_gateway_list.extend(_ for _ in response['VpnGateways'])
            return vpn_gateway_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    @DecoratorClass.my_decorator
    def ec2_one(self) -> None:
        result_list, public_result_list = self.ebs_snapshot_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.1',
                'Amazon EBS snapshots should not be publicly restorable',
                'not_found',
                'CRITICAL',
                'not_available',
                'not_found'
            ))
        if result_list:
            for response_detail in result_list:
                if response_detail in public_result_list:
                    self.ec2_list.append(self.create_ec2_item(
                        'EC2.1',
                        'Amazon EBS snapshots should not be publicly restorable',
                        'failed',
                        'CRITICAL',
                        'not_available',
                        response_detail
                    ))
                else:
                    self.ec2_list.append(self.create_ec2_item(
                        'EC2.1',
                        'Amazon EBS snapshots should not be publicly restorable',
                        'passed',
                        'CRITICAL',
                        'not_available',
                        response_detail
                    ))
    
    @DecoratorClass.my_decorator
    def ec2_two(self) -> None:
        result_list = self.security_group_list()
        if not any([_['GroupName'] == "default" for _ in result_list]):
            self.ec2_list.append(self.create_ec2_item(
                'EC2.2',
                'VPC default security groups should not allow inbound or outbound traffic',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['GroupName'] == "default":
                if any([response_detail['IpPermissions'] != [], \
                        response_detail['IpPermissionsEgress'] != []]):
                    self.ec2_list.append(self.create_ec2_item(
                        'EC2.2',
                        'VPC default security groups should not allow inbound or outbound traffic',
                        'failed',
                        'HIGH',
                        'not_available',
                        response_detail['GroupId']
                    ))
                else:
                    self.ec2_list.append(self.create_ec2_item(
                        'EC2.2',
                        'VPC default security groups should not allow inbound or outbound traffic',
                        'passed',
                        'HIGH',
                        'not_available',
                        response_detail['GroupId']
                    ))
    
    @DecoratorClass.my_decorator
    def ec2_three(self) -> None:
        result_list = self.ebs_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.3',
                'Attached Amazon EBS volumes should be encrypted at-rest',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['Encrypted'] != True:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.3',
                    'Attached Amazon EBS volumes should be encrypted at-rest',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['VolumeId']
                    ))
            else:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.3',
                    'Attached Amazon EBS volumes should be encrypted at-rest',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['VolumeId']
                ))
    
    @DecoratorClass.my_decorator
    def ec2_four(self) -> None:
        result_list = self.ec2_instance_list()
        if not result_list \
            or all([_['State']['Name'] != 'stopped' for _ in result_list]):
            self.ec2_list.append(self.create_ec2_item(
                'EC2.4',
                'Stopped EC2 instances should be removed after a specified time period',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['State']['Name'] == 'stopped':
                if (self.current_datetime - response_detail['LaunchTime']).days > 30:
                    self.ec2_list.append(self.create_ec2_item(
                        'EC2.4',
                        'Stopped EC2 instances should be removed after a specified time period',
                        'failed',
                        'MEDIUM',
                        'not_available',
                        response_detail['InstanceId']
                        ))
                else:
                    self.ec2_list.append(self.create_ec2_item(
                        'EC2.4',
                        'Stopped EC2 instances should be removed after a specified time period',
                        'passed',
                        'MEDIUM',
                        'not_available',
                        response_detail['InstanceId']
                    ))
    
    @DecoratorClass.my_decorator
    def ec2_six(self) -> None:
        result_list = self.vpc_list()
        log_list = self.vpc_flow_log_list()
        log_list = [_['ResourceId'] for _ in log_list]
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.6',
                'VPC flow logging should be enabled in all VPCs',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['VpcId'] not in log_list:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.6',
                    'VPC flow logging should be enabled in all VPCs',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['VpcId']
                    ))
            else:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.6',
                    'VPC flow logging should be enabled in all VPCs',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['ResourceId']['VpcId']
                ))
    
    @DecoratorClass.my_decorator
    def ec2_seven(self) -> None:
        result_list = self.is_ebs_encryption_by_default_enable()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.7',
                'EBS default encryption should be enabled',
                'failed',
                'MEDIUM',
                'available',
                self.session_account
            ))
        else:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.7',
                'EBS default encryption should be enabled',
                'passed',
                'MEDIUM',
                'available',
                self.session_account
            ))
    
    @DecoratorClass.my_decorator
    def ec2_eight(self) -> None:
        result_list = self.ec2_instance_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.8',
                'EC2 instances should use Instance Metadata Service Version 2 (IMDSv2)',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['MetadataOptions']['HttpTokens'] != 'required':
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.8',
                    'EC2 instances should use Instance Metadata Service Version 2 (IMDSv2)',
                    'failed',
                    'HIGH',
                    'not_available',
                    response_detail['InstanceId']
                    ))
            else:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.8',
                    'EC2 instances should use Instance Metadata Service Version 2 (IMDSv2)',
                    'passed',
                    'HIGH',
                    'not_available',
                    response_detail['InstanceId']
                ))
    
    @DecoratorClass.my_decorator
    def ec2_nine(self) -> None:
        result_list = self.ec2_instance_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.9',
                'EC2 instances should not have a public IPv4 address',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if 'PublicIpAddress' in response_detail:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.9',
                    'EC2 instances should not have a public IPv4 address',
                    'failed',
                    'HIGH',
                    'not_available',
                    response_detail['InstanceId']
                    ))
            else:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.9',
                    'EC2 instances should not have a public IPv4 address',
                    'passed',
                    'HIGH',
                    'not_available',
                    response_detail['InstanceId']
                ))
    
    @DecoratorClass.my_decorator
    def ec2_ten(self) -> None:
        result_list = self.vpc_endpoint_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.10',
                'Amazon EC2 should be configured to use VPC endpoints that are created for the Amazon EC2 service',
                'failed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))
        else:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.10',
                'Amazon EC2 should be configured to use VPC endpoints that are created for the Amazon EC2 service',
                'passed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))
    
    @DecoratorClass.my_decorator
    def ec2_twelve(self) -> None:
        result_list = self.eip_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.12',
                'Unused Amazon EC2 EIPs should be removed',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if 'InstanceId' not in response_detail:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.12',
                    'Unused Amazon EC2 EIPs should be removed',
                    'failed',
                    'LOW',
                    'not_available',
                    response_detail['AllocationId']
                ))
            else:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.12',
                    'Unused Amazon EC2 EIPs should be removed',
                    'passed',
                    'LOW',
                    'not_available',
                    response_detail['AllocationId']
                ))
    
    @DecoratorClass.my_decorator
    def ec2_thirteen(self) -> None:
        result_list = self.security_group_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.13',
                'Security groups should not allow ingress from 0.0.0.0/0 or ::/0 to port 22',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
            return None
        for response_detail in result_list:
            compliant_status = "passed"
            for inbound_rule in response_detail['IpPermissions']:
                if inbound_rule.get('FromPort') == 22 and \
                    inbound_rule.get('IpProtocol') == 'tcp':
                    for ip_range in inbound_rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            compliant_status = "failed"
                            break
                    for ip_v6_range in inbound_rule.get('Ipv6Ranges', []):
                        if ip_v6_range.get('CidrIpv6') == '::/0':
                            compliant_status = "failed"
                            break
            self.ec2_list.append(self.create_ec2_item(
                'EC2.13',
                'Security groups should not allow ingress from 0.0.0.0/0 or ::/0 to port 22',
                compliant_status,
                'HIGH',
                'not_available',
                response_detail['GroupId']
            ))
    
    @DecoratorClass.my_decorator
    def ec2_fourteen(self) -> None:
        result_list = self.security_group_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.14',
                'Security groups should not allow ingress from 0.0.0.0/0 or ::/0 to port 3389',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            for inbound_rule in response_detail['IpPermissions']:
                if inbound_rule.get('FromPort') == 3389 and \
                    inbound_rule.get('IpProtocol') == 'tcp':
                    for ip_range in inbound_rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            compliant_status = "failed"
                            break
                    for ip_v6_range in inbound_rule.get('Ipv6Ranges', []):
                        if ip_v6_range.get('CidrIpv6') == '::/0':
                            compliant_status = "failed"
                            break
            self.ec2_list.append(self.create_ec2_item(
                'EC2.14',
                'Security groups should not allow ingress from 0.0.0.0/0 or ::/0 to port 3389',
                compliant_status,
                'HIGH',
                'not_available',
                response_detail['GroupId']
            ))
    
    @DecoratorClass.my_decorator
    def ec2_fifteen(self) -> None:
        result_list = self.subnet_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.15',
                'Amazon EC2 subnets should not automatically assign public IP addresses',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['MapPublicIpOnLaunch'] != False:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.15',
                    'Amazon EC2 subnets should not automatically assign public IP addresses',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['SubnetId']
                ))
            else:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.15',
                    'Amazon EC2 subnets should not automatically assign public IP addresses',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['SubnetId']
                ))
    
    @DecoratorClass.my_decorator
    def ec2_sixteen(self) -> None:
        result_list = self.nacl_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.16',
                'Unused Network Access Control Lists should be removed',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliance_status = "passed"
            if not response_detail['Associations']:
                compliance_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.16',
                'Unused Network Access Control Lists should be removed',
                compliance_status,
                'LOW',
                'not_available',
                response_detail['NetworkAclId']
            ))
    
    @DecoratorClass.my_decorator
    def ec2_seventeen(self) -> None:
        result_list = self.ec2_instance_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.17',
                'Amazon EC2 instances should not use multiple ENIs',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if len(response_detail['NetworkInterfaces']) > 1:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.17',
                    'Amazon EC2 instances should not use multiple ENIs',
                    'failed',
                    'LOW',
                    'not_available',
                    response_detail['InstanceId']
                ))
            else:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.17',
                    'Amazon EC2 instances should not use multiple ENIs',
                    'passed',
                    'LOW',
                    'not_available',
                    response_detail['InstanceId']
                ))
    
    @DecoratorClass.my_decorator
    def ec2_eighteen(self) -> None:
        result_list = self.security_group_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.18',
                'Security groups should only allow unrestricted incoming traffic for authorized ports',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            for inbound_rule in response_detail['IpPermissions']:
                if any([inbound_rule.get('FromPort') == 80 and \
                    inbound_rule.get('IpProtocol') == 'tcp', \
                    inbound_rule.get('FromPort') == 443 and \
                    inbound_rule.get('IpProtocol') == 'tcp']):
                    compliant_status = "failed"
                    break
            self.ec2_list.append(self.create_ec2_item(
                'EC2.18',
                'Security groups should only allow unrestricted incoming traffic for authorized ports',
                compliant_status,
                'HIGH',
                'not_available',
                response_detail['GroupId']
            ))
    
    @DecoratorClass.my_decorator
    def ec2_nineteen(self) -> None:
        result_list = self.security_group_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.19',
                'Security groups should not allow unrestricted access to ports with high risk',
                'not_found',
                'CRITICAL',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            for inbound_rule in response_detail['IpPermissions']:
                if all([inbound_rule.get('FromPort') in (20,21,22,23,25,110,135,143,445,1433,1434,3000,3306,3389,4333,5000,5432,5500,5601,8080,8088,8888,9200,9300), \
                    inbound_rule.get('IpProtocol') == 'tcp']):
                    for ip_range in inbound_rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            compliant_status = "failed"
                            break
                    for ip_v6_range in inbound_rule.get('Ipv6Ranges', []):
                        if ip_v6_range.get('CidrIpv6') == '::/0':
                            compliant_status = "failed"
                            break
            self.ec2_list.append(self.create_ec2_item(
                'EC2.19',
                'Security groups should not allow unrestricted access to ports with high risk',
                compliant_status,
                'CRITICAL',
                'not_available',
                response_detail['GroupId']
            ))
    
    @DecoratorClass.my_decorator
    def ec2_twenty(self) -> None:
        result_list = self.vpn_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.20',
                'Both VPN tunnels for an AWS Site-to-Site VPN connection should be up',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if all(vgw_telemetry['Status'] == "DOWN" for vgw_telemetry in response_detail['VgwTelemetry']):
                compliant_status = "failed"
                break
            self.ec2_list.append(self.create_ec2_item(
                'EC2.20',
                'Both VPN tunnels for an AWS Site-to-Site VPN connection should be up',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['VpnConnectionId']
            ))
    
    @DecoratorClass.my_decorator
    def ec2_twentyone(self) -> None:
        result_list = self.security_group_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.21',
                'Network ACLs should not allow ingress from 0.0.0.0/0 to port 22 or port 3389',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            for inbound_rule in response_detail['IpPermissions']:
                if all([inbound_rule.get('FromPort') in (22,3389), \
                    inbound_rule.get('IpProtocol') == 'tcp']):
                    for ip_range in inbound_rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            compliant_status = "failed"
                            break
                    for ip_v6_range in inbound_rule.get('Ipv6Ranges', []):
                        if ip_v6_range.get('CidrIpv6') == '::/0':
                            compliant_status = "failed"
                            break
            else:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.21',
                    'Network ACLs should not allow ingress from 0.0.0.0/0 to port 22 or port 3389',
                    compliant_status,
                    'MEDIUM',
                    'not_available',
                    response_detail['GroupId']
                ))

    @DecoratorClass.my_decorator
    def ec2_twentytwo(self) -> None:
        result_list = self.security_group_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.22',
                'Unused EC2 security groups should be removed',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if not self.is_security_group_in_use(response_detail['GroupId']):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.22',
                'Unused EC2 security groups should be removed',
                compliant_status,
                'MEDIUM',
                'not_available',
                response_detail['GroupId']
            ))
    
    @DecoratorClass.my_decorator
    def ec2_twentythree(self) -> None:
        result_list = self.tgw_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.23',
                'Amazon EC2 Transit Gateways should not automatically accept VPC attachment requests',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['Options'].get('DefaultRouteTableAssociation') == "enable":
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.23',
                    'Amazon EC2 Transit Gateways should not automatically accept VPC attachment requests',
                    'failed',
                    'HIGH',
                    'not_available',
                    response_detail['TransitGatewayId']
                ))
            else:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.23',
                    'Amazon EC2 Transit Gateways should not automatically accept VPC attachment requests',
                    'passed',
                    'HIGH',
                    'not_available',
                    response_detail['TransitGatewayId']
                ))
    
    @DecoratorClass.my_decorator
    def ec2_twentyfour(self) -> None:
        result_list = self.ec2_instance_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.24',
                'Amazon EC2 paravirtual instance types should not be used',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['VirtualizationType'] == "paravirtual":
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.24',
                    'Amazon EC2 paravirtual instance types should not be used',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response_detail['InstanceId']
                ))
            else:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.24',
                    'Amazon EC2 paravirtual instance types should not be used',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response_detail['InstanceId']
                ))
    
    @DecoratorClass.my_decorator
    def ec2_twentyfive(self) -> None:
        result_list = self.launch_temp_ver_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.25',
                'Amazon EC2 launch templates should not assign public IPs to network interfaces',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            if 'NetworkInterfaces' in response_detail['LaunchTemplateData']:
                for network_interface in response_detail['LaunchTemplateData']['NetworkInterfaces']:
                    if network_interface.get('AssociatePublicIpAddress') == True:
                        compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.25',
                'Amazon EC2 launch templates should not assign public IPs to network interfaces',
                compliant_status,
                'HIGH',
                'not_available',
                response_detail['LaunchTemplateId']
            ))
    
    @DecoratorClass.my_decorator
    def ec2_twentyeight(self) -> None:
        result_list = self.ebs_list()
        recovery_point_list = self.backup_recovery_point_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.28',
                'EBS volumes should be covered by a backup plan',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if recovery_point_list:
                compliant_status = "passed"
                if not response_detail['Attachments']:
                    if response_detail['VolumeId'] not in recovery_point_list:
                        compliant_status = "failed"
                for attachment in response_detail['Attachments']:
                    if attachment['InstanceId'] not in recovery_point_list:
                        if response_detail['VolumeId'] not in recovery_point_list:
                            compliant_status = "failed"
            else:
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.28',
                'EBS volumes should be covered by a backup plan',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['VolumeId']
            ))
    
    @DecoratorClass.my_decorator
    def ec2_thirtythree(self) -> None:
        result_list = self.transit_gateway_attachment_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.33',
                'EC2 transit gateway attachments should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.33',
                'EC2 transit gateway attachments should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['TransitGatewayAttachmentId']
            ))
    
    @DecoratorClass.my_decorator
    def ec2_thirtyfour(self) -> None:
        result_list = self.transit_gateway_route_table_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.34',
                'EC2 transit gateway route tables should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.34',
                'EC2 transit gateway route tables should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['TransitGatewayRouteTableId']
            ))
    
    @DecoratorClass.my_decorator
    def ec2_thirtyfive(self) -> None:
        result_list = self.network_interface_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.35',
                'EC2 network interfaces should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag['Key'] for tag in response_detail['TagSet']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.35',
                'EC2 network interfaces should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['NetworkInterfaceId']
            ))

    @DecoratorClass.my_decorator
    def ec2_thirtysix(self) -> None:
        result_list = self.customer_gateway_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.36',
                'EC2 customer gateways should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.36',
                'EC2 customer gateways should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['CustomerGatewayId']
            ))

    @DecoratorClass.my_decorator
    def ec2_thirtyseven(self) -> None:
        result_list = self.elastic_ip_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.37',
                'EC2 Elastic IP addresses should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.37',
                'EC2 Elastic IP addresses should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['PublicIp']
            ))

    @DecoratorClass.my_decorator
    def ec2_thirtyeight(self) -> None:
        result_list = self.ec2_instance_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.38',
                'EC2 instances should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.38',
                'EC2 instances should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['InstanceId']
            ))

    @DecoratorClass.my_decorator
    def ec2_thirtynine(self) -> None:
        result_list = self.internet_gateway_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.39',
                'EC2 internet gateways should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.39',
                'EC2 internet gateways should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['InternetGatewayId']
            ))

    @DecoratorClass.my_decorator
    def ec2_forty(self) -> None:
        result_list = self.nat_gateway_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.40',
                'EC2 NAT gateways should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.40',
                'EC2 NAT gateways should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['NatGatewayId']
            ))

    @DecoratorClass.my_decorator
    def ec2_fortyone(self) -> None:
        result_list = self.nacl_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.41',
                'EC2 network ACLs should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.41',
                'EC2 network ACLs should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['NetworkAclId']
            ))

    @DecoratorClass.my_decorator
    def ec2_fortytwo(self) -> None:
        result_list = self.route_table_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.42',
                'EC2 route tables should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.42',
                'EC2 route tables should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['RouteTableId']
            ))

    @DecoratorClass.my_decorator
    def ec2_fortythree(self) -> None:
        result_list = self.security_group_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.43',
                'EC2 security groups should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.43',
                'EC2 security groups should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['GroupId']
            ))

    @DecoratorClass.my_decorator
    def ec2_fortyfour(self) -> None:
        result_list = self.subnet_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.44',
                'EC2 subnets should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.44',
                'EC2 subnets should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['SubnetId']
            ))

    @DecoratorClass.my_decorator
    def ec2_fortyfive(self) -> None:
        result_list = self.volume_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.45',
                'EC2 volumes should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.45',
                'EC2 volumes should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['VolumeId']
            ))

    @DecoratorClass.my_decorator
    def ec2_fortysix(self) -> None:
        result_list = self.vpc_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.46',
                'Amazon VPCs should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.46',
                'Amazon VPCs should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['VpcId']
            ))

    @DecoratorClass.my_decorator
    def ec2_fortyseven(self) -> None:
        result_list = self.vpc_endpoint_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.47',
                'Amazon VPC endpoint services should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.47',
                'Amazon VPC endpoint services should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['VpcEndpointId']
            ))

    @DecoratorClass.my_decorator
    def ec2_fortyeight(self) -> None:
        result_list = self.vpc_flow_log_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.48',
                'Amazon VPC flow logs should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.48',
                'Amazon VPC flow logs should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['FlowLogId']
            ))

    @DecoratorClass.my_decorator
    def ec2_fortynine(self) -> None:
        result_list = self.vpc_peering_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.49',
                'Amazon VPC peering connections should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.49',
                'Amazon VPC peering connections should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['VpcPeeringConnectionId']
            ))

    @DecoratorClass.my_decorator
    def ec2_fifty(self) -> None:
        result_list = self.vpn_gateway_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.50',
                'EC2 VPN gateways should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.50',
                'EC2 VPN gateways should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['VpnGatewayId']
            ))
    
    @DecoratorClass.my_decorator
    def ec2_fiftyone(self) -> None:
        result_list = self.clientvpn_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.51',
                'EC2 Client VPN endpoints should have client connection logging enabled',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail['ConnectionLogOptions']['Enabled'] != True:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.51',
                    'EC2 Client VPN endpoints should have client connection logging enabled',
                    'failed',
                    'LOW',
                    'not_available',
                    response_detail['ClientVpnEndpointId']
                ))
            else:
                self.ec2_list.append(self.create_ec2_item(
                    'EC2.51',
                    'EC2 Client VPN endpoints should have client connection logging enabled',
                    'passed',
                    'LOW',
                    'not_available',
                    response_detail['ClientVpnEndpointId']
                ))

    @DecoratorClass.my_decorator
    def ec2_fiftytwo(self) -> None:
        result_list = self.tgw_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.52',
                'EC2 transit gateways should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            tag_key_list = [tag.get('Key') for tag in response_detail.get('Tags', {})]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.52',
                'EC2 transit gateways should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response_detail['TransitGatewayId']
            ))

    @DecoratorClass.my_decorator
    def ec2_fiftythree(self) -> None:
        result_list = self.security_group_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.53',
                'EC2 security groups should not allow ingress from 0.0.0.0/0 to remote server administration ports',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            for inbound_rule in response_detail['IpPermissions']:
                if all([inbound_rule.get('FromPort') in (22,3389), \
                    inbound_rule.get('IpProtocol') == 'tcp']):
                    for ip_range in inbound_rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.53',
                'EC2 security groups should not allow ingress from 0.0.0.0/0 to remote server administration ports',
                compliant_status,
                'HIGH',
                'not_available',
                response_detail['GroupId']
            ))

    @DecoratorClass.my_decorator
    def ec2_fiftyfour(self) -> None:
        result_list = self.security_group_list()
        if not result_list:
            self.ec2_list.append(self.create_ec2_item(
                'EC2.54',
                'EC2 security groups should not allow ingress from ::/0 to remote server administration ports',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            compliant_status = "passed"
            for inbound_rule in response_detail['IpPermissions']:
                if all([inbound_rule.get('FromPort') in (22,3389), \
                    inbound_rule.get('IpProtocol') == 'tcp']):
                    for ip_v6_range in inbound_rule.get('Ipv6Ranges', []):
                        if ip_v6_range.get('CidrIpv6') == '::/0':
                            compliant_status = "failed"
            self.ec2_list.append(self.create_ec2_item(
                'EC2.54',
                'EC2 security groups should not allow ingress from ::/0 to remote server administration ports',
                compliant_status,
                'HIGH',
                'not_available',
                response_detail['GroupId']
            ))

class CrossAccountEC2AutoRemediation:
    def __init__(self) -> None:
        self.ec2_client = UseCrossAccount().client('ec2')
        self.logs_client = UseCrossAccount().client('logs')
        self.iam_client = UseCrossAccount().client('iam')
        self.session_account = UseCrossAccount().client('sts').get_caller_identity().get('Account')
        self.session_region = UseCrossAccount().session_region_name
        self.kms_key_arn = CrossAccountKMSAutoRemediation().get_kms_key_arn()
        self.log_group_retention = 30
        self.vpc_cloudwatch_policy_name = 'automate-vpc-push-to-cloudwatch-policy'
        self.vpc_cloudwatch_role_name = 'automate-vpc-push-to-cloudwatch-role'
        self.vpc_log_group_name = f"VPC/AutomateLogGroup{self.session_account}"
        self.assume_role_policy_document = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "vpc-flow-logs.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        })
        self.vpc_cloudwatch_policy_document = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "logs:CreateLogStream",
                    "Resource": f"arn:aws:logs:{self.session_region}:{self.session_account}:log-group:{self.vpc_log_group_name}:*",
                    "Effect": "Allow"
                },
                {
                    "Action": "logs:PutLogEvents",
                    "Resource": f"arn:aws:logs:{self.session_region}:{self.session_account}:log-group:{self.vpc_log_group_name}:*",
                    "Effect": "Allow"
                }
            ]
        })
        self.remediate_ec2_six()
        self.remediate_ec2_seven()

    def is_ebs_encryption_by_default_enable(self) -> bool:
        try:
            response = self.ec2_client.get_ebs_encryption_by_default()
            return response['EbsEncryptionByDefault']
        except ClientError as e:
            print(f"Error: {e}")
            return False
        
    def get_vpc_list(self) -> list[str]:
        try:
            vpc_list: list[str] = []
            response = self.ec2_client.describe_vpcs()
            vpc_list.extend(_['VpcId'] for _ in response['Vpcs'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_vpcs(NextToken=response['NextToken'])
                vpc_list.extend(_['VpcId'] for _ in response['Vpcs'])
            return vpc_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def get_vpc_flow_log_list(self) -> list[str]:
        try:
            log_list: list[str] = []
            response = self.ec2_client.describe_flow_logs()
            log_list.extend(_ for _ in response['FlowLogs'])
            while 'NextToken' in response:
                response = self.ec2_client.describe_flow_logs(NextToken=response['NextToken'])
                log_list.extend(_ for _ in response['FlowLogs'])
            return log_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def get_vpc_flow_log_unable_list(self, vpc_list: list[str]) -> list[str]:
        flow_log_list = self.get_vpc_flow_log_list()
        flow_log_list = [_['ResourceId'] for _ in flow_log_list]
        unable_flow_log_list = list(set(vpc_list) - set(flow_log_list))
        return unable_flow_log_list

    def verify_log_group(self) -> None:
        try:
            response = self.logs_client.describe_log_groups(logGroupNamePrefix=self.vpc_log_group_name)
            if not response['logGroups']:
                CrossAccountCloudWatchAutoRemediation().create_cloudwatch_log_group(self.vpc_log_group_name, self.kms_key_arn, self.log_group_retention)
        except ClientError as e:
            CrossAccountCloudWatchAutoRemediation().create_cloudwatch_log_group(self.vpc_log_group_name, self.kms_key_arn, self.log_group_retention)

    def verify_vpc_cloudwatch_policy(self) -> None:
        try:
            self.iam_client.get_policy(PolicyArn=f"arn:aws:iam::{self.session_account}:policy/{self.vpc_cloudwatch_policy_name}")
        except ClientError as e:
            CrossAccountIAMAutoRemediation().create_iam_policy(self.vpc_cloudwatch_policy_name, self.vpc_cloudwatch_policy_document)

    def verify_vpc_cloudwatch_role(self) -> None:
        try:
            self.iam_client.get_role(RoleName=self.vpc_cloudwatch_role_name)
        except ClientError as e:
            CrossAccountIAMAutoRemediation().create_iam_role(self.vpc_cloudwatch_role_name, self.assume_role_policy_document)
            CrossAccountIAMAutoRemediation().attach_policy_to_role(self.vpc_cloudwatch_role_name, f"arn:aws:iam::{self.session_account}:policy/{self.vpc_cloudwatch_policy_name}")
    
    def remediate_ec2_six(self) -> None:
        vpc_list = self.get_vpc_list()
        unable_flow_log_list = self.get_vpc_flow_log_unable_list(vpc_list)
        if unable_flow_log_list:
            self.verify_log_group()
            self.verify_vpc_cloudwatch_policy()
            self.verify_vpc_cloudwatch_role()
            try:
                self.ec2_client.create_flow_logs(
                    ResourceIds=unable_flow_log_list,
                    ResourceType='VPC',
                    TrafficType='ALL',
                    LogDestinationType='cloud-watch-logs',
                    DeliverLogsPermissionArn=f"arn:aws:iam::{self.session_account}:role/{self.vpc_cloudwatch_role_name}",
                    LogGroupName=self.vpc_log_group_name
                )
                print(f"Auto remediated for EC2.6: {unable_flow_log_list}")
            except ClientError as e:
                print(f"Error: {e}")
        
    def remediate_ec2_seven(self) -> None:
        if not self.is_ebs_encryption_by_default_enable():
            try:
                self.ec2_client.enable_ebs_encryption_by_default()
                print(f"Auto remediated for EC2.7: {self.session_account}")
            except ClientError as e:
                print(f"Error: {e}")