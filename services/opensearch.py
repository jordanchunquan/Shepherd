'''
Class name OpensearchComplianceChecker
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

class OpensearchComplianceChecker:
    def __init__(self) -> None:
        self.tls_encryption_policy = "Policy-Min-TLS-1-2-PFS-2023-10"
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.opensearch_client = boto3.client('opensearch')
        self.ec2_client = boto3.client('ec2')
        self.opensearch_list = compliance_check_list # type: ignore

    def create_opensearch_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("Opensearch", control_id, compliance, severity, auto_remediation):
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
    
    def opensearch_domain_name_list(self) -> list[str]:
        domain_name_list: list[str] = []
        try:
            response = self.opensearch_client.list_domain_names()
            domain_name_list.extend(_['DomainName'] for _ in response['DomainNames'])
            return domain_name_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def opensearch_domain_name_description_list(self) -> list[dict]:
        result_list = self.opensearch_domain_name_list()
        domain_description_list: list[dict] = []
        try:
            response = self.opensearch_client.describe_domains(DomainNames=result_list)
            domain_description_list.extend(_ for _ in response['DomainStatusList'])
            return domain_description_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def public_subnet_id_list(self) -> list[str]:
        subnets: list[dict] = []
        route_tables: list[dict] = []
        nacls: list[dict] = []
        igw_ids: list[dict] = []
        public_subnet_id_list: list[str] = []
        try:
            response_subnet = self.ec2_client.describe_subnets()
            subnets.extend(_ for _ in response_subnet['Subnets'])
            if 'NextToken' in response_subnet:
                response_subnet = self.ec2_client.describe_subnets(NextToken=response_subnet['NextToken'])
                subnets.extend(_ for _ in response_subnet['Subnets'])
            response_route_table = self.ec2_client.describe_route_tables()
            route_tables.extend(_ for _ in response_route_table['RouteTables'])
            if 'NextToken' in response_route_table:
                response_route_table = self.ec2_client.describe_route_tables(NextToken=response_route_table['NextToken'])
                route_tables.extend(_ for _ in response_route_table['RouteTables'])
            response_nacl = self.ec2_client.describe_network_acls()
            nacls.extend(_ for _ in response_nacl['NetworkAcls'])
            if 'NextToken' in response_nacl:
                response_nacl = self.ec2_client.describe_network_acls(NextToken=response_nacl['NextToken'])
                nacls.extend(_ for _ in response_nacl['NetworkAcls'])
            response_igw = self.ec2_client.describe_internet_gateways()
            igw_ids.extend(_['InternetGatewayId'] for _ in response_igw['InternetGateways'])
            if 'NextToken' in response_igw:
                response_igw = self.ec2_client.describe_internet_gateways(NextToken=response_igw['NextToken'])
                igw_ids.extend(_['InternetGatewayId'] for _ in response_igw['InternetGateways'])
            for subnet in subnets:
                subnet_id = subnet['SubnetId']
                vpc_id = subnet['VpcId']
                subnet_is_public = False
                for route_table in route_tables:
                    if route_table['VpcId'] == vpc_id:
                        for association in route_table.get('Associations', []):
                            if association.get('SubnetId') == subnet_id:
                                for route in route_table.get('Routes', []):
                                    if route.get('GatewayId') in igw_ids or 'NatGatewayId' in route:
                                        subnet_is_public = True
                                        break
                if subnet_is_public:
                    subnet_nacl = next(
                        (nacl for nacl in nacls if nacl['VpcId'] == vpc_id and 
                        any(assoc['SubnetId'] == subnet_id for assoc in nacl['Associations'])),
                        None
                    )
                    if subnet_nacl:
                        outbound_allowed = any(
                            entry['Egress'] and entry['RuleAction'] == 'allow' and (
                                entry['Protocol'] == '-1' or
                                80 in range(entry['PortRange']['From'], entry['PortRange']['To'] + 1) or
                                443 in range(entry['PortRange']['From'], entry['PortRange']['To'] + 1)
                            )
                            for entry in subnet_nacl['Entries']
                        )
                        if outbound_allowed:
                            public_subnet_id_list.append(subnet_id)
            return public_subnet_id_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def opensearch_tag_compliant_status(self, domain_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.opensearch_client.list_tags(ARN=domain_arn)
            tag_key_list = [tag['Key'] for tag in response['TagList']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
    
    @DecoratorClass.my_decorator
    def opensearch_one(self) -> None:
        result_list = self.opensearch_domain_name_description_list()
        if not result_list:
            self.opensearch_list.append(self.create_opensearch_item(
                'Opensearch.1',
                'OpenSearch domains should have encryption at rest enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('EncryptionAtRestOptions', {}).get('Enabled') != True:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.1',
                    'OpenSearch domains should have encryption at rest enabled',
                    'failed',
                    'MEDIUM',
                    'available',
                    response_detail['ARN']
                ))
            else:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.1',
                    'OpenSearch domains should have encryption at rest enabled',
                    'passed',
                    'MEDIUM',
                    'available',
                    response_detail['ARN']
                ))

    @DecoratorClass.my_decorator
    def opensearch_two(self) -> None:
        result_list = self.opensearch_domain_name_description_list()
        public_subnet_id_list = self.public_subnet_id_list()
        if not result_list:
            self.opensearch_list.append(self.create_opensearch_item(
                'Opensearch.2',
                'OpenSearch domains should not be publicly accessible',
                'not_found',
                'CRITICAL',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('VPCOptions', {}).get('SubnetIds') and any(
                subnet_id in public_subnet_id_list for subnet_id in response_detail['VPCOptions']['SubnetIds']
            ):
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.2',
                    'OpenSearch domains should not be publicly accessible',
                    'failed',
                    'CRITICAL',
                    'available',
                    response_detail['ARN']
                ))
            else:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.2',
                    'OpenSearch domains should not be publicly accessible',
                    'passed',
                    'CRITICAL',
                    'available',
                    response_detail['ARN']
                ))
    
    @DecoratorClass.my_decorator
    def opensearch_three(self) -> None:
        result_list = self.opensearch_domain_name_description_list()
        if not result_list:
            self.opensearch_list.append(self.create_opensearch_item(
                'Opensearch.3',
                'OpenSearch domains should encrypt data sent between nodes',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('NodeToNodeEncryptionOptions', {}).get('Enabled') != True:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.3',
                    'OpenSearch domains should encrypt data sent between nodes',
                    'failed',
                    'MEDIUM',
                    'available',
                    response_detail['ARN']
                ))
            else:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.3',
                    'OpenSearch domains should encrypt data sent between nodes',
                    'passed',
                    'MEDIUM',
                    'available',
                    response_detail['ARN']
                ))
    
    @DecoratorClass.my_decorator
    def opensearch_four(self) -> None:
        result_list = self.opensearch_domain_name_description_list()
        if not result_list:
            self.opensearch_list.append(self.create_opensearch_item(
                'Opensearch.4',
                'OpenSearch domain error logging to CloudWatch Logs should be enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('LogPublishingOptions', {}).get('ES_APPLICATION_LOGS', {}).get('Enabled') != True:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.4',
                    'OpenSearch domain error logging to CloudWatch Logs should be enabled',
                    'failed',
                    'MEDIUM',
                    'available',
                    response_detail['ARN']
                ))
            else:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.4',
                    'OpenSearch domain error logging to CloudWatch Logs should be enabled',
                    'passed',
                    'MEDIUM',
                    'available',
                    response_detail['ARN']
                ))
    
    @DecoratorClass.my_decorator
    def opensearch_five(self) -> None:
        result_list = self.opensearch_domain_name_description_list()
        if not result_list:
            self.opensearch_list.append(self.create_opensearch_item(
                'Opensearch.5',
                'OpenSearch domains should have audit logging enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('LogPublishingOptions', {}).get('AUDIT_LOGS', {}).get('CloudWatchLogsLogGroupArn', 'None') == None:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.5',
                    'OpenSearch domains should have audit logging enabled',
                    'failed',
                    'MEDIUM',
                    'available',
                    response_detail['ARN']
                ))
            else:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.5',
                    'OpenSearch domains should have audit logging enabled',
                    'passed',
                    'MEDIUM',
                    'available',
                    response_detail['ARN']
                ))
    
    @DecoratorClass.my_decorator
    def opensearch_six(self) -> None:
        result_list = self.opensearch_domain_name_description_list()
        if not result_list:
            self.opensearch_list.append(self.create_opensearch_item(
                'Opensearch.6',
                'OpenSearch domains should have at least three data nodes',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('ClusterConfig', {}).get('InstanceCount', 0) < 3 \
                or response_detail.get('ClusterConfig', {}).get('ZoneAwarenessEnabled') != True:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.6',
                    'OpenSearch domains should have at least three data nodes',
                    'failed',
                    'MEDIUM',
                    'available',
                    response_detail['ARN']
                ))
            else:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.6',
                    'OpenSearch domains should have at least three data nodes',
                    'passed',
                    'MEDIUM',
                    'available',
                    response_detail['ARN']
                ))
    
    @DecoratorClass.my_decorator
    def opensearch_seven(self) -> None:
        result_list = self.opensearch_domain_name_description_list()
        if not result_list:
            self.opensearch_list.append(self.create_opensearch_item(
                'Opensearch.7',
                'OpenSearch domains should have fine-grained access control enabled',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('AdvancedSecurityOptions', {}).get('Enabled') != True:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.7',
                    'OpenSearch domains should have fine-grained access control enabled',
                    'failed',
                    'HIGH',
                    'available',
                    response_detail['ARN']
                ))
            else:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.7',
                    'OpenSearch domains should have fine-grained access control enabled',
                    'passed',
                    'HIGH',
                    'available',
                    response_detail['ARN']
                ))
    
    @DecoratorClass.my_decorator
    def opensearch_eight(self) -> None:
        tls_encryption_policy = self.tls_encryption_policy
        result_list = self.opensearch_domain_name_description_list()
        if not result_list:
            self.opensearch_list.append(self.create_opensearch_item(
                'Opensearch.8',
                'Connections to OpenSearch domains should be encrypted using the latest TLS security policy',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('DomainEndpointOptions', {}).get('TLSSecurityPolicy', '') != tls_encryption_policy:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.8',
                    'Connections to OpenSearch domains should be encrypted using the latest TLS security policy',
                    'failed',
                    'MEDIUM',
                    'available',
                    response_detail['ARN']
                ))
            else:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.8',
                    'Connections to OpenSearch domains should be encrypted using the latest TLS security policy',
                    'passed',
                    'MEDIUM',
                    'available',
                    response_detail['ARN']
                ))
    
    @DecoratorClass.my_decorator
    def opensearch_nine(self) -> None:
        result_list = self.opensearch_domain_name_description_list()
        if not result_list:
            self.opensearch_list.append(self.create_opensearch_item(
                'Opensearch.9',
                'OpenSearch domains should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            complaint_status = self.opensearch_tag_compliant_status(response_detail['ARN'])
            self.opensearch_list.append(self.create_opensearch_item(
                'Opensearch.9',
                'OpenSearch domains should be tagged',
                complaint_status,
                'LOW',
                'available',
                response_detail['ARN']
            ))
    
    @DecoratorClass.my_decorator
    def opensearch_ten(self) -> None:
        result_list = self.opensearch_domain_name_description_list()
        if not result_list:
            self.opensearch_list.append(self.create_opensearch_item(
                'Opensearch.10',
                'OpenSearch domains should have the latest software update installed',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('SoftwareUpdateOptions', {}).get('AutoSoftwareUpdateEnabled') != True:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.10',
                    'OpenSearch domains should have the latest software update installed',
                    'failed',
                    'LOW',
                    'available',
                    response_detail['ARN']
                ))
            else:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.10',
                    'OpenSearch domains should have the latest software update installed',
                    'passed',
                    'LOW',
                    'available',
                    response_detail['ARN']
                ))
    
    @DecoratorClass.my_decorator
    def opensearch_eleven(self) -> None:
        result_list = self.opensearch_domain_name_description_list()
        if not result_list:
            self.opensearch_list.append(self.create_opensearch_item(
                'Opensearch.11',
                'OpenSearch domains should have at least three dedicated primary nodes',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('ClusterConfig', {}).get('DedicatedMasterCount', 0) < 3:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.11',
                    'OpenSearch domains should have at least three dedicated primary nodes',
                    'failed',
                    'MEDIUM',
                    'available',
                    response_detail['ARN']
                ))
            else:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.11',
                    'OpenSearch domains should have at least three dedicated primary nodes',
                    'passed',
                    'MEDIUM',
                    'available',
                    response_detail['ARN']
                ))

class CrossAccountOpensearchComplianceChecker:
    def __init__(self) -> None:
        self.tls_encryption_policy = "Policy-Min-TLS-1-2-PFS-2023-10"
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.opensearch_client = UseCrossAccount().client('opensearch')
        self.ec2_client = UseCrossAccount().client('ec2')
        self.opensearch_list = compliance_check_list # type: ignore

    def create_opensearch_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("Opensearch", control_id, compliance, severity, auto_remediation):
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
    
    def opensearch_domain_name_list(self) -> list[str]:
        domain_name_list: list[str] = []
        try:
            response = self.opensearch_client.list_domain_names()
            domain_name_list.extend(_['DomainName'] for _ in response['DomainNames'])
            return domain_name_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def opensearch_domain_name_description_list(self) -> list[dict]:
        result_list = self.opensearch_domain_name_list()
        domain_description_list: list[dict] = []
        try:
            response = self.opensearch_client.describe_domains(DomainNames=result_list)
            domain_description_list.extend(_ for _ in response['DomainStatusList'])
            return domain_description_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def public_subnet_id_list(self) -> list[str]:
        subnets: list[dict] = []
        route_tables: list[dict] = []
        nacls: list[dict] = []
        igw_ids: list[dict] = []
        public_subnet_id_list: list[str] = []
        try:
            response_subnet = self.ec2_client.describe_subnets()
            subnets.extend(_ for _ in response_subnet['Subnets'])
            if 'NextToken' in response_subnet:
                response_subnet = self.ec2_client.describe_subnets(NextToken=response_subnet['NextToken'])
                subnets.extend(_ for _ in response_subnet['Subnets'])
            response_route_table = self.ec2_client.describe_route_tables()
            route_tables.extend(_ for _ in response_route_table['RouteTables'])
            if 'NextToken' in response_route_table:
                response_route_table = self.ec2_client.describe_route_tables(NextToken=response_route_table['NextToken'])
                route_tables.extend(_ for _ in response_route_table['RouteTables'])
            response_nacl = self.ec2_client.describe_network_acls()
            nacls.extend(_ for _ in response_nacl['NetworkAcls'])
            if 'NextToken' in response_nacl:
                response_nacl = self.ec2_client.describe_network_acls(NextToken=response_nacl['NextToken'])
                nacls.extend(_ for _ in response_nacl['NetworkAcls'])
            response_igw = self.ec2_client.describe_internet_gateways()
            igw_ids.extend(_['InternetGatewayId'] for _ in response_igw['InternetGateways'])
            if 'NextToken' in response_igw:
                response_igw = self.ec2_client.describe_internet_gateways(NextToken=response_igw['NextToken'])
                igw_ids.extend(_['InternetGatewayId'] for _ in response_igw['InternetGateways'])
            for subnet in subnets:
                subnet_id = subnet['SubnetId']
                vpc_id = subnet['VpcId']
                subnet_is_public = False
                for route_table in route_tables:
                    if route_table['VpcId'] == vpc_id:
                        for association in route_table.get('Associations', []):
                            if association.get('SubnetId') == subnet_id:
                                for route in route_table.get('Routes', []):
                                    if route.get('GatewayId') in igw_ids or 'NatGatewayId' in route:
                                        subnet_is_public = True
                                        break
                if subnet_is_public:
                    subnet_nacl = next(
                        (nacl for nacl in nacls if nacl['VpcId'] == vpc_id and 
                        any(assoc['SubnetId'] == subnet_id for assoc in nacl['Associations'])),
                        None
                    )
                    if subnet_nacl:
                        outbound_allowed = any(
                            entry['Egress'] and entry['RuleAction'] == 'allow' and (
                                entry['Protocol'] == '-1' or
                                80 in range(entry['PortRange']['From'], entry['PortRange']['To'] + 1) or
                                443 in range(entry['PortRange']['From'], entry['PortRange']['To'] + 1)
                            )
                            for entry in subnet_nacl['Entries']
                        )
                        if outbound_allowed:
                            public_subnet_id_list.append(subnet_id)
            return public_subnet_id_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def opensearch_tag_compliant_status(self, domain_arn: str) -> str:
        try:
            compliant_status = "passed"
            response = self.opensearch_client.list_tags(ARN=domain_arn)
            tag_key_list = [tag['Key'] for tag in response['TagList']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""
    
    @DecoratorClass.my_decorator
    def opensearch_one(self) -> None:
        result_list = self.opensearch_domain_name_description_list()
        if not result_list:
            self.opensearch_list.append(self.create_opensearch_item(
                'Opensearch.1',
                'OpenSearch domains should have encryption at rest enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('EncryptionAtRestOptions', {}).get('Enabled') != True:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.1',
                    'OpenSearch domains should have encryption at rest enabled',
                    'failed',
                    'MEDIUM',
                    'available',
                    response_detail['ARN']
                ))
            else:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.1',
                    'OpenSearch domains should have encryption at rest enabled',
                    'passed',
                    'MEDIUM',
                    'available',
                    response_detail['ARN']
                ))

    @DecoratorClass.my_decorator
    def opensearch_two(self) -> None:
        result_list = self.opensearch_domain_name_description_list()
        public_subnet_id_list = self.public_subnet_id_list()
        if not result_list:
            self.opensearch_list.append(self.create_opensearch_item(
                'Opensearch.2',
                'OpenSearch domains should not be publicly accessible',
                'not_found',
                'CRITICAL',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('VPCOptions', {}).get('SubnetIds') and any(
                subnet_id in public_subnet_id_list for subnet_id in response_detail['VPCOptions']['SubnetIds']
            ):
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.2',
                    'OpenSearch domains should not be publicly accessible',
                    'failed',
                    'CRITICAL',
                    'available',
                    response_detail['ARN']
                ))
            else:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.2',
                    'OpenSearch domains should not be publicly accessible',
                    'passed',
                    'CRITICAL',
                    'available',
                    response_detail['ARN']
                ))
    
    @DecoratorClass.my_decorator
    def opensearch_three(self) -> None:
        result_list = self.opensearch_domain_name_description_list()
        if not result_list:
            self.opensearch_list.append(self.create_opensearch_item(
                'Opensearch.3',
                'OpenSearch domains should encrypt data sent between nodes',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('NodeToNodeEncryptionOptions', {}).get('Enabled') != True:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.3',
                    'OpenSearch domains should encrypt data sent between nodes',
                    'failed',
                    'MEDIUM',
                    'available',
                    response_detail['ARN']
                ))
            else:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.3',
                    'OpenSearch domains should encrypt data sent between nodes',
                    'passed',
                    'MEDIUM',
                    'available',
                    response_detail['ARN']
                ))
    
    @DecoratorClass.my_decorator
    def opensearch_four(self) -> None:
        result_list = self.opensearch_domain_name_description_list()
        if not result_list:
            self.opensearch_list.append(self.create_opensearch_item(
                'Opensearch.4',
                'OpenSearch domain error logging to CloudWatch Logs should be enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('LogPublishingOptions', {}).get('ES_APPLICATION_LOGS', {}).get('Enabled') != True:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.4',
                    'OpenSearch domain error logging to CloudWatch Logs should be enabled',
                    'failed',
                    'MEDIUM',
                    'available',
                    response_detail['ARN']
                ))
            else:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.4',
                    'OpenSearch domain error logging to CloudWatch Logs should be enabled',
                    'passed',
                    'MEDIUM',
                    'available',
                    response_detail['ARN']
                ))
    
    @DecoratorClass.my_decorator
    def opensearch_five(self) -> None:
        result_list = self.opensearch_domain_name_description_list()
        if not result_list:
            self.opensearch_list.append(self.create_opensearch_item(
                'Opensearch.5',
                'OpenSearch domains should have audit logging enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('LogPublishingOptions', {}).get('AUDIT_LOGS', {}).get('CloudWatchLogsLogGroupArn', 'None') == None:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.5',
                    'OpenSearch domains should have audit logging enabled',
                    'failed',
                    'MEDIUM',
                    'available',
                    response_detail['ARN']
                ))
            else:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.5',
                    'OpenSearch domains should have audit logging enabled',
                    'passed',
                    'MEDIUM',
                    'available',
                    response_detail['ARN']
                ))
    
    @DecoratorClass.my_decorator
    def opensearch_six(self) -> None:
        result_list = self.opensearch_domain_name_description_list()
        if not result_list:
            self.opensearch_list.append(self.create_opensearch_item(
                'Opensearch.6',
                'OpenSearch domains should have at least three data nodes',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('ClusterConfig', {}).get('InstanceCount', 0) < 3 \
                or response_detail.get('ClusterConfig', {}).get('ZoneAwarenessEnabled') != True:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.6',
                    'OpenSearch domains should have at least three data nodes',
                    'failed',
                    'MEDIUM',
                    'available',
                    response_detail['ARN']
                ))
            else:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.6',
                    'OpenSearch domains should have at least three data nodes',
                    'passed',
                    'MEDIUM',
                    'available',
                    response_detail['ARN']
                ))
    
    @DecoratorClass.my_decorator
    def opensearch_seven(self) -> None:
        result_list = self.opensearch_domain_name_description_list()
        if not result_list:
            self.opensearch_list.append(self.create_opensearch_item(
                'Opensearch.7',
                'OpenSearch domains should have fine-grained access control enabled',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('AdvancedSecurityOptions', {}).get('Enabled') != True:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.7',
                    'OpenSearch domains should have fine-grained access control enabled',
                    'failed',
                    'HIGH',
                    'available',
                    response_detail['ARN']
                ))
            else:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.7',
                    'OpenSearch domains should have fine-grained access control enabled',
                    'passed',
                    'HIGH',
                    'available',
                    response_detail['ARN']
                ))
    
    @DecoratorClass.my_decorator
    def opensearch_eight(self) -> None:
        tls_encryption_policy = self.tls_encryption_policy
        result_list = self.opensearch_domain_name_description_list()
        if not result_list:
            self.opensearch_list.append(self.create_opensearch_item(
                'Opensearch.8',
                'Connections to OpenSearch domains should be encrypted using the latest TLS security policy',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('DomainEndpointOptions', {}).get('TLSSecurityPolicy', '') != tls_encryption_policy:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.8',
                    'Connections to OpenSearch domains should be encrypted using the latest TLS security policy',
                    'failed',
                    'MEDIUM',
                    'available',
                    response_detail['ARN']
                ))
            else:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.8',
                    'Connections to OpenSearch domains should be encrypted using the latest TLS security policy',
                    'passed',
                    'MEDIUM',
                    'available',
                    response_detail['ARN']
                ))
    
    @DecoratorClass.my_decorator
    def opensearch_nine(self) -> None:
        result_list = self.opensearch_domain_name_description_list()
        if not result_list:
            self.opensearch_list.append(self.create_opensearch_item(
                'Opensearch.9',
                'OpenSearch domains should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            complaint_status = self.opensearch_tag_compliant_status(response_detail['ARN'])
            self.opensearch_list.append(self.create_opensearch_item(
                'Opensearch.9',
                'OpenSearch domains should be tagged',
                complaint_status,
                'LOW',
                'available',
                response_detail['ARN']
            ))
    
    @DecoratorClass.my_decorator
    def opensearch_ten(self) -> None:
        result_list = self.opensearch_domain_name_description_list()
        if not result_list:
            self.opensearch_list.append(self.create_opensearch_item(
                'Opensearch.10',
                'OpenSearch domains should have the latest software update installed',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('SoftwareUpdateOptions', {}).get('AutoSoftwareUpdateEnabled') != True:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.10',
                    'OpenSearch domains should have the latest software update installed',
                    'failed',
                    'LOW',
                    'available',
                    response_detail['ARN']
                ))
            else:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.10',
                    'OpenSearch domains should have the latest software update installed',
                    'passed',
                    'LOW',
                    'available',
                    response_detail['ARN']
                ))
    
    @DecoratorClass.my_decorator
    def opensearch_eleven(self) -> None:
        result_list = self.opensearch_domain_name_description_list()
        if not result_list:
            self.opensearch_list.append(self.create_opensearch_item(
                'Opensearch.11',
                'OpenSearch domains should have at least three dedicated primary nodes',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response_detail in result_list:
            if response_detail.get('ClusterConfig', {}).get('DedicatedMasterCount', 0) < 3:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.11',
                    'OpenSearch domains should have at least three dedicated primary nodes',
                    'failed',
                    'MEDIUM',
                    'available',
                    response_detail['ARN']
                ))
            else:
                self.opensearch_list.append(self.create_opensearch_item(
                    'Opensearch.11',
                    'OpenSearch domains should have at least three dedicated primary nodes',
                    'passed',
                    'MEDIUM',
                    'available',
                    response_detail['ARN']
                ))