'''
Class name CloudFrontComplianceChecker
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

class CloudFrontComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.cloudfront_client = boto3.client('cloudfront')
        self.s3_client = boto3.client('s3')
        self.session_region = boto3.session.Session().region_name
        self.cloudfront_list = compliance_check_list

    def create_cloudfront_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("CloudFront", control_id, compliance, severity, auto_remediation):
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
    
    def cloud_front(self) -> list[dict]:
        cloudfront_list: list[dict] = []
        try:
            response = self.cloudfront_client.list_distributions()
            for item in response['DistributionList']['Items']:
                distribution = self.cloudfront_client.get_distribution(Id=item['Id'])['Distribution']
                cloudfront_list.append(distribution)
            while 'NextMarker' in response['DistributionList']:
                response = self.cloudfront_client.list_distributions(Marker=response['DistributionList']['NextMarker'])
                for item in response['DistributionList']['Items']:
                    distribution = self.cloudfront_client.get_distribution(Id=item['Id'])['Distribution']
                    cloudfront_list.append(distribution)
            return cloudfront_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        except KeyError:
            return cloudfront_list

    def s3_bucket(self) -> list[str]:
        s3_list: list[str] = []
        try:
            response = self.s3_client.list_buckets()
            for _ in response['Buckets']:
                s3_list.append(f"{_['Name']}.s3.{self.session_region}.amazonaws.com")
            return s3_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def cloudfront_distribution_tag_list(self, distribution_arn:str) -> str:
        try:
            compliant_status = "passed"
            response = self.cloudfront_client.list_tags_for_resource(
                resourceArn=distribution_arn
            )
            tag_key_list = [tag['Key'] for tag in response['Tags']['Items']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""

    @DecoratorClass.my_decorator
    def cloudfront_one(self) -> None:
        result_list = self.cloud_front()
        if not result_list:
            self.cloudfront_list.append(self.create_cloudfront_item(
                'CloudFront.1',
                'CloudFront distributions should have a default root object configured',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for resposne in result_list:
            if 'DefaultRootObject' not in resposne['DistributionConfig'] \
            or resposne['DistributionConfig']['DefaultRootObject'] == '':
                self.cloudfront_list.append(self.create_cloudfront_item(
                    'CloudFront.1',
                    'CloudFront distributions should have a default root object configured',
                    'failed',
                    'HIGH',
                    'not_available',
                    resposne['ARN']
                ))
            else:
                self.cloudfront_list.append(self.create_cloudfront_item(
                    'CloudFront.1',
                    'CloudFront distributions should have a default root object configured',
                    'passed',
                    'HIGH',
                    'not_available',
                    resposne['ARN']
                ))

    @DecoratorClass.my_decorator
    def cloudfront_three(self) -> None:
        result_list = self.cloud_front()
        if not result_list:
            self.cloudfront_list.append(self.create_cloudfront_item(
                'CloudFront.3',
                'CloudFront distributions should require encryption in transit',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for resposne in result_list:
            if resposne['DistributionConfig']['DefaultCacheBehavior']['ViewerProtocolPolicy'] == "allow-all" \
            or resposne['DistributionConfig'].get('CacheBehaviors', {'':''}).get('ViewerProtocolPolicy', '') == "allow-all":
                self.cloudfront_list.append(self.create_cloudfront_item(
                    'CloudFront.3',
                    'CloudFront distributions should require encryption in transit',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    resposne['ARN']
                ))
            else:
                self.cloudfront_list.append(self.create_cloudfront_item(
                    'CloudFront.3',
                    'CloudFront distributions should require encryption in transit',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    resposne['ARN']
                ))

    @DecoratorClass.my_decorator
    def cloudfront_four(self) -> None:
        result_list = self.cloud_front()
        if not result_list:
            self.cloudfront_list.append(self.create_cloudfront_item(
                'CloudFront.4',
                'CloudFront distributions should have origin failover configured',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            for item in response['DistributionConfig']['Origins']['Items']:
                if 'FailoverCriteria' not in item:
                    self.cloudfront_list.append(self.create_cloudfront_item(
                        'CloudFront.4',
                        'CloudFront distributions should have origin failover configured',
                        'failed',
                        'LOW',
                        'not_available',
                        response['ARN']
                    ))
                else:
                    self.cloudfront_list.append(self.create_cloudfront_item(
                        'CloudFront.4',
                        'CloudFront distributions should have origin failover configured',
                        'passed',
                        'LOW',
                        'not_available',
                        response['ARN']
                    ))

    @DecoratorClass.my_decorator
    def cloudfront_five(self) -> None:
        result_list = self.cloud_front()
        if not result_list:
            self.cloudfront_list.append(self.create_cloudfront_item(
                'CloudFront.5',
                'CloudFront distributions should have logging enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if 'Logging' not in response['DistributionConfig'] \
            or response['DistributionConfig']['Logging']['Enabled'] == False:
                self.cloudfront_list.append(self.create_cloudfront_item(
                    'CloudFront.5',
                    'CloudFront distributions should have logging enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response['ARN']
                ))
            else:
                self.cloudfront_list.append(self.create_cloudfront_item(
                    'CloudFront.5',
                    'CloudFront distributions should have logging enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response['ARN']
                ))

    @DecoratorClass.my_decorator
    def cloudfront_six(self) -> None:
        result_list = self.cloud_front()
        if not result_list:
            self.cloudfront_list.append(self.create_cloudfront_item(
                'CloudFront.1',
                'CloudFront distributions should have WAF enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if response['DistributionConfig']['WebACLId'] == "":
                self.cloudfront_list.append(self.create_cloudfront_item(
                    'CloudFront.6',
                    'CloudFront distributions should have WAF enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response['ARN']
                ))
            else:
                self.cloudfront_list.append(self.create_cloudfront_item(
                    'CloudFront.6',
                    'CloudFront distributions should have WAF enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response['ARN']
                ))

    @DecoratorClass.my_decorator
    def cloudfront_seven(self) -> None:
        result_list = self.cloud_front()
        if not result_list:
            self.cloudfront_list.append(self.create_cloudfront_item(
                'CloudFront.7',
                'CloudFront distributions should use custom SSL/TLS certificates',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if response['DistributionConfig']['ViewerCertificate']['CloudFrontDefaultCertificate'] == True:
                self.cloudfront_list.append(self.create_cloudfront_item(
                    'CloudFront.7',
                    'CloudFront distributions should use custom SSL/TLS certificates',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response['ARN']
                ))
            else:
                self.cloudfront_list.append(self.create_cloudfront_item(
                    'CloudFront.7',
                    'CloudFront distributions should use custom SSL/TLS certificates',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response['ARN']
                ))

    @DecoratorClass.my_decorator
    def cloudfront_eight(self) -> None:
        result_list = self.cloud_front()
        if not result_list:
            self.cloudfront_list.append(self.create_cloudfront_item(
                'CloudFront.8',
                'CloudFront distributions should use SNI to serve HTTPS requests',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if response['DistributionConfig']['ViewerCertificate']['SSLSupportMethod'] != "sni-only":
                self.cloudfront_list.append(self.create_cloudfront_item(
                    'CloudFront.8',
                    'CloudFront distributions should use SNI to serve HTTPS requests',
                    'failed',
                    'LOW',
                    'not_available',
                    response['ARN']
                ))
            else:
                self.cloudfront_list.append(self.create_cloudfront_item(
                    'CloudFront.8',
                    'CloudFront distributions should use SNI to serve HTTPS requests',
                    'passed',
                    'LOW',
                    'not_available',
                    response['ARN']
                ))

    @DecoratorClass.my_decorator
    def cloudfront_nine(self) -> None:
        result_list = self.cloud_front()
        if not result_list:
            self.cloudfront_list.append(self.create_cloudfront_item(
                'CloudFront.9',
                'CloudFront distributions should encrypt traffic to custom origins',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            for item in response['DistributionConfig']['Origins']['Items']:
                if 'CustomOriginConfig' in item:
                    if item['CustomOriginConfig']['OriginProtocolPolicy'] != "https-only" \
                    or (item['CustomOriginConfig']['OriginProtocolPolicy'] == "match-viewer" \
                    and response['DistributionConfig']['DefaultCacheBehavior']['ViewerProtocolPolicy'] == "allow-all"):
                        self.cloudfront_list.append(self.create_cloudfront_item(
                            'CloudFront.9',
                            'CloudFront distributions should encrypt traffic to custom origins',
                            'failed',
                            'MEDIUM',
                            'not_available',
                            response['ARN']
                        ))
                    else:
                        self.cloudfront_list.append(self.create_cloudfront_item(
                            'CloudFront.9',
                            'CloudFront distributions should encrypt traffic to custom origins',
                            'passed',
                            'MEDIUM',
                            'not_available',
                            response['ARN']
                        ))

    @DecoratorClass.my_decorator
    def cloudfront_ten(self) -> None:
        result_list = self.cloud_front()
        if not result_list:
            self.cloudfront_list.append(self.create_cloudfront_item(
                'CloudFront.10',
                'CloudFront distributions should not use deprecated SSL protocols between edge locations and custom origins',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            for item in response['DistributionConfig']['Origins']['Items']:
                if 'CustomOriginConfig' in item:
                    if 'OriginSslProtocols' in item['CustomOriginConfig']:
                        if 'SSLv3' in item['CustomOriginConfig']['OriginSslProtocols']['Items']:
                            self.cloudfront_list.append(self.create_cloudfront_item(
                                'CloudFront.10',
                                'CloudFront distributions should not use deprecated SSL protocols between edge locations and custom origins',
                                'failed',
                                'MEDIUM',
                                'not_available',
                                response['ARN']
                            ))
                        else:
                            self.cloudfront_list.append(self.create_cloudfront_item(
                                'CloudFront.10',
                                'CloudFront distributions should not use deprecated SSL protocols between edge locations and custom origins',
                                'passed',
                                'MEDIUM',
                                'not_available',
                                response['ARN']
                            ))
    
    @DecoratorClass.my_decorator
    def cloudfront_twelve(self) -> None:
        result_list = self.cloud_front()
        s3_list = self.s3_bucket()
        if not result_list:
            self.cloudfront_list.append(self.create_cloudfront_item(
                'CloudFront.12',
                'CloudFront distributions should not point to non-existent S3 origins',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            for item in response['DistributionConfig']['Origins']['Items']:
                if 'S3OriginConfig' in item:
                    if item['DomainName'] not in s3_list:
                        self.cloudfront_list.append(self.create_cloudfront_item(
                            'CloudFront.12',
                            'CloudFront distributions should not point to non-existent S3 origins',
                            'failed',
                            'HIGH',
                            'not_available',
                            response['ARN']
                        ))
                    else:
                        self.cloudfront_list.append(self.create_cloudfront_item(
                            'CloudFront.12',
                            'CloudFront distributions should not point to non-existent S3 origins',
                            'passed',
                            'HIGH',
                            'not_available',
                            response['ARN']
                        ))

    @DecoratorClass.my_decorator
    def cloudfront_thirteen(self) -> None:
        result_list = self.cloud_front()
        if not result_list:
            self.cloudfront_list.append(self.create_cloudfront_item(
                'CloudFront.13',
                'CloudFront distributions should use origin access control',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if 'OriginAccessControlId' not in response['DistributionConfig']['Origins']['Items'][0]:
                self.cloudfront_list.append(self.create_cloudfront_item(
                    'CloudFront.13',
                    'CloudFront distributions should use origin access control',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response['ARN']
                ))
            else:
                self.cloudfront_list.append(self.create_cloudfront_item(
                    'CloudFront.13',
                    'CloudFront distributions should use origin access control',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response['ARN']
                ))

    @DecoratorClass.my_decorator
    def cloudfront_fourteen(self) -> None:
        result_list = self.cloud_front()
        if not result_list:
            self.cloudfront_list.append(self.create_cloudfront_item(
                'CloudFront.14',
                'CloudFront distributions should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            compliant_status = self.cloudfront_distribution_tag_list(response['ARN'])
            self.cloudfront_list.append(self.create_cloudfront_item(
                'CloudFront.14',
                'CloudFront distributions should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response['ARN']
            ))

class CrossAccountCloudFrontComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.cloudfront_client = UseCrossAccount().client('cloudfront')
        self.s3_client = UseCrossAccount().client('s3')
        self.session_region = UseCrossAccount().session_region_name
        self.cloudfront_list = compliance_check_list

    def create_cloudfront_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("CloudFront", control_id, compliance, severity, auto_remediation):
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
    
    def cloud_front(self) -> list[dict]:
        cloudfront_list: list[dict] = []
        try:
            response = self.cloudfront_client.list_distributions()
            for item in response['DistributionList']['Items']:
                distribution = self.cloudfront_client.get_distribution(Id=item['Id'])['Distribution']
                cloudfront_list.append(distribution)
            while 'NextMarker' in response['DistributionList']:
                response = self.cloudfront_client.list_distributions(Marker=response['DistributionList']['NextMarker'])
                for item in response['DistributionList']['Items']:
                    distribution = self.cloudfront_client.get_distribution(Id=item['Id'])['Distribution']
                    cloudfront_list.append(distribution)
            return cloudfront_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        except KeyError:
            return cloudfront_list

    def s3_bucket(self) -> list[str]:
        s3_list: list[str] = []
        try:
            response = self.s3_client.list_buckets()
            for _ in response['Buckets']:
                s3_list.append(f"{_['Name']}.s3.{self.session_region}.amazonaws.com")
            return s3_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def cloudfront_distribution_tag_list(self, distribution_arn:str) -> str:
        try:
            compliant_status = "passed"
            response = self.cloudfront_client.list_tags_for_resource(
                resourceArn=distribution_arn
            )
            tag_key_list = [tag['Key'] for tag in response['Tags']['Items']]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""

    @DecoratorClass.my_decorator
    def cloudfront_one(self) -> None:
        result_list = self.cloud_front()
        if not result_list:
            self.cloudfront_list.append(self.create_cloudfront_item(
                'CloudFront.1',
                'CloudFront distributions should have a default root object configured',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for resposne in result_list:
            if 'DefaultRootObject' not in resposne['DistributionConfig'] \
            or resposne['DistributionConfig']['DefaultRootObject'] == '':
                self.cloudfront_list.append(self.create_cloudfront_item(
                    'CloudFront.1',
                    'CloudFront distributions should have a default root object configured',
                    'failed',
                    'HIGH',
                    'not_available',
                    resposne['ARN']
                ))
            else:
                self.cloudfront_list.append(self.create_cloudfront_item(
                    'CloudFront.1',
                    'CloudFront distributions should have a default root object configured',
                    'passed',
                    'HIGH',
                    'not_available',
                    resposne['ARN']
                ))

    @DecoratorClass.my_decorator
    def cloudfront_three(self) -> None:
        result_list = self.cloud_front()
        if not result_list:
            self.cloudfront_list.append(self.create_cloudfront_item(
                'CloudFront.3',
                'CloudFront distributions should require encryption in transit',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for resposne in result_list:
            if resposne['DistributionConfig']['DefaultCacheBehavior']['ViewerProtocolPolicy'] == "allow-all" \
            or resposne['DistributionConfig'].get('CacheBehaviors', {'':''}).get('ViewerProtocolPolicy', '') == "allow-all":
                self.cloudfront_list.append(self.create_cloudfront_item(
                    'CloudFront.3',
                    'CloudFront distributions should require encryption in transit',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    resposne['ARN']
                ))
            else:
                self.cloudfront_list.append(self.create_cloudfront_item(
                    'CloudFront.3',
                    'CloudFront distributions should require encryption in transit',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    resposne['ARN']
                ))

    @DecoratorClass.my_decorator
    def cloudfront_four(self) -> None:
        result_list = self.cloud_front()
        if not result_list:
            self.cloudfront_list.append(self.create_cloudfront_item(
                'CloudFront.4',
                'CloudFront distributions should have origin failover configured',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            for item in response['DistributionConfig']['Origins']['Items']:
                if 'FailoverCriteria' not in item:
                    self.cloudfront_list.append(self.create_cloudfront_item(
                        'CloudFront.4',
                        'CloudFront distributions should have origin failover configured',
                        'failed',
                        'LOW',
                        'not_available',
                        response['ARN']
                    ))
                else:
                    self.cloudfront_list.append(self.create_cloudfront_item(
                        'CloudFront.4',
                        'CloudFront distributions should have origin failover configured',
                        'passed',
                        'LOW',
                        'not_available',
                        response['ARN']
                    ))

    @DecoratorClass.my_decorator
    def cloudfront_five(self) -> None:
        result_list = self.cloud_front()
        if not result_list:
            self.cloudfront_list.append(self.create_cloudfront_item(
                'CloudFront.5',
                'CloudFront distributions should have logging enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if 'Logging' not in response['DistributionConfig'] \
            or response['DistributionConfig']['Logging']['Enabled'] == False:
                self.cloudfront_list.append(self.create_cloudfront_item(
                    'CloudFront.5',
                    'CloudFront distributions should have logging enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response['ARN']
                ))
            else:
                self.cloudfront_list.append(self.create_cloudfront_item(
                    'CloudFront.5',
                    'CloudFront distributions should have logging enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response['ARN']
                ))

    @DecoratorClass.my_decorator
    def cloudfront_six(self) -> None:
        result_list = self.cloud_front()
        if not result_list:
            self.cloudfront_list.append(self.create_cloudfront_item(
                'CloudFront.1',
                'CloudFront distributions should have WAF enabled',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if response['DistributionConfig']['WebACLId'] == "":
                self.cloudfront_list.append(self.create_cloudfront_item(
                    'CloudFront.6',
                    'CloudFront distributions should have WAF enabled',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response['ARN']
                ))
            else:
                self.cloudfront_list.append(self.create_cloudfront_item(
                    'CloudFront.6',
                    'CloudFront distributions should have WAF enabled',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response['ARN']
                ))

    @DecoratorClass.my_decorator
    def cloudfront_seven(self) -> None:
        result_list = self.cloud_front()
        if not result_list:
            self.cloudfront_list.append(self.create_cloudfront_item(
                'CloudFront.7',
                'CloudFront distributions should use custom SSL/TLS certificates',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if response['DistributionConfig']['ViewerCertificate']['CloudFrontDefaultCertificate'] == True:
                self.cloudfront_list.append(self.create_cloudfront_item(
                    'CloudFront.7',
                    'CloudFront distributions should use custom SSL/TLS certificates',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response['ARN']
                ))
            else:
                self.cloudfront_list.append(self.create_cloudfront_item(
                    'CloudFront.7',
                    'CloudFront distributions should use custom SSL/TLS certificates',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response['ARN']
                ))

    @DecoratorClass.my_decorator
    def cloudfront_eight(self) -> None:
        result_list = self.cloud_front()
        if not result_list:
            self.cloudfront_list.append(self.create_cloudfront_item(
                'CloudFront.8',
                'CloudFront distributions should use SNI to serve HTTPS requests',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if response['DistributionConfig']['ViewerCertificate']['SSLSupportMethod'] != "sni-only":
                self.cloudfront_list.append(self.create_cloudfront_item(
                    'CloudFront.8',
                    'CloudFront distributions should use SNI to serve HTTPS requests',
                    'failed',
                    'LOW',
                    'not_available',
                    response['ARN']
                ))
            else:
                self.cloudfront_list.append(self.create_cloudfront_item(
                    'CloudFront.8',
                    'CloudFront distributions should use SNI to serve HTTPS requests',
                    'passed',
                    'LOW',
                    'not_available',
                    response['ARN']
                ))

    @DecoratorClass.my_decorator
    def cloudfront_nine(self) -> None:
        result_list = self.cloud_front()
        if not result_list:
            self.cloudfront_list.append(self.create_cloudfront_item(
                'CloudFront.9',
                'CloudFront distributions should encrypt traffic to custom origins',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            for item in response['DistributionConfig']['Origins']['Items']:
                if 'CustomOriginConfig' in item:
                    if item['CustomOriginConfig']['OriginProtocolPolicy'] != "https-only" \
                    or (item['CustomOriginConfig']['OriginProtocolPolicy'] == "match-viewer" \
                    and response['DistributionConfig']['DefaultCacheBehavior']['ViewerProtocolPolicy'] == "allow-all"):
                        self.cloudfront_list.append(self.create_cloudfront_item(
                            'CloudFront.9',
                            'CloudFront distributions should encrypt traffic to custom origins',
                            'failed',
                            'MEDIUM',
                            'not_available',
                            response['ARN']
                        ))
                    else:
                        self.cloudfront_list.append(self.create_cloudfront_item(
                            'CloudFront.9',
                            'CloudFront distributions should encrypt traffic to custom origins',
                            'passed',
                            'MEDIUM',
                            'not_available',
                            response['ARN']
                        ))

    @DecoratorClass.my_decorator
    def cloudfront_ten(self) -> None:
        result_list = self.cloud_front()
        if not result_list:
            self.cloudfront_list.append(self.create_cloudfront_item(
                'CloudFront.10',
                'CloudFront distributions should not use deprecated SSL protocols between edge locations and custom origins',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            for item in response['DistributionConfig']['Origins']['Items']:
                if 'CustomOriginConfig' in item:
                    if 'OriginSslProtocols' in item['CustomOriginConfig']:
                        if 'SSLv3' in item['CustomOriginConfig']['OriginSslProtocols']['Items']:
                            self.cloudfront_list.append(self.create_cloudfront_item(
                                'CloudFront.10',
                                'CloudFront distributions should not use deprecated SSL protocols between edge locations and custom origins',
                                'failed',
                                'MEDIUM',
                                'not_available',
                                response['ARN']
                            ))
                        else:
                            self.cloudfront_list.append(self.create_cloudfront_item(
                                'CloudFront.10',
                                'CloudFront distributions should not use deprecated SSL protocols between edge locations and custom origins',
                                'passed',
                                'MEDIUM',
                                'not_available',
                                response['ARN']
                            ))
    
    @DecoratorClass.my_decorator
    def cloudfront_twelve(self) -> None:
        result_list = self.cloud_front()
        s3_list = self.s3_bucket()
        if not result_list:
            self.cloudfront_list.append(self.create_cloudfront_item(
                'CloudFront.12',
                'CloudFront distributions should not point to non-existent S3 origins',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            for item in response['DistributionConfig']['Origins']['Items']:
                if 'S3OriginConfig' in item:
                    if item['DomainName'] not in s3_list:
                        self.cloudfront_list.append(self.create_cloudfront_item(
                            'CloudFront.12',
                            'CloudFront distributions should not point to non-existent S3 origins',
                            'failed',
                            'HIGH',
                            'not_available',
                            response['ARN']
                        ))
                    else:
                        self.cloudfront_list.append(self.create_cloudfront_item(
                            'CloudFront.12',
                            'CloudFront distributions should not point to non-existent S3 origins',
                            'passed',
                            'HIGH',
                            'not_available',
                            response['ARN']
                        ))

    @DecoratorClass.my_decorator
    def cloudfront_thirteen(self) -> None:
        result_list = self.cloud_front()
        if not result_list:
            self.cloudfront_list.append(self.create_cloudfront_item(
                'CloudFront.13',
                'CloudFront distributions should use origin access control',
                'not_found',
                'MEDIUM',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if 'OriginAccessControlId' not in response['DistributionConfig']['Origins']['Items'][0]:
                self.cloudfront_list.append(self.create_cloudfront_item(
                    'CloudFront.13',
                    'CloudFront distributions should use origin access control',
                    'failed',
                    'MEDIUM',
                    'not_available',
                    response['ARN']
                ))
            else:
                self.cloudfront_list.append(self.create_cloudfront_item(
                    'CloudFront.13',
                    'CloudFront distributions should use origin access control',
                    'passed',
                    'MEDIUM',
                    'not_available',
                    response['ARN']
                ))

    @DecoratorClass.my_decorator
    def cloudfront_fourteen(self) -> None:
        result_list = self.cloud_front()
        if not result_list:
            self.cloudfront_list.append(self.create_cloudfront_item(
                'CloudFront.14',
                'CloudFront distributions should be tagged',
                'not_found',
                'LOW',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            compliant_status = self.cloudfront_distribution_tag_list(response['ARN'])
            self.cloudfront_list.append(self.create_cloudfront_item(
                'CloudFront.14',
                'CloudFront distributions should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response['ARN']
            ))