'''
Class name CloudTrailComplianceChecker
Create functions to check compliants and return as 
'control_id': security contorl id,
'control_title': security control title,
'compliance': passed, failed or not_found,
'severity': CRITICAL, HIGH, MEDIUM or LOW,
'auto_remediation': available or not_available,
'resource_id': account id, resource arn or not_found
'''

import json, boto3 # type: ignore
from botocore.exceptions import ClientError # type: ignore
from utils.decorator_class import DecoratorClass # type: ignore
from utils.validate import ParameterValidation # type: ignore
from utils.cross_account import UseCrossAccount # type: ignore
from utils.global_data import compliance_check_list # type: ignore
from services.cloudwatch import CloudWatchAutoRemediation, CrossAccountCloudWatchAutoRemediation # type: ignore
from services.s3 import S3AutoRemediation, CrossAccountS3AutoRemediation # type: ignore
from services.iam import IAMAutoRemediation, CrossAccountIAMAutoRemediation # type: ignore
from services.kms import KMSAutoRemediation, CrossAccountKMSAutoRemediation # type: ignore
from services.sns import SNSAutoRemediation, CrossAccountSNSAutoRemediation # type: ignore

class CloudTrailComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.cloudtrail_client = boto3.client('cloudtrail')
        self.s3_client = boto3.client('s3')
        self.session_region = boto3.session.Session().region_name
        self.session_account = boto3.client('sts').get_caller_identity().get('Account')
        self.cloudtrail_list = compliance_check_list

    def create_cloudtrail_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("CloudTrail", control_id, compliance, severity, auto_remediation):
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

    def cloud_trail(self) -> list[dict]:
        try:
            cloudtrail_list: list[dict] = []
            response = self.cloudtrail_client.describe_trails()
            cloudtrail_list.extend(_ for _ in response['trailList'] if self.session_account in _['TrailARN'])
            return cloudtrail_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def cloud_trail_event_list(self) -> list[str]:
        cloudtrail_list: list[str] = []
        result_list = [_ for _ in self.cloud_trail() if _['IsMultiRegionTrail'] == True]
        try:
            for response_detail in result_list:
                response = self.cloudtrail_client.get_event_selectors(
                    TrailName=response_detail['TrailARN']
                )
                if any([_.get('IncludeManagementEvents', False) for _ in response.get('EventSelectors', {}) if _.get('ReadWriteType', '') == 'All']):
                    cloudtrail_list.append(response_detail['TrailARN'])
            return cloudtrail_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    def s3_bucket_public(self) -> list[dict]:
        result_list = self.cloud_trail()
        bucket_list: list[dict] = []
        for response in result_list:
            bucket_name = response['S3BucketName']
            try:
                bucket_response = self.s3_client.get_public_access_block(Bucket=bucket_name)
                if bucket_response['PublicAccessBlockConfiguration']['BlockPublicAcls'] \
                and bucket_response['PublicAccessBlockConfiguration']['BlockPublicPolicy']:
                    bucket_list.append({
                        'resource_id': response['TrailARN'],
                        'compliance': 'passed'
                    })
                else:
                    bucket_list.append({
                        'resource_id': response['TrailARN'],
                        'compliance': 'failed'
                    })
            except ClientError as e:
                if e.response['Error']['Code'] == 'AccessDenied':
                    bucket_list.append({
                        'resource_id': response['TrailARN'],
                        'compliance': 'not_found'
                    })
                else:
                    print(f"Error: {e}")
        return bucket_list

    def s3_bucket_logging(self) -> list[dict]:
        result_list = self.cloud_trail()
        bucket_list: list[dict] = []
        for response in result_list:
            bucket_name = response['S3BucketName']
            try:
                bucket_response = self.s3_client.get_bucket_logging(Bucket=bucket_name)
                if bucket_response.get('LoggingEnabled', "failed") != "failed":
                    bucket_list.append({
                        'resource_id': response['TrailARN'],
                        'compliance': 'passed'
                    })
                else:
                    bucket_list.append({
                        'resource_id': response['TrailARN'],
                        'compliance': 'failed'
                    })
            except ClientError as e:
                if e.response['Error']['Code'] == 'AccessDenied':
                    bucket_list.append({
                        'resource_id': response['TrailARN'],
                        'compliance': 'not_found'
                    })
                else:
                    print(f"Error: {e}")
        return bucket_list
    
    def cloudtrail_tag_list(self, trail_arn:str) -> str:
        try:
            compliant_status = "passed"
            response = self.cloudtrail_client.list_tags(
                ResourceIdList=[trail_arn]
            )
            tag_key_list = [_['Key'] for response_detail in response.get('ResourceTagList', []) for _ in response_detail.get('TagsList', [])]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""

    @DecoratorClass.my_decorator
    def cloudtrail_one(self) -> None:
        result_list = self.cloud_trail()
        cloudtrail_event_list = self.cloud_trail_event_list()
        count = len(cloudtrail_event_list)
        if not result_list:
            self.cloudtrail_list.append(self.create_cloudtrail_item(
                    'CloudTrail.1',
                    'CloudTrail should be enabled and configured with at least one multi-Region trail that includes read and write management events',
                    'not_found',
                    'HIGH',
                    'not_available',
                    'not_found'
            ))
        if count == 0:
            self.cloudtrail_list.append(self.create_cloudtrail_item(
                    'CloudTrail.1',
                    'CloudTrail should be enabled and configured with at least one multi-Region trail that includes read and write management events',
                    'failed',
                    'HIGH',
                    'not_available',
                    self.session_account
            ))
        else:
            self.cloudtrail_list.append(self.create_cloudtrail_item(
                    'CloudTrail.1',
                    'CloudTrail should be enabled and configured with at least one multi-Region trail that includes read and write management events',
                    'passed',
                    'HIGH',
                    'not_available',
                    self.session_account
            ))

    @DecoratorClass.my_decorator
    def cloudtrail_two(self) -> None:
        result_list = self.cloud_trail()
        if not result_list:
            self.cloudtrail_list.append(self.create_cloudtrail_item(
                    'CloudTrail.2',
                    'CloudTrail should have encryption at-rest enabled',
                    'not_found',
                    'MEDIUM',
                    'not_available',
                    'not_found'
            ))
        if any(['KmsKeyId' not in _ for _ in result_list]):
            self.cloudtrail_list.append(self.create_cloudtrail_item(
                'CloudTrail.2',
                'CloudTrail should have encryption at-rest enabled',
                'failed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))
        else:
            self.cloudtrail_list.append(self.create_cloudtrail_item(
                'CloudTrail.2',
                'CloudTrail should have encryption at-rest enabled',
                'failed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))

    @DecoratorClass.my_decorator
    def cloudtrail_three(self) -> None:
        result_list = self.cloud_trail()
        if not result_list:
            self.cloudtrail_list.append(self.create_cloudtrail_item(
                    'CloudTrail.3',
                    'CloudTrail should be enabled',
                    'failed',
                    'HIGH',
                    'not_available',
                    self.session_account
            ))
        else:
            self.cloudtrail_list.append(self.create_cloudtrail_item(
                    'CloudTrail.3',
                    'CloudTrail should be enabled',
                    'passed',
                    'HIGH',
                    'not_available',
                    self.session_account
            ))

    @DecoratorClass.my_decorator
    def cloudtrail_four(self) -> None:
        result_list = self.cloud_trail()
        if not result_list:
            self.cloudtrail_list.append(self.create_cloudtrail_item(
                    'CloudTrail.4',
                    'CloudTrail log file validation should be enabled',
                    'not_found',
                    'LOW',
                    'not_available',
                    'not_found'
            ))
        for response in result_list:
            if response['LogFileValidationEnabled'] != True:
                self.cloudtrail_list.append(self.create_cloudtrail_item(
                    'CloudTrail.4',
                    'CloudTrail log file validation should be enabled',
                    'failed',
                    'LOW',
                    'not_available',
                    response['TrailARN']
                ))
            else:
                self.cloudtrail_list.append(self.create_cloudtrail_item(
                    'CloudTrail.4',
                    'CloudTrail log file validation should be enabled',
                    'passed',
                    'LOW',
                    'not_available',
                    response['TrailARN']
                ))

    @DecoratorClass.my_decorator
    def cloudtrail_five(self) -> None:
        result_list = self.cloud_trail()
        if not result_list:
            self.cloudtrail_list.append(self.create_cloudtrail_item(
                    'CloudTrail.5',
                    'CloudTrail trails should be integrated with Amazon CloudWatch Logs',
                    'not_found',
                    'LOW',
                    'not_available',
                    'not_found'
            ))
        for response in result_list:
            if 'CloudWatchLogsLogGroupArn' not in response:
                self.cloudtrail_list.append(self.create_cloudtrail_item(
                    'CloudTrail.5',
                    'CloudTrail trails should be integrated with Amazon CloudWatch Logs',
                    'failed',
                    'LOW',
                    'not_available',
                    response['TrailARN']
                ))
            else:
                self.cloudtrail_list.append(self.create_cloudtrail_item(
                    'CloudTrail.5',
                    'CloudTrail trails should be integrated with Amazon CloudWatch Logs',
                    'passed',
                    'LOW',
                    'not_available',
                    response['TrailARN']
                ))

    @DecoratorClass.my_decorator
    def cloudtrail_six(self) -> None:
        result_list = self.s3_bucket_public()
        if not result_list:
            self.cloudtrail_list.append(self.create_cloudtrail_item(
                    'CloudTrail.6',
                    'Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible',
                    'not_found',
                    'CRITICAL',
                    'not_available',
                    'not_found'
            ))
        for response in result_list:
            self.cloudtrail_list.append(self.create_cloudtrail_item(
                'CloudTrail.6',
                'Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible',
                response['compliance'],
                'CRITICAL',
                'not_available',
                response['resource_id']
            ))

    @DecoratorClass.my_decorator
    def cloudtrail_seven(self) -> None:
        result_list = self.s3_bucket_logging()
        if not result_list:
            self.cloudtrail_list.append(self.create_cloudtrail_item(
                    'CloudTrail.7',
                    'Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket',
                    'not_found',
                    'LOW',
                    'not_available',
                    'not_found'
            ))
        for response in result_list:
            self.cloudtrail_list.append(self.create_cloudtrail_item(
                'CloudTrail.7',
                'Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket',
                response['compliance'],
                'LOW',
                'not_available',
                response['resource_id']
            ))

    def cloudtrail_nine(self) -> None:
        result_list = self.cloud_trail()
        if not result_list:
            self.cloudtrail_list.append(self.create_cloudtrail_item(
                    'CloudTrail.9',
                    'CloudTrail trails should be tagged',
                    'not_found',
                    'LOW',
                    'not_available',
                    'not_found'
            ))
        for response in result_list:
            compliant_status = self.cloudtrail_tag_list(response['TrailARN'])
            self.cloudtrail_list.append(self.create_cloudtrail_item(
                'CloudTrail.9',
                'CloudTrail trails should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response['TrailARN']
            ))

class CloudTrailAutoRemediation:
    def __init__(self) -> None:
        self.s3_client = boto3.client('s3')
        self.logs_client = boto3.client('logs')
        self.iam_client = boto3.client('iam')
        self.sns_client = boto3.client('sns')
        self.cloudtrail_client = boto3.client('cloudtrail')
        self.session_region = boto3.session.Session().region_name
        self.session_account = boto3.client('sts').get_caller_identity().get('Account')
        self.cloudtrail_name = "AutomateCloudTrail"
        self.bucket_name = f"automate-cloudtrail-logging-bucket-{self.session_account}"
        self.log_group_name = f"CloudTrail/AutomateLogGroup{self.session_account}"
        self.log_group_retention = 7
        self.kms_key_arn = KMSAutoRemediation().get_kms_key_arn()
        self.sns_topic_name = f"automate-cloudtrail-sns-topic-{self.session_account}"
        self.sns_subcription_email_address = ""
        self.cloudtrail_cloudwatch_policy_name = 'automate-cloudtrail-push-to-cloudwatch-policy'
        self.cloudtrail_cloudwatch_role_name = 'automate-cloudtrail-push-to-cloudwatch-role'
        self.bucket_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AWSCloudTrailAclCheck",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "cloudtrail.amazonaws.com"
                    },
                    "Action": "s3:GetBucketAcl",
                    "Resource": f"arn:aws:s3:::{self.bucket_name}",
                    "Condition": {
                        "StringEquals": {
                            "AWS:SourceArn": f"arn:aws:cloudtrail:{self.session_region}:{self.session_account}:trail/{self.cloudtrail_name}"
                        }
                    }
                },
                {
                    "Sid": "AWSCloudTrailWrite",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "cloudtrail.amazonaws.com"
                    },
                    "Action": "s3:PutObject",
                    "Resource": f"arn:aws:s3:::{self.bucket_name}/*",
                    "Condition": {
                        "StringEquals": {
                            "AWS:SourceArn": f"arn:aws:cloudtrail:{self.session_region}:{self.session_account}:trail/{self.cloudtrail_name}",
                            "s3:x-amz-acl": "bucket-owner-full-control"
                        }
                    }
                }
            ]
        })
        self.assume_role_policy_document = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "cloudtrail.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        })
        self.cloudtrail_cloudwatch_policy_document = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "logs:CreateLogStream",
                    "Resource": f"arn:aws:logs:{self.session_region}:{self.session_account}:log-group:{self.log_group_name}:*",
                    "Effect": "Allow"
                },
                {
                    "Action": "logs:PutLogEvents",
                    "Resource": f"arn:aws:logs:{self.session_region}:{self.session_account}:log-group:{self.log_group_name}:*",
                    "Effect": "Allow"
                }
            ]
        })
        self.cloudtrail_sns_access_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AWSCloudTrailSNSPolicy",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "cloudtrail.amazonaws.com"
                    },
                    "Action": "SNS:Publish",
                    "Resource": f"arn:aws:sns:{self.session_region}:{self.session_account}:{self.sns_topic_name}",
                    "Condition": {
                        "StringEquals": {
                            "AWS:SourceArn": f"arn:aws:cloudtrail:{self.session_region}:{self.session_account}:trail/{self.cloudtrail_name}"
                        }
                    }
                }
            ]
        })
        self.remediate_cloudtrail_three()

    def verify_log_group(self) -> None:
        try:
            response = self.logs_client.describe_log_groups(logGroupNamePrefix=self.log_group_name)
            if not response['logGroups']:
                CloudWatchAutoRemediation().create_cloudwatch_log_group(self.log_group_name, self.kms_key_arn, self.log_group_retention)
        except ClientError as e:
            CloudWatchAutoRemediation().create_cloudwatch_log_group(self.log_group_name, self.kms_key_arn, self.log_group_retention)

    def verify_bucket(self) -> None:
        try:
            self.s3_client.head_bucket(Bucket=self.bucket_name)
        except ClientError as e:
            S3AutoRemediation().create_bucket(self.bucket_name, self.bucket_policy, self.kms_key_arn)

    def verify_cloudtrail_cloudwatch_policy(self) -> None:
        try:
            self.iam_client.get_policy(PolicyArn=f"arn:aws:iam::{self.session_account}:policy/{self.cloudtrail_cloudwatch_policy_name}")
        except ClientError as e:
            IAMAutoRemediation().create_iam_policy(self.cloudtrail_cloudwatch_policy_name, self.cloudtrail_cloudwatch_policy_document)

    def verify_cloudtrail_cloudwatch_role(self) -> None:
        try:
            self.iam_client.get_role(RoleName=self.cloudtrail_cloudwatch_role_name)
        except ClientError as e:
            IAMAutoRemediation().create_iam_role(self.cloudtrail_cloudwatch_role_name, self.assume_role_policy_document)
            IAMAutoRemediation().attach_policy_to_role(self.cloudtrail_cloudwatch_role_name, f"arn:aws:iam::{self.session_account}:policy/{self.cloudtrail_cloudwatch_policy_name}")

    def verify_sns(self) -> None:
        try:
            self.sns_client.get_topic_attributes(TopicArn=f"arn:aws:sns:{self.session_region}:{self.session_account}:{self.sns_topic_name}")
        except ClientError as e:
            SNSAutoRemediation().create_sns_topic(self.sns_topic_name, self.kms_key_arn)
            SNSAutoRemediation().create_sns_subscription(f"arn:aws:sns:{self.session_region}:{self.session_account}:{self.sns_topic_name}", self.sns_subcription_email_address)
            SNSAutoRemediation().set_sns_topic_attribute(f"arn:aws:sns:{self.session_region}:{self.session_account}:{self.sns_topic_name}", self.cloudtrail_sns_access_policy)

    def is_cloud_trail_enable(self) -> bool:
        try:
            trail_list = [_ for _ in self.cloudtrail_client.describe_trails()['trailList'] if _['IsOrganizationTrail'] == False]
            if not trail_list:
                return False
            else:
                return True
        except ClientError as e:
            return False

    def remediate_cloudtrail_three(self) -> None:
        if not self.is_cloud_trail_enable():
            self.verify_log_group()
            self.verify_bucket()
            self.verify_cloudtrail_cloudwatch_policy()
            self.verify_cloudtrail_cloudwatch_role()
            self.verify_sns()
            try:
                self.cloudtrail_client.create_trail(
                    Name=self.cloudtrail_name,
                    S3BucketName=self.bucket_name,
                    SnsTopicName=self.sns_topic_name,
                    IsMultiRegionTrail=True,
                    IncludeGlobalServiceEvents=True,
                    EnableLogFileValidation=True,
                    CloudWatchLogsLogGroupArn=f"arn:aws:logs:{self.session_region}:{self.session_account}:log-group:{self.log_group_name}:*",
                    CloudWatchLogsRoleArn=f"arn:aws:iam::{self.session_account}:role/{self.cloudtrail_cloudwatch_role_name}",
                    KmsKeyId=KMSAutoRemediation().get_kms_key_arn(),
                    TagsList=[{"Key": "", "Value": ""}]
                )
                self.cloudtrail_client.start_logging(Name=self.cloudtrail_name)
                self.cloudtrail_client.put_event_selectors(
                    TrailName=self.cloudtrail_name,
                    EventSelectors=[
                        {
                            'ReadWriteType': 'All',
                            'IncludeManagementEvents': True,
                            'DataResources': [
                                {
                                    'Type': 'AWS::S3::Object',
                                    'Values': [
                                        f"arn:aws:s3:::{self.bucket_name}/*"
                                    ]
                                }
                            ]
                        }
                    ]
                )
                print(f"Auto remediated for CloudTrail.3: {self.session_account}")
            except ClientError as e:
                print(f"Error: {e}")

class CrossAccountCloudTrailComplianceChecker:
    def __init__(self) -> None:
        self.require_tag_keys = ParameterValidation().require_tag_key()
        self.cloudtrail_client = UseCrossAccount().client('cloudtrail')
        self.s3_client = UseCrossAccount().client('s3')
        self.session_region = UseCrossAccount().session_region_name
        self.session_account = UseCrossAccount().client('sts').get_caller_identity().get('Account')
        self.cloudtrail_list = compliance_check_list

    def create_cloudtrail_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("CloudTrail", control_id, compliance, severity, auto_remediation):
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

    def cloud_trail(self) -> list[dict]:
        try:
            cloudtrail_list: list[dict] = []
            response = self.cloudtrail_client.describe_trails()
            cloudtrail_list.extend(_ for _ in response['trailList'] if self.session_account in _['TrailARN'])
            return cloudtrail_list
        except ClientError as e:
            print(f"Error: {e}")
            return []
        
    def cloud_trail_event_list(self) -> list[str]:
        cloudtrail_list: list[str] = []
        result_list = [_ for _ in self.cloud_trail() if _['IsMultiRegionTrail'] == True]
        try:
            for response_detail in result_list:
                response = self.cloudtrail_client.get_event_selectors(
                    TrailName=response_detail['TrailARN']
                )
                if any([_.get('IncludeManagementEvents', False) for _ in response.get('EventSelectors', {}) if _.get('ReadWriteType', '') == 'All']):
                    cloudtrail_list.append(response_detail['TrailARN'])
            return cloudtrail_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    def s3_bucket_public(self) -> list[dict]:
        result_list = self.cloud_trail()
        bucket_list: list[dict] = []
        for response in result_list:
            bucket_name = response['S3BucketName']
            try:
                bucket_response = self.s3_client.get_public_access_block(Bucket=bucket_name)
                if bucket_response['PublicAccessBlockConfiguration']['BlockPublicAcls'] \
                and bucket_response['PublicAccessBlockConfiguration']['BlockPublicPolicy']:
                    bucket_list.append({
                        'resource_id': response['TrailARN'],
                        'compliance': 'passed'
                    })
                else:
                    bucket_list.append({
                        'resource_id': response['TrailARN'],
                        'compliance': 'failed'
                    })
            except ClientError as e:
                if e.response['Error']['Code'] == 'AccessDenied':
                    bucket_list.append({
                        'resource_id': response['TrailARN'],
                        'compliance': 'not_found'
                    })
                else:
                    print(f"Error: {e}")
        return bucket_list

    def s3_bucket_logging(self) -> list[dict]:
        result_list = self.cloud_trail()
        bucket_list: list[dict] = []
        for response in result_list:
            bucket_name = response['S3BucketName']
            try:
                bucket_response = self.s3_client.get_bucket_logging(Bucket=bucket_name)
                if bucket_response.get('LoggingEnabled', "failed") != "failed":
                    bucket_list.append({
                        'resource_id': response['TrailARN'],
                        'compliance': 'passed'
                    })
                else:
                    bucket_list.append({
                        'resource_id': response['TrailARN'],
                        'compliance': 'failed'
                    })
            except ClientError as e:
                if e.response['Error']['Code'] == 'AccessDenied':
                    bucket_list.append({
                        'resource_id': response['TrailARN'],
                        'compliance': 'not_found'
                    })
                else:
                    print(f"Error: {e}")
        return bucket_list
    
    def cloudtrail_tag_list(self, trail_arn:str) -> str:
        try:
            compliant_status = "passed"
            response = self.cloudtrail_client.list_tags(
                ResourceIdList=[trail_arn]
            )
            tag_key_list = [_['Key'] for response_detail in response.get('ResourceTagList', []) for _ in response_detail.get('TagsList', [])]
            if list(set(self.require_tag_keys) - set(tag_key_list)):
                compliant_status = "failed"
            return compliant_status
        except ClientError as e:
            print(f"Error: {e}")
            return ""

    @DecoratorClass.my_decorator
    def cloudtrail_one(self) -> None:
        result_list = self.cloud_trail()
        cloudtrail_event_list = self.cloud_trail_event_list()
        count = len(cloudtrail_event_list)
        if not result_list:
            self.cloudtrail_list.append(self.create_cloudtrail_item(
                    'CloudTrail.1',
                    'CloudTrail should be enabled and configured with at least one multi-Region trail that includes read and write management events',
                    'not_found',
                    'HIGH',
                    'not_available',
                    'not_found'
            ))
        if count == 0:
            self.cloudtrail_list.append(self.create_cloudtrail_item(
                    'CloudTrail.1',
                    'CloudTrail should be enabled and configured with at least one multi-Region trail that includes read and write management events',
                    'failed',
                    'HIGH',
                    'not_available',
                    self.session_account
            ))
        else:
            self.cloudtrail_list.append(self.create_cloudtrail_item(
                    'CloudTrail.1',
                    'CloudTrail should be enabled and configured with at least one multi-Region trail that includes read and write management events',
                    'passed',
                    'HIGH',
                    'not_available',
                    self.session_account
            ))

    @DecoratorClass.my_decorator
    def cloudtrail_two(self) -> None:
        result_list = self.cloud_trail()
        if not result_list:
            self.cloudtrail_list.append(self.create_cloudtrail_item(
                    'CloudTrail.2',
                    'CloudTrail should have encryption at-rest enabled',
                    'not_found',
                    'MEDIUM',
                    'not_available',
                    'not_found'
            ))
        if any(['KmsKeyId' not in _ for _ in result_list]):
            self.cloudtrail_list.append(self.create_cloudtrail_item(
                'CloudTrail.2',
                'CloudTrail should have encryption at-rest enabled',
                'failed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))
        else:
            self.cloudtrail_list.append(self.create_cloudtrail_item(
                'CloudTrail.2',
                'CloudTrail should have encryption at-rest enabled',
                'failed',
                'MEDIUM',
                'not_available',
                self.session_account
            ))

    @DecoratorClass.my_decorator
    def cloudtrail_three(self) -> None:
        result_list = self.cloud_trail()
        if not result_list:
            self.cloudtrail_list.append(self.create_cloudtrail_item(
                    'CloudTrail.3',
                    'CloudTrail should be enabled',
                    'failed',
                    'HIGH',
                    'not_available',
                    self.session_account
            ))
        else:
            self.cloudtrail_list.append(self.create_cloudtrail_item(
                    'CloudTrail.3',
                    'CloudTrail should be enabled',
                    'passed',
                    'HIGH',
                    'not_available',
                    self.session_account
            ))

    @DecoratorClass.my_decorator
    def cloudtrail_four(self) -> None:
        result_list = self.cloud_trail()
        if not result_list:
            self.cloudtrail_list.append(self.create_cloudtrail_item(
                    'CloudTrail.4',
                    'CloudTrail log file validation should be enabled',
                    'not_found',
                    'LOW',
                    'not_available',
                    'not_found'
            ))
        for response in result_list:
            if response['LogFileValidationEnabled'] != True:
                self.cloudtrail_list.append(self.create_cloudtrail_item(
                    'CloudTrail.4',
                    'CloudTrail log file validation should be enabled',
                    'failed',
                    'LOW',
                    'not_available',
                    response['TrailARN']
                ))
            else:
                self.cloudtrail_list.append(self.create_cloudtrail_item(
                    'CloudTrail.4',
                    'CloudTrail log file validation should be enabled',
                    'passed',
                    'LOW',
                    'not_available',
                    response['TrailARN']
                ))

    @DecoratorClass.my_decorator
    def cloudtrail_five(self) -> None:
        result_list = self.cloud_trail()
        if not result_list:
            self.cloudtrail_list.append(self.create_cloudtrail_item(
                    'CloudTrail.5',
                    'CloudTrail trails should be integrated with Amazon CloudWatch Logs',
                    'not_found',
                    'LOW',
                    'not_available',
                    'not_found'
            ))
        for response in result_list:
            if 'CloudWatchLogsLogGroupArn' not in response:
                self.cloudtrail_list.append(self.create_cloudtrail_item(
                    'CloudTrail.5',
                    'CloudTrail trails should be integrated with Amazon CloudWatch Logs',
                    'failed',
                    'LOW',
                    'not_available',
                    response['TrailARN']
                ))
            else:
                self.cloudtrail_list.append(self.create_cloudtrail_item(
                    'CloudTrail.5',
                    'CloudTrail trails should be integrated with Amazon CloudWatch Logs',
                    'passed',
                    'LOW',
                    'not_available',
                    response['TrailARN']
                ))

    @DecoratorClass.my_decorator
    def cloudtrail_six(self) -> None:
        result_list = self.s3_bucket_public()
        if not result_list:
            self.cloudtrail_list.append(self.create_cloudtrail_item(
                    'CloudTrail.6',
                    'Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible',
                    'not_found',
                    'CRITICAL',
                    'not_available',
                    'not_found'
            ))
        for response in result_list:
            self.cloudtrail_list.append(self.create_cloudtrail_item(
                'CloudTrail.6',
                'Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible',
                response['compliance'],
                'CRITICAL',
                'not_available',
                response['resource_id']
            ))

    @DecoratorClass.my_decorator
    def cloudtrail_seven(self) -> None:
        result_list = self.s3_bucket_logging()
        if not result_list:
            self.cloudtrail_list.append(self.create_cloudtrail_item(
                    'CloudTrail.7',
                    'Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket',
                    'not_found',
                    'LOW',
                    'not_available',
                    'not_found'
            ))
        for response in result_list:
            self.cloudtrail_list.append(self.create_cloudtrail_item(
                'CloudTrail.7',
                'Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket',
                response['compliance'],
                'LOW',
                'not_available',
                response['resource_id']
            ))

    def cloudtrail_nine(self) -> None:
        result_list = self.cloud_trail()
        if not result_list:
            self.cloudtrail_list.append(self.create_cloudtrail_item(
                    'CloudTrail.9',
                    'CloudTrail trails should be tagged',
                    'not_found',
                    'LOW',
                    'not_available',
                    'not_found'
            ))
        for response in result_list:
            compliant_status = self.cloudtrail_tag_list(response['TrailARN'])
            self.cloudtrail_list.append(self.create_cloudtrail_item(
                'CloudTrail.9',
                'CloudTrail trails should be tagged',
                compliant_status,
                'LOW',
                'not_available',
                response['TrailARN']
            ))

class CrossAccountCloudTrailAutoRemediation:
    def __init__(self) -> None:
        self.s3_client = UseCrossAccount().client('s3')
        self.logs_client = UseCrossAccount().client('logs')
        self.iam_client = UseCrossAccount().client('iam')
        self.sns_client = UseCrossAccount().client('sns')
        self.cloudtrail_client = UseCrossAccount().client('cloudtrail')
        self.session_region = UseCrossAccount().session_region_name
        self.session_account = UseCrossAccount().client('sts').get_caller_identity().get('Account')
        self.cloudtrail_name = "AutomateCloudTrail"
        self.bucket_name = f"automate-cloudtrail-logging-bucket-{self.session_account}"
        self.log_group_name = f"CloudTrail/AutomateLogGroup{self.session_account}"
        self.log_group_retention = 7
        self.kms_key_arn = CrossAccountKMSAutoRemediation().get_kms_key_arn()
        self.sns_topic_name = f"automate-cloudtrail-sns-topic-{self.session_account}"
        self.sns_subcription_email_address = ""
        self.cloudtrail_cloudwatch_policy_name = 'automate-cloudtrail-push-to-cloudwatch-policy'
        self.cloudtrail_cloudwatch_role_name = 'automate-cloudtrail-push-to-cloudwatch-role'
        self.bucket_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AWSCloudTrailAclCheck",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "cloudtrail.amazonaws.com"
                    },
                    "Action": "s3:GetBucketAcl",
                    "Resource": f"arn:aws:s3:::{self.bucket_name}",
                    "Condition": {
                        "StringEquals": {
                            "AWS:SourceArn": f"arn:aws:cloudtrail:{self.session_region}:{self.session_account}:trail/{self.cloudtrail_name}"
                        }
                    }
                },
                {
                    "Sid": "AWSCloudTrailWrite",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "cloudtrail.amazonaws.com"
                    },
                    "Action": "s3:PutObject",
                    "Resource": f"arn:aws:s3:::{self.bucket_name}/*",
                    "Condition": {
                        "StringEquals": {
                            "AWS:SourceArn": f"arn:aws:cloudtrail:{self.session_region}:{self.session_account}:trail/{self.cloudtrail_name}",
                            "s3:x-amz-acl": "bucket-owner-full-control"
                        }
                    }
                }
            ]
        })
        self.assume_role_policy_document = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "cloudtrail.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        })
        self.cloudtrail_cloudwatch_policy_document = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "logs:CreateLogStream",
                    "Resource": f"arn:aws:logs:{self.session_region}:{self.session_account}:log-group:{self.log_group_name}:*",
                    "Effect": "Allow"
                },
                {
                    "Action": "logs:PutLogEvents",
                    "Resource": f"arn:aws:logs:{self.session_region}:{self.session_account}:log-group:{self.log_group_name}:*",
                    "Effect": "Allow"
                }
            ]
        })
        self.cloudtrail_sns_access_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AWSCloudTrailSNSPolicy",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "cloudtrail.amazonaws.com"
                    },
                    "Action": "SNS:Publish",
                    "Resource": f"arn:aws:sns:{self.session_region}:{self.session_account}:{self.sns_topic_name}",
                    "Condition": {
                        "StringEquals": {
                            "AWS:SourceArn": f"arn:aws:cloudtrail:{self.session_region}:{self.session_account}:trail/{self.cloudtrail_name}"
                        }
                    }
                }
            ]
        })
        self.remediate_cloudtrail_three()

    def verify_log_group(self) -> None:
        try:
            response = self.logs_client.describe_log_groups(logGroupNamePrefix=self.log_group_name)
            if not response['logGroups']:
                CrossAccountCloudWatchAutoRemediation().create_cloudwatch_log_group(self.log_group_name, self.kms_key_arn, self.log_group_retention)
        except ClientError as e:
            CrossAccountCloudWatchAutoRemediation().create_cloudwatch_log_group(self.log_group_name, self.kms_key_arn, self.log_group_retention)

    def verify_bucket(self) -> None:
        try:
            self.s3_client.head_bucket(Bucket=self.bucket_name)
        except ClientError as e:
            CrossAccountS3AutoRemediation().create_bucket(self.bucket_name, self.bucket_policy, self.kms_key_arn)

    def verify_cloudtrail_cloudwatch_policy(self) -> None:
        try:
            self.iam_client.get_policy(PolicyArn=f"arn:aws:iam::{self.session_account}:policy/{self.cloudtrail_cloudwatch_policy_name}")
        except ClientError as e:
            CrossAccountIAMAutoRemediation().create_iam_policy(self.cloudtrail_cloudwatch_policy_name, self.cloudtrail_cloudwatch_policy_document)

    def verify_cloudtrail_cloudwatch_role(self) -> None:
        try:
            self.iam_client.get_role(RoleName=self.cloudtrail_cloudwatch_role_name)
        except ClientError as e:
            CrossAccountIAMAutoRemediation().create_iam_role(self.cloudtrail_cloudwatch_role_name, self.assume_role_policy_document)
            CrossAccountIAMAutoRemediation().attach_policy_to_role(self.cloudtrail_cloudwatch_role_name, f"arn:aws:iam::{self.session_account}:policy/{self.cloudtrail_cloudwatch_policy_name}")

    def verify_sns(self) -> None:
        try:
            self.sns_client.get_topic_attributes(TopicArn=f"arn:aws:sns:{self.session_region}:{self.session_account}:{self.sns_topic_name}")
        except ClientError as e:
            CrossAccountSNSAutoRemediation().create_sns_topic(self.sns_topic_name, self.kms_key_arn)
            CrossAccountSNSAutoRemediation().create_sns_subscription(f"arn:aws:sns:{self.session_region}:{self.session_account}:{self.sns_topic_name}", self.sns_subcription_email_address)
            CrossAccountSNSAutoRemediation().set_sns_topic_attribute(f"arn:aws:sns:{self.session_region}:{self.session_account}:{self.sns_topic_name}", self.cloudtrail_sns_access_policy)

    def is_cloud_trail_enable(self) -> bool:
        try:
            trail_list = [_ for _ in self.cloudtrail_client.describe_trails()['trailList'] if _['IsOrganizationTrail'] == False]
            if not trail_list:
                return False
            else:
                return True
        except ClientError as e:
            return False

    def remediate_cloudtrail_three(self) -> None:
        if not self.is_cloud_trail_enable():
            self.verify_log_group()
            self.verify_bucket()
            self.verify_cloudtrail_cloudwatch_policy()
            self.verify_cloudtrail_cloudwatch_role()
            self.verify_sns()
            try:
                self.cloudtrail_client.create_trail(
                    Name=self.cloudtrail_name,
                    S3BucketName=self.bucket_name,
                    SnsTopicName=self.sns_topic_name,
                    IsMultiRegionTrail=True,
                    IncludeGlobalServiceEvents=True,
                    EnableLogFileValidation=True,
                    CloudWatchLogsLogGroupArn=f"arn:aws:logs:{self.session_region}:{self.session_account}:log-group:{self.log_group_name}:*",
                    CloudWatchLogsRoleArn=f"arn:aws:iam::{self.session_account}:role/{self.cloudtrail_cloudwatch_role_name}",
                    KmsKeyId=KMSAutoRemediation().get_kms_key_arn(),
                    TagsList=[{"Key": "", "Value": ""}]
                )
                self.cloudtrail_client.start_logging(Name=self.cloudtrail_name)
                self.cloudtrail_client.put_event_selectors(
                    TrailName=self.cloudtrail_name,
                    EventSelectors=[
                        {
                            'ReadWriteType': 'All',
                            'IncludeManagementEvents': True,
                            'DataResources': [
                                {
                                    'Type': 'AWS::S3::Object',
                                    'Values': [
                                        f"arn:aws:s3:::{self.bucket_name}/*"
                                    ]
                                }
                            ]
                        }
                    ]
                )
                print(f"Auto remediated for CloudTrail.3: {self.session_account}")
            except ClientError as e:
                print(f"Error: {e}")