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

class SNSAutoRemediation:
    def __init__(self) -> None:
        self.sns_client = boto3.client('sns')
        
    def create_sns_topic(self, sns_topic_name, kms_key_arn) -> None:
        try:
            self.sns_client.create_topic(
                Name=sns_topic_name,
                Attributes={
                    'KmsMasterKeyId': kms_key_arn,
                }
            )
            print(f"SNS topic created: {sns_topic_name}")
        except ClientError as e:
            print(f"Error: {e}")

    def create_sns_subscription(self, sns_topic_arn, subcription_email_address) -> None:
        try:
            self.sns_client.subscribe(
                TopicArn=sns_topic_arn,
                Protocol='email',
                Endpoint=subcription_email_address,
            )
            print(f"SNS subcription created: {subcription_email_address}")
        except ClientError as e:
            print(f"Error: {e}")

    def set_sns_topic_attribute(self, sns_topic_arn, sns_access_policy) -> None:
        try:
            self.sns_client.set_topic_attributes(
                TopicArn=sns_topic_arn,
                AttributeName="Policy",
                AttributeValue=sns_access_policy
            )
        except ClientError as e:
            print(f"Error: {e}")

class CrossAccountSNSAutoRemediation:
    def __init__(self) -> None:
        self.sns_client = UseCrossAccount().client('sns')
        
    def create_sns_topic(self, sns_topic_name, kms_key_arn) -> None:
        try:
            self.sns_client.create_topic(
                Name=sns_topic_name,
                Attributes={
                    'KmsMasterKeyId': kms_key_arn,
                }
            )
            print(f"SNS topic created: {sns_topic_name}")
        except ClientError as e:
            print(f"Error: {e}")

    def create_sns_subscription(self, sns_topic_arn, subcription_email_address) -> None:
        try:
            self.sns_client.subscribe(
                TopicArn=sns_topic_arn,
                Protocol='email',
                Endpoint=subcription_email_address,
            )
            print(f"SNS subcription created: {subcription_email_address}")
        except ClientError as e:
            print(f"Error: {e}")

    def set_sns_topic_attribute(self, sns_topic_arn, sns_access_policy) -> None:
        try:
            self.sns_client.set_topic_attributes(
                TopicArn=sns_topic_arn,
                AttributeName="Policy",
                AttributeValue=sns_access_policy
            )
        except ClientError as e:
            print(f"Error: {e}")