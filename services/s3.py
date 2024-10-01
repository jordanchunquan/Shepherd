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
from services.kms import KMSAutoRemediation, CrossAccountKMSAutoRemediation # type: ignore

class S3AutoRemediation:
    def __init__(self) -> None:
        self.s3_client = boto3.client('s3')
        
    def create_bucket(self, bucket_name: str, bucket_policy: str, kms_key_arn: str) -> None:
        try:
            self.s3_client.create_bucket(
                ACL='private',
                Bucket=bucket_name,
                CreateBucketConfiguration={
                    "LocationConstraint": "ap-southeast-1",
                },
                ObjectLockEnabledForBucket=True
            )
            self.s3_client.put_bucket_encryption(
                Bucket=bucket_name,
                ServerSideEncryptionConfiguration={
                    'Rules': [
                        {
                            'ApplyServerSideEncryptionByDefault': {
                                'SSEAlgorithm': 'aws:kms',
                                'KMSMasterKeyID': kms_key_arn
                            }
                        }
                    ]
                }
            )
            self.s3_client.put_bucket_policy(
                Bucket=bucket_name,
                Policy=bucket_policy
            )
            print(f"Bucket created: {bucket_name}")
        except ClientError as e:
            print(f"Error: {e}")

class CrossAccountS3AutoRemediation:
    def __init__(self) -> None:
        self.s3_client = UseCrossAccount().client('s3')
        
    def create_bucket(self, bucket_name: str, bucket_policy: str, kms_key_arn: str) -> None:
        try:
            self.s3_client.create_bucket(
                ACL='private',
                Bucket=bucket_name,
                CreateBucketConfiguration={
                    "LocationConstraint": "ap-southeast-1",
                },
                ObjectLockEnabledForBucket=True
            )
            self.s3_client.put_bucket_encryption(
                Bucket=bucket_name,
                ServerSideEncryptionConfiguration={
                    'Rules': [
                        {
                            'ApplyServerSideEncryptionByDefault': {
                                'SSEAlgorithm': 'aws:kms',
                                'KMSMasterKeyID': kms_key_arn
                            }
                        }
                    ]
                }
            )
            self.s3_client.put_bucket_policy(
                Bucket=bucket_name,
                Policy=bucket_policy
            )
            print(f"Bucket created: {bucket_name}")
        except ClientError as e:
            print(f"Error: {e}")