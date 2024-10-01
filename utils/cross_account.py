import os, boto3
from botocore.exceptions import ClientError

class UseCrossAccount:
    def __init__(self) -> None:
        cross_account_id: str = os.environ.get('AWS_ACCOUNT_ID')
        cross_account_role: str = os.environ.get('AWS_ACCOUNT_ROLE')
        self.account_assume_role: dict = boto3.client('sts').assume_role(RoleArn=f'arn:aws:iam::{cross_account_id}:role/{cross_account_role}', RoleSessionName=cross_account_role)
        self.aws_access_key_id: str = self.account_assume_role['Credentials']['AccessKeyId']
        self.aws_secret_access_key: str = self.account_assume_role['Credentials']['SecretAccessKey']
        self.aws_session_token: str = self.account_assume_role['Credentials']['SessionToken']
        self.session_region_name: str = boto3.session.Session(aws_access_key_id=self.aws_access_key_id, aws_secret_access_key=self.aws_secret_access_key, aws_session_token=self.aws_session_token).region_name

    def account_assume_role(self) -> dict:
        try:
            client = boto3.client('sts')
            response = client.assume_role(
                RoleArn=f'arn:aws:iam::{self.cross_account_id}:role/security_aws_scanner_role',
                RoleSessionName='security_aws_scanner_role'
            )
            return response
        except ClientError as e:
            print(e)
            return {
                'Error': e
            }
        
    def client(self, service: str) -> boto3.client:
        return boto3.client(service, aws_access_key_id=self.aws_access_key_id, aws_secret_access_key=self.aws_secret_access_key, aws_session_token=self.aws_session_token)