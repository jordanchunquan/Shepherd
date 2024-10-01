'''
Class name CloudWatchComplianceChecker
Create functions to check compliants and return as 
'control_id': security contorl id,
'control_title': security control title,
'compliance': passed, failed or not_found,
'severity': CRITICAL, HIGH, MEDIUM or LOW,
'auto_remediation': available or not_available,
'resource_id': account id, resource arn or not_found

Autoremediate CLOUDWATCH_LOG_GROUP_ENCRYPTED by enabling encryption for all log groups
'''

import boto3 # type: ignore
from botocore.exceptions import ClientError # type: ignore
from utils.decorator_class import DecoratorClass # type: ignore
from utils.validate import ParameterValidation # type: ignore
from utils.cross_account import UseCrossAccount # type: ignore
from utils.global_data import compliance_check_list # type: ignore
from services.kms import KMSAutoRemediation, CrossAccountKMSAutoRemediation # type: ignore

class CloudWatchComplianceChecker:
    def __init__(self) -> None:
        self.logs_client = boto3.client('logs')
        self.sns_client = boto3.client('sns')
        self.cloudwatch_client = boto3.client('cloudwatch')
        self.session_account = boto3.client('sts').get_caller_identity().get('Account')
        self.cloudwatch_list = compliance_check_list

    def create_cloudwatch_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("CloudWatch", control_id, compliance, severity, auto_remediation):
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

    def cloud_watch(self) -> list[dict]:
        cloudwatch_list: list[dict] = []
        response = self.logs_client.describe_metric_filters()
        cloudwatch_list.extend([_ for _ in response['metricFilters']])
        while 'nextToken' in response:
            response = self.logs_client.describe_metric_filters(nextToken=response['nextToken'])
            cloudwatch_list.extend([_ for _ in response['metricFilters']])
        return cloudwatch_list

    def sns_subcription(self) -> list[str]:
        sns_list: list[str] = []
        try:
            response = self.sns_client.list_topics()
            for topic in response['Topics']:
                subcription_response = self.sns_client.list_subscriptions_by_topic(TopicArn=topic['TopicArn'])
                sns_list.extend([topic['TopicArn'] \
                                for _ in subcription_response['Subscriptions'] \
                                if subcription_response != [] \
                                and _['SubscriptionArn'] != 'PendingConfirmation'])
                while 'NextToken' in subcription_response:
                    subcription_response = self.sns_client.list_subscriptions_by_topic(TopicArn=topic['TopicArn'], \
                                                                                        NextToken=subcription_response['NextToken'])
                    sns_list.extend([topic['TopicArn'] \
                                    for _ in subcription_response['Subscriptions'] \
                                    if subcription_response != [] \
                                    and _['SubscriptionArn'] != 'PendingConfirmation'])
            while 'NextToken' in response:
                response = self.sns_client.list_topics(NextToken=response['NextToken'])
                for topic in response['Topics']:
                    subcription_response = self.sns_client.list_subscriptions_by_topic(TopicArn=topic['TopicArn'])
                    sns_list.extend([topic['TopicArn'] \
                                    for _ in subcription_response['Subscriptions'] \
                                    if subcription_response != [] \
                                    and _['SubscriptionArn'] != 'PendingConfirmation'])
                    while 'NextToken' in subcription_response:
                        subcription_response = self.sns_client.list_subscriptions_by_topic(TopicArn=topic['TopicArn'], \
                                                                                            NextToken=subcription_response['NextToken'])
                        sns_list.extend([topic['TopicArn'] \
                                        for _ in subcription_response['Subscriptions'] \
                                        if subcription_response != [] \
                                        and _['SubscriptionArn'] != 'PendingConfirmation'])
            return sns_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    def cloudwatch_alarm(self, metric_name: str, metric_namespace: str) -> bool:
        sns_list = self.sns_subcription()
        response = self.cloudwatch_client.describe_alarms_for_metric(MetricName=metric_name, Namespace=metric_namespace)
        return any(_ in sns_list for alarm in response['MetricAlarms'] for _ in alarm['AlarmActions'])
    
    def get_compliant_status(self, filter_pattern: str) -> str:
        result_list = self.cloud_watch()
        # Failed if no CloudWatch metric with filter pattern or alarm else passed
        compliant_status = 'failed' \
            if sum(1 for _ in result_list if _['filterPattern'] == filter_pattern \
            for metric in _['metricTransformations']
            if self.cloudwatch_alarm(metric['metricName'], metric['metricNamespace'])) == 0 \
            else 'passed'
        return compliant_status
    
    def cloudwatch_alarm_action(self) -> list[dict]:
        alarm_action_list: list[dict] = []
        try:
            response = self.cloudwatch_client.describe_alarms()
            alarm_action_list.extend(_ for _ in response['MetricAlarms'])
            while 'NextToken' in response:
                response = self.cloudwatch_client.describe_alarms(NextToken=response['NextToken'])
                alarm_action_list.extend(_ for _ in response['MetricAlarms'])
            return alarm_action_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    def cloudwatch_log_group(self) -> list[dict]:
        log_group_list: list[dict] = []
        try:
            response = self.logs_client.describe_log_groups()
            log_group_list.extend(_ for _ in response['logGroups'])
            while 'nextToken' in response:
                response = self.logs_client.describe_log_groups(nextToken=response['nextToken'])
                log_group_list.extend(_ for _ in response['logGroups'])
            return log_group_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    @DecoratorClass.my_decorator
    def cloudwatch_one(self) -> None:
        compliant_status = self.get_compliant_status(
            '{$.userIdentity.type=\"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !=\"AwsServiceEvent\"}'
            )
        self.cloudwatch_list.append(self.create_cloudwatch_item(
            'CloudWatch.1',
            'A log metric filter and alarm should exist for usage of the "root" user',
            compliant_status,
            'LOW',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def cloudwatch_two(self) -> None:
        compliant_status = self.get_compliant_status(
            '{($.errorCode="*UnauthorizedOperation") || ($.errorCode="AccessDenied*")}'
            )
        self.cloudwatch_list.append(self.create_cloudwatch_item(
            'CloudWatch.2',
            'Ensure a log metric filter and alarm exist for unauthorized API calls',
            compliant_status,
            'LOW',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def cloudwatch_three(self) -> None:
        compliant_status = self.get_compliant_status(
            '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") && ($.userIdentity.type = "IAMUser") && ($.responseElements.ConsoleLogin = "Success") }'
            )
        self.cloudwatch_list.append(self.create_cloudwatch_item(
            'CloudWatch.3',
            'Ensure a log metric filter and alarm exist for Management Console sign-in without MFA',
            compliant_status,
            'LOW',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def cloudwatch_four(self) -> None:
        compliant_status = self.get_compliant_status(
            '{($.eventSource=iam.amazonaws.com) && (($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy) || ($.eventName=DetachGroupPolicy))}'
            )
        self.cloudwatch_list.append(self.create_cloudwatch_item(
            'CloudWatch.4',
            'Ensure a log metric filter and alarm exist for IAM policy changes',
            compliant_status,
            'LOW',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def cloudwatch_five(self) -> None:
        compliant_status = self.get_compliant_status(
            '{($.eventName=CreateTrail) || ($.eventName=UpdateTrail) || ($.eventName=DeleteTrail) || ($.eventName=StartLogging) || ($.eventName=StopLogging)}'
            )
        self.cloudwatch_list.append(self.create_cloudwatch_item(
            'CloudWatch.5',
            'Ensure a log metric filter and alarm exist for CloudTrail configuration changes',
            compliant_status,
            'LOW',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def cloudwatch_six(self) -> None:
        compliant_status = self.get_compliant_status(
            '{($.eventName=ConsoleLogin) && ($.errorMessage="Failed authentication")}'
            )
        self.cloudwatch_list.append(self.create_cloudwatch_item(
            'CloudWatch.6',
            'Ensure a log metric filter and alarm exist for AWS Management Console authentication failures',
            compliant_status,
            'LOW',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def cloudwatch_seven(self) -> None:
        compliant_status = self.get_compliant_status(
            '{($.eventSource=kms.amazonaws.com) && (($.eventName=DisableKey) || ($.eventName=ScheduleKeyDeletion))}'
            )
        self.cloudwatch_list.append(self.create_cloudwatch_item(
            'CloudWatch.7',
            'Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs',
            compliant_status,
            'LOW',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def cloudwatch_eight(self) -> None:
        compliant_status = self.get_compliant_status(
            '{($.eventSource=s3.amazonaws.com) && (($.eventName=PutBucketAcl) || ($.eventName=PutBucketPolicy) || ($.eventName=PutBucketCors) || ($.eventName=PutBucketLifecycle) || ($.eventName=PutBucketReplication) || ($.eventName=DeleteBucketPolicy) || ($.eventName=DeleteBucketCors) || ($.eventName=DeleteBucketLifecycle) || ($.eventName=DeleteBucketReplication))}'
            )
        self.cloudwatch_list.append(self.create_cloudwatch_item(
            'CloudWatch.8',
            'Ensure a log metric filter and alarm exist for S3 bucket policy changes',
            compliant_status,
            'LOW',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def cloudwatch_nine(self) -> None:
        compliant_status = self.get_compliant_status(
            '{($.eventSource=config.amazonaws.com) && (($.eventName=StopConfigurationRecorder) || ($.eventName=DeleteDeliveryChannel) || ($.eventName=PutDeliveryChannel) || ($.eventName=PutConfigurationRecorder))}'
            )
        self.cloudwatch_list.append(self.create_cloudwatch_item(
            'CloudWatch.9',
            'Ensure a log metric filter and alarm exist for AWS Config configuration changes',
            compliant_status,
            'LOW',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def cloudwatch_ten(self) -> None:
        compliant_status = self.get_compliant_status(
            '{($.eventName=AuthorizeSecurityGroupIngress) || ($.eventName=AuthorizeSecurityGroupEgress) || ($.eventName=RevokeSecurityGroupIngress) || ($.eventName=RevokeSecurityGroupEgress) || ($.eventName=CreateSecurityGroup) || ($.eventName=DeleteSecurityGroup)}'
            )
        self.cloudwatch_list.append(self.create_cloudwatch_item(
            'CloudWatch.10',
            'Ensure a log metric filter and alarm exist for security group changes',
            compliant_status,
            'LOW',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def cloudwatch_eleven(self) -> None:
        compliant_status = self.get_compliant_status(
            '{($.eventName=CreateNetworkAcl) || ($.eventName=CreateNetworkAclEntry) || ($.eventName=DeleteNetworkAcl) || ($.eventName=DeleteNetworkAclEntry) || ($.eventName=ReplaceNetworkAclEntry) || ($.eventName=ReplaceNetworkAclAssociation)}'
            )
        self.cloudwatch_list.append(self.create_cloudwatch_item(
            'CloudWatch.11',
            'Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)',
            compliant_status,
            'LOW',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def cloudwatch_twelve(self) -> None:
        compliant_status = self.get_compliant_status(
            '{($.eventName=CreateCustomerGateway) || ($.eventName=DeleteCustomerGateway) || ($.eventName=AttachInternetGateway) || ($.eventName=CreateInternetGateway) || ($.eventName=DeleteInternetGateway) || ($.eventName=DetachInternetGateway)}'
            )
        self.cloudwatch_list.append(self.create_cloudwatch_item(
            'CloudWatch.12',
            'Ensure a log metric filter and alarm exist for changes to network gateways',
            compliant_status,
            'LOW',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def cloudwatch_thirteen(self) -> None:
        compliant_status = self.get_compliant_status(
            '{($.eventSource=ec2.amazonaws.com) && (($.eventName=CreateRoute) || ($.eventName=CreateRouteTable) || ($.eventName=ReplaceRoute) || ($.eventName=ReplaceRouteTableAssociation) || ($.eventName=DeleteRouteTable) || ($.eventName=DeleteRoute) || ($.eventName=DisassociateRouteTable))}'
            )
        self.cloudwatch_list.append(self.create_cloudwatch_item(
            'CloudWatch.13',
            'Ensure a log metric filter and alarm exist for route table changes',
            compliant_status,
            'LOW',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def cloudwatch_fourteen(self) -> None:
        compliant_status = self.get_compliant_status(
            '{($.eventName=CreateVpc) || ($.eventName=DeleteVpc) || ($.eventName=ModifyVpcAttribute) || ($.eventName=AcceptVpcPeeringConnection) || ($.eventName=CreateVpcPeeringConnection) || ($.eventName=DeleteVpcPeeringConnection) || ($.eventName=RejectVpcPeeringConnection) || ($.eventName=AttachClassicLinkVpc) || ($.eventName=DetachClassicLinkVpc) || ($.eventName=DisableVpcClassicLink) || ($.eventName=EnableVpcClassicLink)}'
            )
        self.cloudwatch_list.append(self.create_cloudwatch_item(
            'CloudWatch.14',
            'Ensure a log metric filter and alarm exist for VPC changes',
            compliant_status,
            'LOW',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def cloudwatch_fifteen(self) -> None:
        result_list = self.cloudwatch_alarm_action()
        if not result_list:
            self.cloudwatch_list.append(self.create_cloudwatch_item(
                'CloudWatch.15',
                'CloudWatch alarms should have specified actions configured',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if response['AlarmActions'] == []:
                self.cloudwatch_list.append(self.create_cloudwatch_item(
                    'CloudWatch.15',
                    'CloudWatch alarms should have specified actions configured',
                    'failed',
                    'HIGH',
                    'not_available',
                    response['AlarmArn']
                ))
            else:
                self.cloudwatch_list.append(self.create_cloudwatch_item(
                    'CloudWatch.15',
                    'CloudWatch alarms should have specified actions configured',
                    'passed',
                    'HIGH',
                    'not_available',
                    response['AlarmArn']
                ))

    @DecoratorClass.my_decorator
    def cloudwatch_sixteen(self) -> None:
        result_list = self.cloudwatch_log_group()
        if not result_list:
            self.cloudwatch_list.append(self.create_cloudwatch_item(
                'CloudWatch.16',
                'CloudWatch log groups should be retained for a specified time period',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if 'retentionInDays' not in response:
                self.cloudwatch_list.append(self.create_cloudwatch_item(
                    'CloudWatch.16',
                    'CloudWatch log groups should be retained for a specified time period',
                    'failed',
                    'HIGH',
                    'not_available',
                    response['logGroupArn']
                ))
            else:
                self.cloudwatch_list.append(self.create_cloudwatch_item(
                    'CloudWatch.16',
                    'CloudWatch log groups should be retained for a specified time period',
                    'passed',
                    'HIGH',
                    'not_available',
                    response['logGroupArn']
                ))

    @DecoratorClass.my_decorator
    def cloudwatch_seventeen(self) -> None:
        result_list = self.cloudwatch_alarm_action()
        if not result_list:
            self.cloudwatch_list.append(self.create_cloudwatch_item(
                'CloudWatch.17',
                'CloudWatch alarm actions should be activated',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if response['ActionsEnabled'] == False:
                self.cloudwatch_list.append(self.create_cloudwatch_item(
                    'CloudWatch.17',
                    'CloudWatch alarm actions should be activated',
                    'failed',
                    'HIGH',
                    'not_available',
                    response['AlarmArn']
                ))
            else:
                self.cloudwatch_list.append(self.create_cloudwatch_item(
                    'CloudWatch.17',
                    'CloudWatch alarm actions should be activated',
                    'passed',
                    'HIGH',
                    'not_available',
                    response['AlarmArn']
                ))
    
class CloudWatchAutoRemediation:
    def __init__(self) -> None:
        self.logs_client = boto3.client('logs')
        self.kms_key_arn = KMSAutoRemediation().get_kms_key_arn()

    def remediate_config_cloudwatch_log_group_encrypted(self) -> None:
        response = self.logs_client.describe_log_groups()
        for log_group in response['logGroups']:
            if 'kmsKeyId' not in log_group:
                try:
                    self.logs_client.associate_kms_key(
                        logGroupName=log_group['logGroupName'],
                        kmsKeyId=self.kms_key_arn
                    )
                    print(f"Auto remediated for CLOUDWATCH_LOG_GROUP_ENCRYPTED: {log_group['arn']}")
                except ClientError as e:
                    print(f"Error: {e}")
        while 'nextToken' in response:
            response = self.logs_client.describe_log_groups(nextToken=response['nextToken'])
            for log_group in response['logGroups']:
                if 'kmsKeyId' not in log_group:
                    try:
                        self.logs_client.associate_kms_key(
                            logGroupName=log_group['logGroupName'],
                            kmsKeyId=self.kms_key_arn
                        )
                        print(f"Auto remediated for CLOUDWATCH_LOG_GROUP_ENCRYPTED: {log_group['arn']}")
                    except ClientError as e:
                        print(f"Error: {e}")

    def create_cloudwatch_log_group(self, log_group_name: str, kms_key_arn: str, retention_day: int) -> None:
        try:
            self.logs_client.create_log_group(
                logGroupName=log_group_name,
                kmsKeyId=kms_key_arn
            )
            self.logs_client.put_retention_policy(
                logGroupName=log_group_name,
                retentionInDays=retention_day
            )
            print(f"Log group created: {log_group_name}")
        except ClientError as e:
            print(f"Error: {e}")

class CrossAccountCloudWatchComplianceChecker:
    def __init__(self) -> None:
        self.logs_client = UseCrossAccount().client('logs')
        self.sns_client = UseCrossAccount().client('sns')
        self.cloudwatch_client = UseCrossAccount().client('cloudwatch')
        self.session_account = UseCrossAccount().client('sts').get_caller_identity().get('Account')
        self.cloudwatch_list = compliance_check_list

    def create_cloudwatch_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("CloudWatch", control_id, compliance, severity, auto_remediation):
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

    def cloud_watch(self) -> list[dict]:
        cloudwatch_list: list[dict] = []
        response = self.logs_client.describe_metric_filters()
        cloudwatch_list.extend([_ for _ in response['metricFilters']])
        while 'nextToken' in response:
            response = self.logs_client.describe_metric_filters(nextToken=response['nextToken'])
            cloudwatch_list.extend([_ for _ in response['metricFilters']])
        return cloudwatch_list

    def sns_subcription(self) -> list[str]:
        sns_list: list[str] = []
        try:
            response = self.sns_client.list_topics()
            for topic in response['Topics']:
                subcription_response = self.sns_client.list_subscriptions_by_topic(TopicArn=topic['TopicArn'])
                sns_list.extend([topic['TopicArn'] \
                                for _ in subcription_response['Subscriptions'] \
                                if subcription_response != [] \
                                and _['SubscriptionArn'] != 'PendingConfirmation'])
                while 'NextToken' in subcription_response:
                    subcription_response = self.sns_client.list_subscriptions_by_topic(TopicArn=topic['TopicArn'], \
                                                                                        NextToken=subcription_response['NextToken'])
                    sns_list.extend([topic['TopicArn'] \
                                    for _ in subcription_response['Subscriptions'] \
                                    if subcription_response != [] \
                                    and _['SubscriptionArn'] != 'PendingConfirmation'])
            while 'NextToken' in response:
                response = self.sns_client.list_topics(NextToken=response['NextToken'])
                for topic in response['Topics']:
                    subcription_response = self.sns_client.list_subscriptions_by_topic(TopicArn=topic['TopicArn'])
                    sns_list.extend([topic['TopicArn'] \
                                    for _ in subcription_response['Subscriptions'] \
                                    if subcription_response != [] \
                                    and _['SubscriptionArn'] != 'PendingConfirmation'])
                    while 'NextToken' in subcription_response:
                        subcription_response = self.sns_client.list_subscriptions_by_topic(TopicArn=topic['TopicArn'], \
                                                                                            NextToken=subcription_response['NextToken'])
                        sns_list.extend([topic['TopicArn'] \
                                        for _ in subcription_response['Subscriptions'] \
                                        if subcription_response != [] \
                                        and _['SubscriptionArn'] != 'PendingConfirmation'])
            return sns_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    def cloudwatch_alarm(self, metric_name: str, metric_namespace: str) -> bool:
        sns_list = self.sns_subcription()
        response = self.cloudwatch_client.describe_alarms_for_metric(MetricName=metric_name, Namespace=metric_namespace)
        return any(_ in sns_list for alarm in response['MetricAlarms'] for _ in alarm['AlarmActions'])
    
    def get_compliant_status(self, filter_pattern: str) -> str:
        result_list = self.cloud_watch()
        # Failed if no CloudWatch metric with filter pattern or alarm else passed
        compliant_status = 'failed' \
            if sum(1 for _ in result_list if _['filterPattern'] == filter_pattern \
            for metric in _['metricTransformations']
            if self.cloudwatch_alarm(metric['metricName'], metric['metricNamespace'])) == 0 \
            else 'passed'
        return compliant_status
    
    def cloudwatch_alarm_action(self) -> list[dict]:
        alarm_action_list: list[dict] = []
        try:
            response = self.cloudwatch_client.describe_alarms()
            alarm_action_list.extend(_ for _ in response['MetricAlarms'])
            while 'NextToken' in response:
                response = self.cloudwatch_client.describe_alarms(NextToken=response['NextToken'])
                alarm_action_list.extend(_ for _ in response['MetricAlarms'])
            return alarm_action_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    def cloudwatch_log_group(self) -> list[dict]:
        log_group_list: list[dict] = []
        try:
            response = self.logs_client.describe_log_groups()
            log_group_list.extend(_ for _ in response['logGroups'])
            while 'nextToken' in response:
                response = self.logs_client.describe_log_groups(nextToken=response['nextToken'])
                log_group_list.extend(_ for _ in response['logGroups'])
            return log_group_list
        except ClientError as e:
            print(f"Error: {e}")
            return []

    @DecoratorClass.my_decorator
    def cloudwatch_one(self) -> None:
        compliant_status = self.get_compliant_status(
            '{$.userIdentity.type=\"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !=\"AwsServiceEvent\"}'
            )
        self.cloudwatch_list.append(self.create_cloudwatch_item(
            'CloudWatch.1',
            'A log metric filter and alarm should exist for usage of the "root" user',
            compliant_status,
            'LOW',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def cloudwatch_two(self) -> None:
        compliant_status = self.get_compliant_status(
            '{($.errorCode="*UnauthorizedOperation") || ($.errorCode="AccessDenied*")}'
            )
        self.cloudwatch_list.append(self.create_cloudwatch_item(
            'CloudWatch.2',
            'Ensure a log metric filter and alarm exist for unauthorized API calls',
            compliant_status,
            'LOW',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def cloudwatch_three(self) -> None:
        compliant_status = self.get_compliant_status(
            '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") && ($.userIdentity.type = "IAMUser") && ($.responseElements.ConsoleLogin = "Success") }'
            )
        self.cloudwatch_list.append(self.create_cloudwatch_item(
            'CloudWatch.3',
            'Ensure a log metric filter and alarm exist for Management Console sign-in without MFA',
            compliant_status,
            'LOW',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def cloudwatch_four(self) -> None:
        compliant_status = self.get_compliant_status(
            '{($.eventSource=iam.amazonaws.com) && (($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy) || ($.eventName=DetachGroupPolicy))}'
            )
        self.cloudwatch_list.append(self.create_cloudwatch_item(
            'CloudWatch.4',
            'Ensure a log metric filter and alarm exist for IAM policy changes',
            compliant_status,
            'LOW',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def cloudwatch_five(self) -> None:
        compliant_status = self.get_compliant_status(
            '{($.eventName=CreateTrail) || ($.eventName=UpdateTrail) || ($.eventName=DeleteTrail) || ($.eventName=StartLogging) || ($.eventName=StopLogging)}'
            )
        self.cloudwatch_list.append(self.create_cloudwatch_item(
            'CloudWatch.5',
            'Ensure a log metric filter and alarm exist for CloudTrail configuration changes',
            compliant_status,
            'LOW',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def cloudwatch_six(self) -> None:
        compliant_status = self.get_compliant_status(
            '{($.eventName=ConsoleLogin) && ($.errorMessage="Failed authentication")}'
            )
        self.cloudwatch_list.append(self.create_cloudwatch_item(
            'CloudWatch.6',
            'Ensure a log metric filter and alarm exist for AWS Management Console authentication failures',
            compliant_status,
            'LOW',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def cloudwatch_seven(self) -> None:
        compliant_status = self.get_compliant_status(
            '{($.eventSource=kms.amazonaws.com) && (($.eventName=DisableKey) || ($.eventName=ScheduleKeyDeletion))}'
            )
        self.cloudwatch_list.append(self.create_cloudwatch_item(
            'CloudWatch.7',
            'Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs',
            compliant_status,
            'LOW',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def cloudwatch_eight(self) -> None:
        compliant_status = self.get_compliant_status(
            '{($.eventSource=s3.amazonaws.com) && (($.eventName=PutBucketAcl) || ($.eventName=PutBucketPolicy) || ($.eventName=PutBucketCors) || ($.eventName=PutBucketLifecycle) || ($.eventName=PutBucketReplication) || ($.eventName=DeleteBucketPolicy) || ($.eventName=DeleteBucketCors) || ($.eventName=DeleteBucketLifecycle) || ($.eventName=DeleteBucketReplication))}'
            )
        self.cloudwatch_list.append(self.create_cloudwatch_item(
            'CloudWatch.8',
            'Ensure a log metric filter and alarm exist for S3 bucket policy changes',
            compliant_status,
            'LOW',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def cloudwatch_nine(self) -> None:
        compliant_status = self.get_compliant_status(
            '{($.eventSource=config.amazonaws.com) && (($.eventName=StopConfigurationRecorder) || ($.eventName=DeleteDeliveryChannel) || ($.eventName=PutDeliveryChannel) || ($.eventName=PutConfigurationRecorder))}'
            )
        self.cloudwatch_list.append(self.create_cloudwatch_item(
            'CloudWatch.9',
            'Ensure a log metric filter and alarm exist for AWS Config configuration changes',
            compliant_status,
            'LOW',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def cloudwatch_ten(self) -> None:
        compliant_status = self.get_compliant_status(
            '{($.eventName=AuthorizeSecurityGroupIngress) || ($.eventName=AuthorizeSecurityGroupEgress) || ($.eventName=RevokeSecurityGroupIngress) || ($.eventName=RevokeSecurityGroupEgress) || ($.eventName=CreateSecurityGroup) || ($.eventName=DeleteSecurityGroup)}'
            )
        self.cloudwatch_list.append(self.create_cloudwatch_item(
            'CloudWatch.10',
            'Ensure a log metric filter and alarm exist for security group changes',
            compliant_status,
            'LOW',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def cloudwatch_eleven(self) -> None:
        compliant_status = self.get_compliant_status(
            '{($.eventName=CreateNetworkAcl) || ($.eventName=CreateNetworkAclEntry) || ($.eventName=DeleteNetworkAcl) || ($.eventName=DeleteNetworkAclEntry) || ($.eventName=ReplaceNetworkAclEntry) || ($.eventName=ReplaceNetworkAclAssociation)}'
            )
        self.cloudwatch_list.append(self.create_cloudwatch_item(
            'CloudWatch.11',
            'Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)',
            compliant_status,
            'LOW',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def cloudwatch_twelve(self) -> None:
        compliant_status = self.get_compliant_status(
            '{($.eventName=CreateCustomerGateway) || ($.eventName=DeleteCustomerGateway) || ($.eventName=AttachInternetGateway) || ($.eventName=CreateInternetGateway) || ($.eventName=DeleteInternetGateway) || ($.eventName=DetachInternetGateway)}'
            )
        self.cloudwatch_list.append(self.create_cloudwatch_item(
            'CloudWatch.12',
            'Ensure a log metric filter and alarm exist for changes to network gateways',
            compliant_status,
            'LOW',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def cloudwatch_thirteen(self) -> None:
        compliant_status = self.get_compliant_status(
            '{($.eventSource=ec2.amazonaws.com) && (($.eventName=CreateRoute) || ($.eventName=CreateRouteTable) || ($.eventName=ReplaceRoute) || ($.eventName=ReplaceRouteTableAssociation) || ($.eventName=DeleteRouteTable) || ($.eventName=DeleteRoute) || ($.eventName=DisassociateRouteTable))}'
            )
        self.cloudwatch_list.append(self.create_cloudwatch_item(
            'CloudWatch.13',
            'Ensure a log metric filter and alarm exist for route table changes',
            compliant_status,
            'LOW',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def cloudwatch_fourteen(self) -> None:
        compliant_status = self.get_compliant_status(
            '{($.eventName=CreateVpc) || ($.eventName=DeleteVpc) || ($.eventName=ModifyVpcAttribute) || ($.eventName=AcceptVpcPeeringConnection) || ($.eventName=CreateVpcPeeringConnection) || ($.eventName=DeleteVpcPeeringConnection) || ($.eventName=RejectVpcPeeringConnection) || ($.eventName=AttachClassicLinkVpc) || ($.eventName=DetachClassicLinkVpc) || ($.eventName=DisableVpcClassicLink) || ($.eventName=EnableVpcClassicLink)}'
            )
        self.cloudwatch_list.append(self.create_cloudwatch_item(
            'CloudWatch.14',
            'Ensure a log metric filter and alarm exist for VPC changes',
            compliant_status,
            'LOW',
            'not_available',
            self.session_account
        ))

    @DecoratorClass.my_decorator
    def cloudwatch_fifteen(self) -> None:
        result_list = self.cloudwatch_alarm_action()
        if not result_list:
            self.cloudwatch_list.append(self.create_cloudwatch_item(
                'CloudWatch.15',
                'CloudWatch alarms should have specified actions configured',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if response['AlarmActions'] == []:
                self.cloudwatch_list.append(self.create_cloudwatch_item(
                    'CloudWatch.15',
                    'CloudWatch alarms should have specified actions configured',
                    'failed',
                    'HIGH',
                    'not_available',
                    response['AlarmArn']
                ))
            else:
                self.cloudwatch_list.append(self.create_cloudwatch_item(
                    'CloudWatch.15',
                    'CloudWatch alarms should have specified actions configured',
                    'passed',
                    'HIGH',
                    'not_available',
                    response['AlarmArn']
                ))

    @DecoratorClass.my_decorator
    def cloudwatch_sixteen(self) -> None:
        result_list = self.cloudwatch_log_group()
        if not result_list:
            self.cloudwatch_list.append(self.create_cloudwatch_item(
                'CloudWatch.16',
                'CloudWatch log groups should be retained for a specified time period',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if 'retentionInDays' not in response:
                self.cloudwatch_list.append(self.create_cloudwatch_item(
                    'CloudWatch.16',
                    'CloudWatch log groups should be retained for a specified time period',
                    'failed',
                    'HIGH',
                    'not_available',
                    response['logGroupArn']
                ))
            else:
                self.cloudwatch_list.append(self.create_cloudwatch_item(
                    'CloudWatch.16',
                    'CloudWatch log groups should be retained for a specified time period',
                    'passed',
                    'HIGH',
                    'not_available',
                    response['logGroupArn']
                ))

    @DecoratorClass.my_decorator
    def cloudwatch_seventeen(self) -> None:
        result_list = self.cloudwatch_alarm_action()
        if not result_list:
            self.cloudwatch_list.append(self.create_cloudwatch_item(
                'CloudWatch.17',
                'CloudWatch alarm actions should be activated',
                'not_found',
                'HIGH',
                'not_available',
                'not_found'
            ))
        for response in result_list:
            if response['ActionsEnabled'] == False:
                self.cloudwatch_list.append(self.create_cloudwatch_item(
                    'CloudWatch.17',
                    'CloudWatch alarm actions should be activated',
                    'failed',
                    'HIGH',
                    'not_available',
                    response['AlarmArn']
                ))
            else:
                self.cloudwatch_list.append(self.create_cloudwatch_item(
                    'CloudWatch.17',
                    'CloudWatch alarm actions should be activated',
                    'passed',
                    'HIGH',
                    'not_available',
                    response['AlarmArn']
                ))
    
class CrossAccountCloudWatchAutoRemediation:
    def __init__(self) -> None:
        self.logs_client = UseCrossAccount().client('logs')
        self.kms_key_arn = CrossAccountKMSAutoRemediation().get_kms_key_arn()

    def remediate_config_cloudwatch_log_group_encrypted(self) -> None:
        response = self.logs_client.describe_log_groups()
        for log_group in response['logGroups']:
            if 'kmsKeyId' not in log_group:
                try:
                    self.logs_client.associate_kms_key(
                        logGroupName=log_group['logGroupName'],
                        kmsKeyId=self.kms_key_arn
                    )
                    print(f"Auto remediated for CLOUDWATCH_LOG_GROUP_ENCRYPTED: {log_group['arn']}")
                except ClientError as e:
                    print(f"Error: {e}")
        while 'nextToken' in response:
            response = self.logs_client.describe_log_groups(nextToken=response['nextToken'])
            for log_group in response['logGroups']:
                if 'kmsKeyId' not in log_group:
                    try:
                        self.logs_client.associate_kms_key(
                            logGroupName=log_group['logGroupName'],
                            kmsKeyId=self.kms_key_arn
                        )
                        print(f"Auto remediated for CLOUDWATCH_LOG_GROUP_ENCRYPTED: {log_group['arn']}")
                    except ClientError as e:
                        print(f"Error: {e}")

    def create_cloudwatch_log_group(self, log_group_name: str, kms_key_arn: str, retention_day: int) -> None:
        try:
            self.logs_client.create_log_group(
                logGroupName=log_group_name,
                kmsKeyId=kms_key_arn
            )
            self.logs_client.put_retention_policy(
                logGroupName=log_group_name,
                retentionInDays=retention_day
            )
            print(f"Log group created: {log_group_name}")
        except ClientError as e:
            print(f"Error: {e}")