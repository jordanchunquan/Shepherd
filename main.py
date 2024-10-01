import os, csv, shutil, argparse, datetime
from utils.decorator_class import DecoratorClass
from utils.validate import ParameterValidation
from services.account import AccountComplianceChecker, CrossAccountAccountComplianceChecker
from services.acm import ACMComplianceChecker, CrossAccountACMComplianceChecker
from services.apigateway import APIGatewayComplianceChecker, CrossAccountAPIGatewayComplianceChecker
from services.appsync import AppSyncComplianceChecker, CrossAccountAppSyncComplianceChecker
from services.athena import AthenaComplianceChecker, CrossAccountAthenaComplianceChecker
from services.autoscaling import AutoScalingComplianceChecker, CrossAccountAutoScalingComplianceChecker
from services.backup import BackupComplianceChecker, CrossAccountBackupComplianceChecker
from services.cloudformation import CloudFormationComplianceChecker, CrossAccountCloudFormationComplianceChecker
from services.cloudfront import CloudFrontComplianceChecker, CrossAccountCloudFrontComplianceChecker
from services.cloudtrail import CloudTrailComplianceChecker, CrossAccountCloudTrailComplianceChecker
from services.cloudwatch import CloudWatchComplianceChecker, CrossAccountCloudWatchComplianceChecker
from services.codeartifact import CodeArtifactComplianceChecker, CrossAccountCodeArtifactComplianceChecker
from services.config import ConfigComplianceChecker, CrossAccountConfigComplianceChecker
from services.datafirehose import DataFirehoseComplianceChecker, CrossAccountDataFirehoseComplianceChecker
from services.detective import DetectiveComplianceChecker, CrossAccountDetectiveComplianceChecker
from services.dms import DMSComplianceChecker, CrossAccountDMSComplianceChecker
from services.codebuild import CodeBuildComplianceChecker, CrossAccountCodeBuildComplianceChecker
from services.docdb import DocumentDBComplianceChecker, CrossAccountDocumentDBComplianceChecker
from services.dynamodb import DynamoDBComplianceChecker, CrossAccountDynamoDBComplianceChecker
from services.ec2 import EC2ComplianceChecker, CrossAccountEC2ComplianceChecker
from services.ecr import ECRComplianceChecker, CrossAccountECRComplianceChecker
from services.ecs import ECSComplianceChecker, CrossAccountECSComplianceChecker
from services.efs import EFSComplianceChecker, CrossAccountEFSComplianceChecker
from services.eks import EKSComplianceChecker, CrossAccountEKSComplianceChecker
from services.elasticache import ElastiCacheComplianceChecker, CrossAccountElastiCacheComplianceChecker
from services.elasticbeanstalk import ElasticBeanstalkComplianceChecker, CrossAccountElasticBeanstalkComplianceChecker
from services.elb import ELBComplianceChecker, CrossAccountELBComplianceChecker
from services.emr import EMRComplianceChecker, CrossAccountEMRComplianceChecker
from services.es import ESComplianceChecker, CrossAccountESComplianceChecker
from services.eventbridge import EventBridgeComplianceChecker, CrossAccountEventBridgeComplianceChecker
from services.fsx import FSxComplianceChecker, CrossAccountFSxComplianceChecker
from services.globalaccelerator import GlobalAcceleratorComplianceChecker, CrossAccountGlobalAcceleratorComplianceChecker
from services.glue import GlueComplianceChecker, CrossAccountGlueComplianceChecker
from services.guardduty import GuardDutyComplianceChecker, CrossAccountGuardDutyComplianceChecker
from services.iam import IAMComplianceChecker, CrossAccountIAMComplianceChecker
from services.iot import IoTComplianceChecker, CrossAccountIoTComplianceChecker
from services.kinesis import KinesisComplianceChecker, CrossAccountKinesisComplianceChecker
from services.kms import KMSComplianceChecker, CrossAccountKMSComplianceChecker
from services.aws_lambda import LambdaComplianceChecker, CrossAccountLambdaComplianceChecker
from services.macie import MacieComplianceChecker, CrossAccountMacieComplianceChecker
from services.msk import MSKComplianceChecker, CrossAccountMSKComplianceChecker
from services.mq import MQComplianceChecker, CrossAccountMQComplianceChecker
from services.neptune import NeptuneComplianceChecker, CrossAccountNeptuneComplianceChecker
from services.networkfirewall import NetworkFirewallComplianceChecker, CrossAccountNetworkFirewallComplianceChecker
from services.opensearch import OpensearchComplianceChecker, CrossAccountOpensearchComplianceChecker
from services.pca import PCAComplianceChecker, CrossAccountPCAComplianceChecker
from standard.standard import AWSFSBP_1_0_0, CISAWSFundationsBenchmark_1_2_0, CISAWSFundationsBenchmark_1_4_0, NISTSP_800_53_Rev_5, PCI_DSS, ServiceManagedStandardAWSControlTower, AWSResourceTaggingStandard, AllAWSSecurityHubControl
from utils.global_data import compliance_check_list, reset_compliance_list
from cross_account_list import CrossAccountList

class RunScan():
    def __init__(self) -> None:
        self.time_now = datetime.datetime.now().strftime('%Y-%m-%dT%H_%M_%S%z')
        self.args = self.parse_arguments()
        if not self.args['cross']: # type: ignore
            self.validate_run_default_account_scan()
        if self.args['cross']:  # type: ignore
            while True:
                if ParameterValidation().validate_arg_parser(arg_parser = self.args['cross']): # type: ignore
                    self.validate_run_default_account_scan()
                    for cross_account in CrossAccountList().cross_account_list:
                        self.valdiate_run_cross_account_scan(cross_account)
                    break
                else:
                    self.args['cross'] = input("Invalid input, please confirm enable cross account report by entering 'y': ")  # type: ignore
        self.zip_folder()

    def validate_run_default_account_scan(self) -> None:
        self.default_account_name = input('Please enter account name: ')
        default_account_name = self.default_account_name.replace(" ", "_").lower()
        while True:
            if self.default_account_name and ParameterValidation().validate_input_account_name(default_account_name):
                break
            else:
                self.default_account_name = input("Invalid input, please re-enter account name(alphabet or space only): ")
                default_account_name = self.default_account_name.replace(" ", "_").lower()
        print(f"----------Account: {self.default_account_name}----------")
        print(f"----------Start security scanning----------")
        [eval(_) for _ in AllAWSSecurityHubControl().standard_list]
        # self.run_scan([])
        print(f"----------End security scanning----------")
        data = compliance_check_list
        [print(_) for _ in data]
        return None
        # self.create_account_folder(default_account_name)
        # file_path = f"report/{default_account_name}/security_report_generator_{self.time_now}+08_00.csv"
        # self.export_dict_to_csv(data, file_path)
        # data = self.export_failed_resource(data)
        # file_path = f"report/{default_account_name}/failed_security_report_generator_{self.time_now}+08_00.csv"
        # self.export_dict_to_csv(data, file_path)
        # reset_compliance_list()
        # print('\n')
        # return None
    
    def valdiate_run_cross_account_scan(self, cross_account: dict) -> None:
        self.cross_account_name = cross_account.get('aws_account_name')
        os.environ['AWS_ACCOUNT_ID'] = cross_account.get('aws_account_id') # type: ignore
        os.environ['AWS_ACCOUNT_ROLE'] = cross_account.get('aws_account_role') # type: ignore
        cross_account_name = self.cross_account_name.replace(" ", "_").lower() # type: ignore
        print(f"----------Account: {self.cross_account_name}----------")
        print(f"----------Start security scanning----------")
        self.run_cross_account_scan()
        print(f"----------End security scanning----------")
        data = compliance_check_list
        [print(_) for _ in data]
        return None
        # self.create_account_folder(cross_account_name)
        # file_path = f"report/{cross_account_name}/security_report_generator_{self.time_now}+08_00.csv"
        # self.export_dict_to_csv(data, file_path)
        # data = self.export_failed_resource(data)
        # file_path = f"report/{cross_account_name}/failed_security_report_generator_{self.time_now}+08_00.csv"
        # self.export_dict_to_csv(data, file_path)
        # reset_compliance_list()
        # print('\n')
        # return None

    def parse_arguments(self) -> vars:  # type: ignore
        parser = argparse.ArgumentParser(description='Shepherd - Security Report Generator')
        parser.add_argument('-c', '--cross', metavar='y', type=str, help='Enable security report for cross account.')
        return vars(parser.parse_args())
    
    def export_failed_resource(self, data: list[dict]) -> list[dict]:
        data = [_ for _ in data if _.get('compliance') == 'failed']
        data = self.failed_check_count(data)
        data = self.join_resource(data)
        data = self.drop_duplicate(data)
        data = self.rearrange_dict_keys(data, ['control_id', 'control_title', 'compliance', 'severity', 'failed_check', 'resource_id'])
        return data
    
    def failed_check_count(self, data: list[dict]) -> list[dict]:
        failed_check_count: dict = {}
        for _ in data:
            key = (_['control_id'], _['control_title'])
            failed_check_count[key] = failed_check_count.get(key, 0) + 1
            _['failed_check'] = failed_check_count[key]
        return data
    
    def join_resource(self, data: list[dict]) -> list[dict]:
        resource_dict: dict = {}
        for _ in data:
            key = (_['control_id'], _['control_title'])
            resource_dict.setdefault(key, []).append(_['resource_id'])
        for key, resource_id in resource_dict.items():
            resource_id_str = ', '.join(resource_id)
            for row in data:
                if (row['control_id'], row['control_title']) == key:
                    row['resource_id'] = resource_id_str
        return data

    def drop_duplicate(self, data: list[dict]) -> list[dict]:
        seen_keys = set()
        filtered_rows = []
        for _ in reversed(data):
            key = (_['control_id'], _['control_title'])
            if key not in seen_keys:
                    seen_keys.add(key)
                    filtered_rows.append(_)
            data = list(reversed(filtered_rows))
        return data
    
    def rearrange_dict_keys(self, data: list[dict], key_order: list[str]) -> list[dict]:
        rearranged_list: list[dict] = []
        for d in data:
            rearranged_dict = {key: d[key] for key in key_order if key in d}
            rearranged_list.append(rearranged_dict)
        return rearranged_list
    
    def create_account_folder(self, account_name) -> None:
        current_directory = os.getcwd()
        folder_path = os.path.join(current_directory, "report")
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)
        if os.path.exists("report") and os.path.isdir("report"):
            os.chdir("report")
            report_dir = os.getcwd()
            account_folder_path = os.path.join(report_dir, account_name)
            if not os.path.exists(account_folder_path):
                os.makedirs(account_folder_path)
            os.chdir(current_directory)

    def zip_folder(self) -> None:
        current_directory = os.getcwd()
        folder_path = os.path.join(current_directory, "report")
        shutil.make_archive("report", 'zip', folder_path)
        print(f"Security report exported to location: {folder_path}.zip")

    @DecoratorClass.my_decorator
    def run_scan(standard_list: list[str]) -> None:
        combine_standard = standard_list[0]
        for _ in range(1, len(standard_list)):
            combine_standard = set(combine_standard).union(standard_list[_])
        [eval(_) for _ in combine_standard]

    @DecoratorClass.my_decorator
    def run_cross_account_scan(standard_list: list[str]) -> None:
        combine_standard = standard_list[0]
        for _ in range(1, len(standard_list)):
            combine_standard = set(combine_standard).union(standard_list[_])
        [eval(_) for _ in combine_standard]

    def export_dict_to_csv(self, data: list[dict], file_path: str) -> None:
        with open(file_path, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=data[0].keys())
            writer.writeheader()
            for row in data:
                writer.writerow(row)

if __name__ == "__main__":
    RunScan()