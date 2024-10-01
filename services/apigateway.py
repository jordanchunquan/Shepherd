'''
Class name APIGatewayComplianceChecker
Create functions to check compliants and return as 
'control_id': security contorl id,
'control_title': security control title,
'compliance': passed, failed or not_found,
'severity': CRITICAL, HIGH, MEDIUM or LOW,
'auto_remediation': available or not_available,
'resource_id': account id, resource arn or not_found

Class name APIGatewayAutoRemediation
Autoremediate APIGateway one by enable CloudWatch log group logging for execution logging
Unable to autoremediate APIGateway two because it require approval from client to select SSL certificate
Autoremediate APIGateway three by enable X-Ray tracing
Unable to autoremediate APIGateway four because it require approval from client to select Web ACL
Unable to autoremediate APIGateway five because it require approval from client to enable cache data and encrypt
Unable to autoremediate APIGateway eight because it require approvel from client to enable authorization
Autoremediate APIGateway nine by enable CloudWatch log group logging for access logging
'''

import json, boto3 # type: ignore
from time import sleep
from botocore.exceptions import ClientError # type: ignore
from utils.decorator_class import DecoratorClass # type: ignore
from utils.validate import ParameterValidation # type: ignore
from utils.cross_account import UseCrossAccount # type: ignore
from utils.global_data import compliance_check_list # type: ignore

class APIGatewayComplianceChecker:
    def __init__(self) -> None:
        self.apigateway_client = boto3.client('apigateway')
        self.apigatewayv2_client = boto3.client('apigatewayv2')
        self.session_region = boto3.session.Session().region_name
        self.session_account = boto3.client('sts').get_caller_identity().get('Account')

        self.apigateway_list = compliance_check_list

    def create_apigateway_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("APIGateway", control_id, compliance, severity, auto_remediation):
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
    
    @DecoratorClass.my_decorator
    def apigateway_one(self) -> None:
        try:
            if not self.apigateway_client.get_rest_apis()['items'] \
            and (not self.apigatewayv2_client.get_apis()['Items'] \
            or not any(response_detail['ProtocolType'] == "WEBSOCKET" \
            for response_detail in self.apigatewayv2_client.get_apis()['Items'])):  # Check if no stages found
                self.apigateway_list.append(self.create_apigateway_item(
                    'APIGateway.1',
                    'API Gateway REST and WebSocket API execution logging should be enabled',
                    'not_found',
                    'MEDIUM',
                    'available',
                    'not_found'
                ))
            response = self.apigateway_client.get_rest_apis()
            for response_detail in response['items']:
                stage_response = self.apigateway_client.get_stages(restApiId=response_detail['id'])
                for item in stage_response['item']:
                    if item['methodSettings'] == {}:
                        self.apigateway_list.append(self.create_apigateway_item(
                            'APIGateway.1',
                            'API Gateway REST and WebSocket API execution logging should be enabled',
                            'failed',
                            'MEDIUM',
                            'available',
                            f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                        ))
                    else:
                        for method in item['methodSettings']:
                            if item['methodSettings'][method]['loggingLevel'] == "OFF":
                                self.apigateway_list.append(self.create_apigateway_item(
                                    'APIGateway.1',
                                    'API Gateway REST and WebSocket API execution logging should be enabled',
                                    'failed',
                                    'MEDIUM',
                                    'available',
                                    f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                                ))
                            else:
                                self.apigateway_list.append(self.create_apigateway_item(
                                    'APIGateway.1',
                                    'API Gateway REST and WebSocket API execution logging should be enabled',
                                    'passed',
                                    'MEDIUM',
                                    'available',
                                    f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                                ))
            while 'position' in response:
                response = self.apigateway_client.get_rest_apis(position=response['position'])
                for response_detail in response['items']:
                    stage_response = self.apigateway_client.get_stages(restApiId=response_detail['id'])
                    for item in stage_response['item']:
                        if item['methodSettings'] == {}:
                            self.apigateway_list.append(self.create_apigateway_item(
                                'APIGateway.1',
                                'API Gateway REST and WebSocket API execution logging should be enabled',
                                'failed',
                                'MEDIUM',
                                'available',
                                f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                            ))
                        else:
                            for method in item['methodSettings']:
                                if item['methodSettings'][method]['loggingLevel'] == "OFF":
                                    self.apigateway_list.append(self.create_apigateway_item(
                                        'APIGateway.1',
                                        'API Gateway REST and WebSocket API execution logging should be enabled',
                                        'failed',
                                        'MEDIUM',
                                        'available',
                                        f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                                    ))
                                else:
                                    self.apigateway_list.append(self.create_apigateway_item(
                                        'APIGateway.1',
                                        'API Gateway REST and WebSocket API execution logging should be enabled',
                                        'passed',
                                        'MEDIUM',
                                        'available',
                                        f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                                    ))
            response = self.apigatewayv2_client.get_apis()
            for response_detail in response['Items']:
                if response_detail['ProtocolType'] == "WEBSOCKET":
                    stage_response = self.apigatewayv2_client.get_stages(ApiId=response_detail['ApiId'])
                    for items in stage_response['Items']:
                        if items['DefaultRouteSettings']['LoggingLevel'] == "OFF":
                            self.apigateway_list.append(self.create_apigateway_item(
                                'APIGateway.1',
                                'API Gateway REST and WebSocket API execution logging should be enabled',
                                'failed',
                                'MEDIUM',
                                'available',
                                f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/stages/{items['StageName']}"
                            ))
                        else:
                            self.apigateway_list.append(self.create_apigateway_item(
                                'APIGateway.1',
                                'API Gateway REST and WebSocket API execution logging should be enabled',
                                'passed',
                                'MEDIUM',
                                'available',
                                f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/stages/{items['StageName']}"
                            ))
                    while 'NextToken' in stage_response:
                        stage_response = self.apigatewayv2_client.get_stages(ApiId=response_detail['ApiId'], \
                                                                                NextToken=stage_response['NextToken'])
                        for items in stage_response['Items']:
                            if items['DefaultRouteSettings']['LoggingLevel'] == "OFF":
                                self.apigateway_list.append(self.create_apigateway_item(
                                    'APIGateway.1',
                                    'API Gateway REST and WebSocket API execution logging should be enabled',
                                    'failed',
                                    'MEDIUM',
                                    'available',
                                    f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/stages/{items['StageName']}"
                                ))
                            else:
                                self.apigateway_list.append(self.create_apigateway_item(
                                    'APIGateway.1',
                                    'API Gateway REST and WebSocket API execution logging should be enabled',
                                    'passed',
                                    'MEDIUM',
                                    'available',
                                    f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/stages/{items['StageName']}"
                                ))
            while 'NextToken' in response:
                response = self.apigatewayv2_client.get_apis(NextToken=response['NextToken'])
                for response_detail in response['Items']:
                    if response_detail['ProtocolType'] == "WEBSOCKET":
                        stage_response = self.apigatewayv2_client.get_stages(ApiId=response_detail['ApiId'])
                        for items in stage_response['Items']:
                            if items['DefaultRouteSettings']['LoggingLevel'] == "OFF":
                                self.apigateway_list.append(self.create_apigateway_item(
                                    'APIGateway.1',
                                    'API Gateway REST and WebSocket API execution logging should be enabled',
                                    'failed',
                                    'MEDIUM',
                                    'available',
                                    f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/stages/{items['StageName']}"
                                ))
                            else:
                                self.apigateway_list.append(self.create_apigateway_item(
                                    'APIGateway.1',
                                    'API Gateway REST and WebSocket API execution logging should be enabled',
                                    'passed',
                                    'MEDIUM',
                                    'available',
                                    f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/stages/{items['StageName']}"
                                ))
                        while 'NextToken' in stage_response:
                            stage_response = self.apigatewayv2_client.get_stages(ApiId=response_detail['ApiId'], \
                                                                                    NextToken=stage_response['NextToken'])
                            for items in stage_response['Items']:
                                if items['DefaultRouteSettings']['LoggingLevel'] == "OFF":
                                    self.apigateway_list.append(self.create_apigateway_item(
                                        'APIGateway.1',
                                        'API Gateway REST and WebSocket API execution logging should be enabled',
                                        'failed',
                                        'MEDIUM',
                                        'available',
                                        f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/stages/{items['StageName']}"
                                    ))
                                else:
                                    self.apigateway_list.append(self.create_apigateway_item(
                                        'APIGateway.1',
                                        'API Gateway REST and WebSocket API execution logging should be enabled',
                                        'passed',
                                        'MEDIUM',
                                        'available',
                                        f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/stages/{items['StageName']}"
                                    ))
        except ClientError as e:
            print(f"Error: {e}")

    @DecoratorClass.my_decorator
    def apigateway_two(self) -> None:
        try:
            if not self.apigateway_client.get_rest_apis()['items']:  # Check if no stages found
                self.apigateway_list.append(self.create_apigateway_item(
                    'APIGateway.2',
                    'API Gateway REST API stages should be configured to use SSL certificates for backend authentication',
                    'not_found',
                    'MEDIUM',
                    'not_available',
                    'not_found'
                ))
            response = self.apigateway_client.get_rest_apis()
            for response_detail in response['items']:
                stage_response = self.apigateway_client.get_stages(restApiId=response_detail['id'])
                for item in stage_response['item']:
                    if 'clientCertificateId' not in item:
                        self.apigateway_list.append(self.create_apigateway_item(
                            'APIGateway.2',
                            'API Gateway REST API stages should be configured to use SSL certificates for backend authentication',
                            'failed',
                            'MEDIUM',
                            'not_available',
                            f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                        ))
                    else:
                        self.apigateway_list.append(self.create_apigateway_item(
                            'APIGateway.2',
                            'API Gateway REST API stages should be configured to use SSL certificates for backend authentication',
                            'passed',
                            'MEDIUM',
                            'not_available',
                            f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                        ))
            while 'position' in response:
                response = self.apigateway_client.get_rest_apis(position=response['position'])
                for response_detail in response['items']:
                    stage_response = self.apigateway_client.get_stages(restApiId=response_detail['id'])
                    for item in stage_response['item']:
                        if 'clientCertificateId' not in item:
                            self.apigateway_list.append(self.create_apigateway_item(
                                'APIGateway.2',
                                'API Gateway REST API stages should be configured to use SSL certificates for backend authentication',
                                'failed',
                                'MEDIUM',
                                'not_available',
                                f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                            ))
                        else:
                            self.apigateway_list.append(self.create_apigateway_item(
                                'APIGateway.2',
                                'API Gateway REST API stages should be configured to use SSL certificates for backend authentication',
                                'passed',
                                'MEDIUM',
                                'not_available',
                                f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                            ))
        except ClientError as e:
            print(f"Error: {e}")

    @DecoratorClass.my_decorator
    def apigateway_three(self) -> None:
        try:
            if not self.apigateway_client.get_rest_apis()['items']:  # Check if no stages found
                self.apigateway_list.append(self.create_apigateway_item(
                    'APIGateway.3',
                    'API Gateway REST API stages should have AWS X-Ray tracing enabled',
                    'not_found',
                    'LOW',
                    'available',
                    'not_found'
                ))
            response = self.apigateway_client.get_rest_apis()
            for response_detail in response['items']:
                stage_response = self.apigateway_client.get_stages(restApiId=response_detail['id'])
                for item in stage_response['item']:
                    if item['tracingEnabled']  == False:
                        self.apigateway_list.append(self.create_apigateway_item(
                            'APIGateway.3',
                            'API Gateway REST API stages should have AWS X-Ray tracing enabled',
                            'failed',
                            'LOW',
                            'available',
                            f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                        ))
                    else:
                        self.apigateway_list.append(self.create_apigateway_item(
                            'APIGateway.3',
                            'API Gateway REST API stages should have AWS X-Ray tracing enabled',
                            'passed',
                            'LOW',
                            'available',
                            f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                        ))
            while 'position' in response:
                response = self.apigateway_client.get_rest_apis(position=response['position'])
                for response_detail in response['items']:
                    stage_response = self.apigateway_client.get_stages(restApiId=response_detail['id'])
                    for item in stage_response['item']:
                        if item['tracingEnabled']  == False:
                            self.apigateway_list.append(self.create_apigateway_item(
                                'APIGateway.3',
                                'API Gateway REST API stages should have AWS X-Ray tracing enabled',
                                'failed',
                                'LOW',
                                'available',
                                f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                            ))
                        else:
                            self.apigateway_list.append(self.create_apigateway_item(
                                'APIGateway.3',
                                'API Gateway REST API stages should have AWS X-Ray tracing enabled',
                                'passed',
                                'LOW',
                                'available',
                                f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                            ))
        except ClientError as e:
            print(f"Error: {e}")

    @DecoratorClass.my_decorator
    def apigateway_four(self) -> None:
        try:
            if not self.apigateway_client.get_rest_apis()['items']:  # Check if no stages found
                self.apigateway_list.append(self.create_apigateway_item(
                    'APIGateway.4',
                    'API Gateway should be associated with a WAF Web ACL',
                    'not_found',
                    'MEDIUM',
                    'not_available',
                    'not_found'
                ))
            response = self.apigateway_client.get_rest_apis()
            for response_detail in response['items']:
                stage_response = self.apigateway_client.get_stages(restApiId=response_detail['id'])
                for item in stage_response['item']:
                    if 'webAclArn' not in item:
                        self.apigateway_list.append(self.create_apigateway_item(
                            'APIGateway.4',
                            'API Gateway should be associated with a WAF Web ACL',
                            'failed',
                            'MEDIUM',
                            'not_available',
                            f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                        ))
                    else:
                        self.apigateway_list.append(self.create_apigateway_item(
                            'APIGateway.4',
                            'API Gateway should be associated with a WAF Web ACL',
                            'passed',
                            'MEDIUM',
                            'not_available',
                            f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                        ))
            while 'position' in response:
                response = self.apigateway_client.get_rest_apis(position=response['position'])
                for response_detail in response['items']:
                    stage_response = self.apigateway_client.get_stages(restApiId=response_detail['id'])
                    for item in stage_response['item']:
                        if 'webAclArn' not in item:
                            self.apigateway_list.append(self.create_apigateway_item(
                                'APIGateway.4',
                                'API Gateway should be associated with a WAF Web ACL',
                                'failed',
                                'MEDIUM',
                                'not_available',
                                f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                            ))
                        else:
                            self.apigateway_list.append(self.create_apigateway_item(
                                'APIGateway.4',
                                'API Gateway should be associated with a WAF Web ACL',
                                'passed',
                                'MEDIUM',
                                'not_available',
                                f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                            ))
        except ClientError as e:
            print(f"Error: {e}")

    @DecoratorClass.my_decorator
    def apigateway_five(self) -> None:
        try:
            if not self.apigateway_client.get_rest_apis()['items']:  # Check if no stages found
                self.apigateway_list.append(self.create_apigateway_item(
                    'APIGateway.5',
                    'API Gateway REST API cache data should be encrypted at rest',
                    'not_found',
                    'MEDIUM',
                    'not_available',
                    'not_found'
                ))
            response = self.apigateway_client.get_rest_apis()
            for response_detail in response['items']:
                stage_response = self.apigateway_client.get_stages(restApiId=response_detail['id'])
                for item in stage_response['item']:
                    if item['methodSettings'] == {}:
                        self.apigateway_list.append(self.create_apigateway_item(
                            'APIGateway.5',
                            'API Gateway REST API cache data should be encrypted at rest',
                            'failed',
                            'MEDIUM',
                            'not_available',
                            f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                        ))
                    else:
                        for method in item['methodSettings']:
                            if item['methodSettings'][method]['cacheDataEncrypted'] == False:
                                self.apigateway_list.append(self.create_apigateway_item(
                                    'APIGateway.5',
                                    'API Gateway REST API cache data should be encrypted at rest',
                                    'failed',
                                    'MEDIUM',
                                    'not_available',
                                    f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                                ))
                            else:
                                self.apigateway_list.append(self.create_apigateway_item(
                                    'APIGateway.5',
                                    'API Gateway REST API cache data should be encrypted at rest',
                                    'passed',
                                    'MEDIUM',
                                    'not_available',
                                    f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                                ))
            while 'position' in response:
                response = self.apigateway_client.get_rest_apis(position=response['position'])
                for response_detail in response['items']:
                    stage_response = self.apigateway_client.get_stages(restApiId=response_detail['id'])
                    for item in stage_response['item']:
                        if item['methodSettings'] == {}:
                            self.apigateway_list.append(self.create_apigateway_item(
                                'APIGateway.5',
                                'API Gateway REST API cache data should be encrypted at rest',
                                'failed',
                                'MEDIUM',
                                'not_available',
                                f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                            ))
                        else:
                            for method in item['methodSettings']:
                                if item['methodSettings'][method]['cacheDataEncrypted'] == False:
                                    self.apigateway_list.append(self.create_apigateway_item(
                                        'APIGateway.5',
                                        'API Gateway REST API cache data should be encrypted at rest',
                                        'failed',
                                        'MEDIUM',
                                        'not_available',
                                        f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                                    ))
                                else:
                                    self.apigateway_list.append(self.create_apigateway_item(
                                        'APIGateway.5',
                                        'API Gateway REST API cache data should be encrypted at rest',
                                        'passed',
                                        'MEDIUM',
                                        'not_available',
                                        f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                                    ))
        except ClientError as e:
            print(f"Error: {e}")

    @DecoratorClass.my_decorator
    def apigateway_eight(self) -> None:
        try:
            if not self.apigatewayv2_client.get_apis()['Items'] \
            and not [response_detail \
            for response_detail in self.apigatewayv2_client.get_apis()['Items'] \
            if response_detail['ProtocolType'] == "HTTP"]:  # Check if no stages found
                self.apigateway_list.append(self.create_apigateway_item(
                    'APIGateway.8',
                    'API Gateway routes should specify an authorization type',
                    'not_found',
                    'MEDIUM',
                    'not_available',
                    'not_found'
                ))
            response = self.apigatewayv2_client.get_apis()
            for response_detail in response['Items']:
                if response_detail['ProtocolType'] == "HTTP":
                    stage_response = self.apigatewayv2_client.get_routes(ApiId=response_detail['ApiId'])
                    for items in stage_response['Items']:
                        if items['AuthorizationType'] == "NONE":
                            self.apigateway_list.append(self.create_apigateway_item(
                                'APIGateway.8',
                                'API Gateway routes should specify an authorization type',
                                'failed',
                                'MEDIUM',
                                'not_available',
                                f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/routes/{items['RouteId']}"
                            ))
                        else:
                            self.apigateway_list.append(self.create_apigateway_item(
                                'APIGateway.8',
                                'API Gateway routes should specify an authorization type',
                                'passed',
                                'MEDIUM',
                                'not_available',
                                f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/routes/{items['RouteId']}"
                            ))
                while 'NextToken' in stage_response:
                    stage_response = self.apigatewayv2_client.get_apis(NextToken=response['NextToken'])
                    for items in stage_response['Items']:
                        if items['AuthorizationType'] == "NONE":
                            self.apigateway_list.append(self.create_apigateway_item(
                                'APIGateway.8',
                                'API Gateway routes should specify an authorization type',
                                'failed',
                                'MEDIUM',
                                'not_available',
                                f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/routes/{items['RouteId']}"
                            ))
                        else:
                            self.apigateway_list.append(self.create_apigateway_item(
                                'APIGateway.8',
                                'API Gateway routes should specify an authorization type',
                                'passed',
                                'MEDIUM',
                                'not_available',
                                f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/routes/{items['RouteId']}"
                            ))
            while 'NextToken' in response:
                response = self.apigatewayv2_client.get_apis(NextToken=response['NextToken'])
                for response_detail in response['Items']:
                    if response_detail['ProtocolType'] == "HTTP":
                        stage_response = self.apigatewayv2_client.get_routes(ApiId=response_detail['ApiId'])
                        for items in stage_response['Items']:
                            if items['AuthorizationType'] == "NONE":
                                self.apigateway_list.append(self.create_apigateway_item(
                                    'APIGateway.8',
                                    'API Gateway routes should specify an authorization type',
                                    'failed',
                                    'MEDIUM',
                                    'not_available',
                                    f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/routes/{items['RouteId']}"
                                ))
                            else:
                                self.apigateway_list.append(self.create_apigateway_item(
                                    'APIGateway.8',
                                    'API Gateway routes should specify an authorization type',
                                    'passed',
                                    'MEDIUM',
                                    'not_available',
                                    f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/routes/{items['RouteId']}"
                                ))
                    while 'NextToken' in stage_response:
                        stage_response = self.apigatewayv2_client.get_apis(NextToken=response['NextToken'])
                        for items in stage_response['Items']:
                            if items['AuthorizationType'] == "NONE":
                                self.apigateway_list.append(self.create_apigateway_item(
                                    'APIGateway.8',
                                    'API Gateway routes should specify an authorization type',
                                    'failed',
                                    'MEDIUM',
                                    'not_available',
                                    f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/routes/{items['RouteId']}"
                                ))
                            else:
                                self.apigateway_list.append(self.create_apigateway_item(
                                    'APIGateway.8',
                                    'API Gateway routes should specify an authorization type',
                                    'passed',
                                    'MEDIUM',
                                    'not_available',
                                    f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/routes/{items['RouteId']}"
                                ))
        except ClientError as e:
            print(f"Error: {e}")

    @DecoratorClass.my_decorator
    def apigateway_nine(self) -> None:
        try:
            if not self.apigatewayv2_client.get_apis()['Items'] \
            and not [response_detail \
            for response_detail in self.apigatewayv2_client.get_apis()['Items'] \
            if response_detail['ProtocolType'] == "HTTP"]:  # Check if no stages found
                self.apigateway_list.append(self.create_apigateway_item(
                    'APIGateway.9',
                    'Access logging should be configured for API Gateway V2 Stages',
                    'not_found',
                    'MEDIUM',
                    'available',
                    'not_found'
                ))
            response = self.apigatewayv2_client.get_apis()
            for response_detail in response['Items']:
                if response_detail['ProtocolType'] == "HTTP":
                    stage_response = self.apigatewayv2_client.get_stages(ApiId=response_detail['ApiId'])
                    for items in stage_response['Items']:
                        if 'AccessLogSettings' not in items:
                            self.apigateway_list.append(self.create_apigateway_item(
                                'APIGateway.9',
                                'Access logging should be configured for API Gateway V2 Stages',
                                'failed',
                                'MEDIUM',
                                'available',
                                f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/stages/{items['StageName']}"
                            ))
                        else:
                            self.apigateway_list.append(self.create_apigateway_item(
                                'APIGateway.9',
                                'Access logging should be configured for API Gateway V2 Stages',
                                'passed',
                                'MEDIUM',
                                'available',
                                f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/stages/{items['StageName']}"
                            ))
                    while 'NextToken' in stage_response:
                        stage_response = self.apigatewayv2_client.get_stages(ApiId=response_detail['ApiId'], \
                                                                                NextToken=stage_response['NextToken'])
                        for items in stage_response['Items']:
                            if 'AccessLogSettings' not in items:
                                self.apigateway_list.append(self.create_apigateway_item(
                                    'APIGateway.9',
                                    'Access logging should be configured for API Gateway V2 Stages',
                                    'failed',
                                    'MEDIUM',
                                    'available',
                                    f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/stages/{items['StageName']}"
                                ))
                            else:
                                self.apigateway_list.append(self.create_apigateway_item(
                                    'APIGateway.9',
                                    'Access logging should be configured for API Gateway V2 Stages',
                                    'passed',
                                    'MEDIUM',
                                    'available',
                                    f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/stages/{items['StageName']}"
                                ))
            while 'NextToken' in response:
                response = self.apigatewayv2_client.get_apis(NextToken=response['NextToken'])
                for response_detail in response['Items']:
                    if response_detail['ProtocolType'] == "HTTP":
                        stage_response = self.apigatewayv2_client.get_stages(ApiId=response_detail['ApiId'])
                        for items in stage_response['Items']:
                            if 'AccessLogSettings' not in items:
                                self.apigateway_list.append(self.create_apigateway_item(
                                    'APIGateway.9',
                                    'Access logging should be configured for API Gateway V2 Stages',
                                    'failed',
                                    'MEDIUM',
                                    'available',
                                    f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/stages/{items['StageName']}"
                                ))
                            else:
                                self.apigateway_list.append(self.create_apigateway_item(
                                    'APIGateway.9',
                                    'Access logging should be configured for API Gateway V2 Stages',
                                    'passed',
                                    'MEDIUM',
                                    'available',
                                    f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/stages/{items['StageName']}"
                                ))
                        while 'NextToken' in stage_response:
                            stage_response = self.apigatewayv2_client.get_stages(ApiId=response_detail['ApiId'], \
                                                                                    NextToken=stage_response['NextToken'])
                            for items in stage_response['Items']:
                                if 'AccessLogSettings' not in items:
                                    self.apigateway_list.append(self.create_apigateway_item(
                                        'APIGateway.9',
                                        'Access logging should be configured for API Gateway V2 Stages',
                                        'failed',
                                        'MEDIUM',
                                        'available',
                                        f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/stages/{items['StageName']}"
                                    ))
                                else:
                                    self.apigateway_list.append(self.create_apigateway_item(
                                        'APIGateway.9',
                                        'Access logging should be configured for API Gateway V2 Stages',
                                        'passed',
                                        'MEDIUM',
                                        'available',
                                        f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/stages/{items['StageName']}"
                                    ))
        except ClientError as e:
            print(f"Error: {e}")

class APIGatewayAutoRemediation:
    def __init__(self) -> None:
        self.apigateway_client = boto3.client('apigateway')
        self.apigatewayv2_client = boto3.client('apigatewayv2')
        self.iam_client = boto3.client('iam')
        self.kms_client = boto3.client('kms')
        self.logs_client = boto3.client('logs')
        self.session_region = boto3.session.Session().region_name
        self.session_account = boto3.client('sts').get_caller_identity().get('Account')
        
        # Variables use to detect and create CloudWatch role for API Gateway if not attach
        self.api_gw_cloudwatch_error_message = "CloudWatch Logs role ARN must be set in account settings to enable logging"
        self.role_name = 'api_gateway_cloudwatch_log_role'
        self.policy_name = 'AmazonAPIGatewayPushToCloudWatchLogs'
        self.trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "apigateway.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }

        # Variables use to check KMS key arn or create one if not exists
        self.automate_key_description = "Automate Security Remediation Key with Best Practices"
        self.policy_document = {
            "Version": "2012-10-17",
            "Id": "key-default-1",
            "Statement": [
                {
                    "Sid": "Enable IAM User Permissions",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{self.session_account}:root"
                    },
                    "Action": "kms:*",
                    "Resource": "*"
                },
                {
                    "Sid": "Enable CloudWatch Log Group Permissions",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "*"
                    },
                    "Action": [
                        "kms:Encrypt*",
                        "kms:Decrypt*",
                        "kms:ReEncrypt*",
                        "kms:GenerateDataKey*",
                        "kms:Describe*"
                    ],
                    "Resource": f"arn:aws:kms:{self.session_region}:{self.session_account}:key/*"
                }
            ]
        }
        
        # Run auto remediation
        self.remediate_apigateway_one()
        self.remediate_apigateway_three()
        self.remediate_apigateway_nine()

    def get_api_gateway_cloudwatch_arn(self) -> str:
        try:
            response = self.iam_client.get_role(
                RoleName=self.role_name
            )
            apigw_role_arn = response['Role']['Arn']
            return apigw_role_arn
        except ClientError as e:
            if e.response['Error']['Code'] == "NoSuchEntity":
                iam_role_response = self.iam_client.create_role(
                    RoleName=self.role_name,
                    AssumeRolePolicyDocument=json.dumps(self.trust_policy)
                )
                self.iam_client.attach_role_policy(
                    RoleName=self.role_name,
                    PolicyArn=f'arn:aws:iam::aws:policy/service-role/{self.policy_name}'
                )
                apigw_role_arn = iam_role_response['Role']['Arn']
                sleep(10)
                return apigw_role_arn
            else:
                print(f"Error: {e}")
                return ""

    def update_apigateway_account_cloudwatch(self) -> None:
        try:
            api_gateway_cloudwatch_arn = self.get_api_gateway_cloudwatch_arn()
            self.apigateway_client.update_account(
                patchOperations=[
                    {
                        'op': 'replace',
                        'path': '/cloudwatchRoleArn',
                        'value': api_gateway_cloudwatch_arn
                    }
                ]
            )
        except ClientError as e:
            print(f"Error: {e}")

    def remediate_apigateway_one_version_one(self, id: str, stage: str) -> None:
        try:
            self.apigateway_client.update_stage(
                restApiId=id,
                stageName=stage,
                patchOperations=[
                    {
                        'op': 'replace',
                        'path': '/*/*/logging/loglevel',
                        'value': 'INFO'
                    }
                ]
            )
            print(f"Auto remediated for APIGateway.1: arn:aws:apigateway:{self.session_region}::/restapis/{id}/stages/{stage}")
        except ClientError as e:
            if self.api_gw_cloudwatch_error_message in e.response['Error']['Message']:
                self.update_apigateway_account_cloudwatch()
                self.apigateway_client.update_stage(
                    restApiId=id,
                    stageName=stage,
                    patchOperations=[
                        {
                            'op': 'replace',
                            'path': '/*/*/logging/loglevel',
                            'value': 'INFO'
                        }
                    ]
                )
                print(f"Auto remediated for APIGateway.1: arn:aws:apigateway:{self.session_region}::/restapis/{id}/stages/{stage}")
            else:
                print(f"Error: {e}")

    def remediate_apigateway_one_version_two(self, id: str, stage: str) -> None:
        try:
            self.apigatewayv2_client.update_stage(
                ApiId=id,
                StageName=stage,
                DefaultRouteSettings={
                    'LoggingLevel': 'INFO'
                }
            )
            print(f"Auto remediated for APIGateway.1: arn:aws:apigateway:{self.session_region}::/apis/{id}/stages/{stage}")
        except ClientError as e:
            if self.api_gw_cloudwatch_error_message in e.response['Error']['Message']:
                self.update_apigateway_account_cloudwatch()
                self.apigatewayv2_client.update_stage(
                    ApiId=id,
                    StageName=stage,
                    DefaultRouteSettings={
                        'LoggingLevel': 'INFO'
                    }
                )
                print(f"Auto remediated for APIGateway.1: arn:aws:apigateway:{self.session_region}::/apis/{id}/stages/{stage}")
            else:
                print(f"Error: {e}")

    def remediate_apigateway_one(self) -> None:
        try:
            response = self.apigateway_client.get_rest_apis()
            for response_detail in response['items']:
                stage_response = self.apigateway_client.get_stages(restApiId=response_detail['id'])
                for item in stage_response['item']:
                    for _ in item['methodSettings']:
                        if item['methodSettings'][_]['loggingLevel'] == "OFF":
                            self.remediate_apigateway_one_version_one(response_detail['id'], item['stageName'])
                for _ in stage_response['item']:
                    if _['methodSettings'] == {}:
                        self.remediate_apigateway_one_version_one(response_detail['id'], _['stageName'])
            while 'position' in response:
                response = self.apigateway_client.get_rest_apis(position=response['position'])
                for response_detail in response['items']:
                    stage_response = self.apigateway_client.get_stages(restApiId=response_detail['id'])
                    for item in stage_response['item']:
                        for _ in item['methodSettings']:
                            if item['methodSettings'][_]['loggingLevel'] == "OFF":
                                self.remediate_apigateway_one_version_one(response_detail['id'], item['stageName'])
                    for _ in stage_response['item']:
                        if _['methodSettings'] == {}:
                            self.remediate_apigateway_one_version_one(response_detail['id'], _['stageName'])
            response = self.apigatewayv2_client.get_apis()
            for response_detail in response['Items']:
                if response_detail['ProtocolType'] == "WEBSOCKET":
                    stage_response = self.apigatewayv2_client.get_stages(ApiId=response_detail['ApiId'])
                    for _ in stage_response['Items']:
                        if _['DefaultRouteSettings']['LoggingLevel'] == "OFF":
                            self.remediate_apigateway_one_version_two(response_detail['ApiId'], _['StageName'])
                    while 'NextToken' in stage_response:
                        stage_response = self.apigatewayv2_client.get_stages(ApiId=response_detail['ApiId'], NextToken=stage_response['NextToken'])
                        for _ in stage_response['Items']:
                            if _['DefaultRouteSettings']['LoggingLevel'] == "OFF":
                                self.remediate_apigateway_one_version_two(response_detail['ApiId'], _['StageName'])
            while 'NextToken' in response:
                response = self.apigatewayv2_client.get_apis(NextToken=response['NextToken'])
                for response_detail in response['Items']:
                    if response_detail['ProtocolType'] == "WEBSOCKET":
                        stage_response = self.apigatewayv2_client.get_stages(ApiId=response_detail['ApiId'])
                        for _ in stage_response['Items']:
                            if _['DefaultRouteSettings']['LoggingLevel'] == "OFF":
                                self.remediate_apigateway_one_version_two(response_detail['ApiId'], _['StageName'])
                        while 'NextToken' in stage_response:
                            stage_response = self.apigatewayv2_client.get_stages(ApiId=response_detail['ApiId'], NextToken=stage_response['NextToken'])
                            for _ in stage_response['Items']:
                                if _['DefaultRouteSettings']['LoggingLevel'] == "OFF":
                                    self.remediate_apigateway_one_version_two(response_detail['ApiId'], _['StageName'])
        except ClientError as e:
            print(f"Error: {e}")

    def remediate_apigateway_three_action(self, id: str, stage: str) -> None:
        try:
            self.apigateway_client.update_stage(
                restApiId=id,
                stageName=stage,
                patchOperations=[
                    {
                        'op': 'replace',
                        'path': '/tracingEnabled',
                        'value': 'true'
                    }
                ]
            )
            print(f"Auto remediated for APIGateway.3: arn:aws:apigateway:{self.session_region}::/restapis/{id}/stages/{stage}")
        except ClientError as e:
            print(f"Error: {e}")

    def remediate_apigateway_three(self):
        try:
            response = self.apigateway_client.get_rest_apis()
            for response_detail in response['items']:
                stage_response = self.apigateway_client.get_stages(restApiId=response_detail['id'])
                [self.remediate_apigateway_three_action(response_detail['id'], \
                _['stageName']) \
                for _ in stage_response['item'] \
                if _['tracingEnabled'] == False]
            while 'position' in response:
                response = self.apigateway_client.get_rest_apis(position=response['position'])
                for response_detail in response['items']:
                    stage_response = self.apigateway_client.get_stages(restApiId=response_detail['id'])
                    [self.remediate_apigateway_three_action(response_detail['id'], \
                    _['stageName']) \
                    for _ in stage_response['item'] \
                    if _['tracingEnabled'] == False]
        except ClientError as e:
            print(f"Error: {e}")

    def create_kms_key(self) -> str:
        response = self.kms_client.create_key()
        key_id = response['KeyMetadata']['KeyId']
        key_arn = response['KeyMetadata']['Arn']
        self.kms_client.update_key_description(
            KeyId=key_id,
            Description=self.automate_key_description
        )
        # Attach the key policy to the created key
        self.kms_client.put_key_policy(
            KeyId=key_id,
            PolicyName='default',
            Policy=json.dumps(self.policy_document)
        )
        self.kms_client.create_alias(
            AliasName="alias/AutomateSecurityRemediationKey",
            TargetKeyId=key_id
        )
        self.kms_client.enable_key_rotation(
            KeyId=key_id
        )
        return key_arn

    def create_cloudwatch_log_group(self, id: str, stage: str) -> None:
        try:
            key_list: list[dict] = []
            response = self.kms_client.list_keys()
            key_list.extend(_ for _ in response['Keys'])
            while 'NextMarker' in response:
                response = self.kms_client.list_keys(Marker=response['NextMarker'])
                key_list.extend(_ for _ in response['Keys'])
            kms_key_arn_check = [_['KeyArn'] \
                    for _ in key_list \
                    if self.kms_client.describe_key(KeyId=_['KeyId'])['KeyMetadata']['Description'] == self.automate_key_description]
            if kms_key_arn_check:
                kms_key_arn = kms_key_arn_check[0]
            else:
                kms_key_arn = self.create_kms_key()
            self.logs_client.create_log_group(
                logGroupName=f"API-Gateway-Access-Logs_{id}/{stage}",
                kmsKeyId=kms_key_arn
            )
            self.logs_client.put_retention_policy(
                logGroupName=f"API-Gateway-Access-Logs_{id}/{stage}",
                retentionInDays=7
            )
        except ClientError as e:
            print(f"Error: {e}")

    def remediate_apigateway_nine_action(self, id: str, stage: str) -> None:
        try:
            converted_stage = stage.replace("$","")
            log_group_arn = f"arn:aws:logs:{self.session_region}:{self.session_account}:log-group:API-Gateway-Access-Logs_{id}/{converted_stage}"
            self.apigatewayv2_client.update_stage(
                ApiId=id,
                StageName=stage,
                AccessLogSettings={
                    'DestinationArn': log_group_arn,
                    'Format': '$context.identity.sourceIp - - [$context.requestTime] "$context.httpMethod $context.routeKey $context.protocol" $context.status $context.responseLength $context.requestId'
                }
            )
            print(f"Auto remediated for APIGateway.9: arn:aws:apigateway:{self.session_region}::/apis/{id}/stages/{stage}")
        except ClientError as e:
            if e.response['Error']['Code'] == "NotFoundException":
                converted_stage = stage.replace("$","")
                log_group_arn = f"arn:aws:logs:{self.session_region}:{self.session_account}:log-group:API-Gateway-Access-Logs_{id}/{converted_stage}"
                self.create_cloudwatch_log_group(id, converted_stage)
                self.apigatewayv2_client.update_stage(
                    ApiId=id,
                    StageName=stage,
                    AccessLogSettings={
                        'DestinationArn': log_group_arn,
                        'Format': '$context.identity.sourceIp - - [$context.requestTime] "$context.httpMethod $context.routeKey $context.protocol" $context.status $context.responseLength $context.requestId'
                    }
                )
                print(f"Auto remediated for APIGateway.9: arn:aws:apigateway:{self.session_region}::/apis/{id}/stages/{stage}")
            else:
                print(f"Error: {e}")

    def remediate_apigateway_nine(self) -> None:
        try:
            response = self.apigatewayv2_client.get_apis()
            for response_detail in response['Items']:
                if response_detail['ProtocolType'] == "HTTP":
                    stage_response = self.apigatewayv2_client.get_stages(ApiId=response_detail['ApiId'])
                    for _ in stage_response['Items']:
                        if 'AccessLogSettings' not in _:
                            self.remediate_apigateway_nine_action(response_detail['ApiId'], _['StageName'])
                    while 'NextToken' in stage_response:
                        stage_response = self.apigatewayv2_client.get_stages(ApiId=response_detail['ApiId'], \
                                                                                NextToken=stage_response['NextToken'])
                        for _ in stage_response['Items']:
                            if 'AccessLogSettings' not in _:
                                self.remediate_apigateway_nine_action(response_detail['ApiId'], _['StageName'])
            while 'NextToken' in response:
                response = self.apigatewayv2_client.get_apis(NextToken=response['NextToken'])
                for response_detail in response['Items']:
                    if response_detail['ProtocolType'] == "HTTP":
                        stage_response = self.apigatewayv2_client.get_stages(ApiId=response_detail['ApiId'])
                        for _ in stage_response['Items']:
                            if 'AccessLogSettings' not in _:
                                self.remediate_apigateway_nine_action(response_detail['ApiId'], _['StageName'])
                        while 'NextToken' in stage_response:
                            stage_response = self.apigatewayv2_client.get_stages(ApiId=response_detail['ApiId'], \
                                                                                    NextToken=stage_response['NextToken'])
                            for _ in stage_response['Items']:
                                if 'AccessLogSettings' not in _:
                                    self.remediate_apigateway_nine_action(response_detail['ApiId'], _['StageName'])
        except ClientError as e:
            print(f"Error: {e}")

class CrossAccountAPIGatewayComplianceChecker:
    def __init__(self) -> None:
        self.apigateway_client = UseCrossAccount().client('apigateway')
        self.apigatewayv2_client = UseCrossAccount().client('apigatewayv2')
        self.session_region = UseCrossAccount().session_region_name
        self.session_account = UseCrossAccount().client('sts').get_caller_identity().get('Account')

        self.apigateway_list = compliance_check_list

    def create_apigateway_item(self, control_id: str, control_title: str, compliance: str, severity: str, auto_remediation: str, resource_id: str) -> dict:
        if ParameterValidation().validate_parameter("APIGateway", control_id, compliance, severity, auto_remediation):
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
    
    @DecoratorClass.my_decorator
    def apigateway_one(self) -> None:
        try:
            if not self.apigateway_client.get_rest_apis()['items'] \
            and (not self.apigatewayv2_client.get_apis()['Items'] \
            or not any(response_detail['ProtocolType'] == "WEBSOCKET" \
            for response_detail in self.apigatewayv2_client.get_apis()['Items'])):  # Check if no stages found
                self.apigateway_list.append(self.create_apigateway_item(
                    'APIGateway.1',
                    'API Gateway REST and WebSocket API execution logging should be enabled',
                    'not_found',
                    'MEDIUM',
                    'available',
                    'not_found'
                ))
            response = self.apigateway_client.get_rest_apis()
            for response_detail in response['items']:
                stage_response = self.apigateway_client.get_stages(restApiId=response_detail['id'])
                for item in stage_response['item']:
                    if item['methodSettings'] == {}:
                        self.apigateway_list.append(self.create_apigateway_item(
                            'APIGateway.1',
                            'API Gateway REST and WebSocket API execution logging should be enabled',
                            'failed',
                            'MEDIUM',
                            'available',
                            f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                        ))
                    else:
                        for method in item['methodSettings']:
                            if item['methodSettings'][method]['loggingLevel'] == "OFF":
                                self.apigateway_list.append(self.create_apigateway_item(
                                    'APIGateway.1',
                                    'API Gateway REST and WebSocket API execution logging should be enabled',
                                    'failed',
                                    'MEDIUM',
                                    'available',
                                    f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                                ))
                            else:
                                self.apigateway_list.append(self.create_apigateway_item(
                                    'APIGateway.1',
                                    'API Gateway REST and WebSocket API execution logging should be enabled',
                                    'passed',
                                    'MEDIUM',
                                    'available',
                                    f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                                ))
            while 'position' in response:
                response = self.apigateway_client.get_rest_apis(position=response['position'])
                for response_detail in response['items']:
                    stage_response = self.apigateway_client.get_stages(restApiId=response_detail['id'])
                    for item in stage_response['item']:
                        if item['methodSettings'] == {}:
                            self.apigateway_list.append(self.create_apigateway_item(
                                'APIGateway.1',
                                'API Gateway REST and WebSocket API execution logging should be enabled',
                                'failed',
                                'MEDIUM',
                                'available',
                                f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                            ))
                        else:
                            for method in item['methodSettings']:
                                if item['methodSettings'][method]['loggingLevel'] == "OFF":
                                    self.apigateway_list.append(self.create_apigateway_item(
                                        'APIGateway.1',
                                        'API Gateway REST and WebSocket API execution logging should be enabled',
                                        'failed',
                                        'MEDIUM',
                                        'available',
                                        f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                                    ))
                                else:
                                    self.apigateway_list.append(self.create_apigateway_item(
                                        'APIGateway.1',
                                        'API Gateway REST and WebSocket API execution logging should be enabled',
                                        'passed',
                                        'MEDIUM',
                                        'available',
                                        f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                                    ))
            response = self.apigatewayv2_client.get_apis()
            for response_detail in response['Items']:
                if response_detail['ProtocolType'] == "WEBSOCKET":
                    stage_response = self.apigatewayv2_client.get_stages(ApiId=response_detail['ApiId'])
                    for items in stage_response['Items']:
                        if items['DefaultRouteSettings']['LoggingLevel'] == "OFF":
                            self.apigateway_list.append(self.create_apigateway_item(
                                'APIGateway.1',
                                'API Gateway REST and WebSocket API execution logging should be enabled',
                                'failed',
                                'MEDIUM',
                                'available',
                                f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/stages/{items['StageName']}"
                            ))
                        else:
                            self.apigateway_list.append(self.create_apigateway_item(
                                'APIGateway.1',
                                'API Gateway REST and WebSocket API execution logging should be enabled',
                                'passed',
                                'MEDIUM',
                                'available',
                                f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/stages/{items['StageName']}"
                            ))
                    while 'NextToken' in stage_response:
                        stage_response = self.apigatewayv2_client.get_stages(ApiId=response_detail['ApiId'], \
                                                                                NextToken=stage_response['NextToken'])
                        for items in stage_response['Items']:
                            if items['DefaultRouteSettings']['LoggingLevel'] == "OFF":
                                self.apigateway_list.append(self.create_apigateway_item(
                                    'APIGateway.1',
                                    'API Gateway REST and WebSocket API execution logging should be enabled',
                                    'failed',
                                    'MEDIUM',
                                    'available',
                                    f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/stages/{items['StageName']}"
                                ))
                            else:
                                self.apigateway_list.append(self.create_apigateway_item(
                                    'APIGateway.1',
                                    'API Gateway REST and WebSocket API execution logging should be enabled',
                                    'passed',
                                    'MEDIUM',
                                    'available',
                                    f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/stages/{items['StageName']}"
                                ))
            while 'NextToken' in response:
                response = self.apigatewayv2_client.get_apis(NextToken=response['NextToken'])
                for response_detail in response['Items']:
                    if response_detail['ProtocolType'] == "WEBSOCKET":
                        stage_response = self.apigatewayv2_client.get_stages(ApiId=response_detail['ApiId'])
                        for items in stage_response['Items']:
                            if items['DefaultRouteSettings']['LoggingLevel'] == "OFF":
                                self.apigateway_list.append(self.create_apigateway_item(
                                    'APIGateway.1',
                                    'API Gateway REST and WebSocket API execution logging should be enabled',
                                    'failed',
                                    'MEDIUM',
                                    'available',
                                    f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/stages/{items['StageName']}"
                                ))
                            else:
                                self.apigateway_list.append(self.create_apigateway_item(
                                    'APIGateway.1',
                                    'API Gateway REST and WebSocket API execution logging should be enabled',
                                    'passed',
                                    'MEDIUM',
                                    'available',
                                    f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/stages/{items['StageName']}"
                                ))
                        while 'NextToken' in stage_response:
                            stage_response = self.apigatewayv2_client.get_stages(ApiId=response_detail['ApiId'], \
                                                                                    NextToken=stage_response['NextToken'])
                            for items in stage_response['Items']:
                                if items['DefaultRouteSettings']['LoggingLevel'] == "OFF":
                                    self.apigateway_list.append(self.create_apigateway_item(
                                        'APIGateway.1',
                                        'API Gateway REST and WebSocket API execution logging should be enabled',
                                        'failed',
                                        'MEDIUM',
                                        'available',
                                        f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/stages/{items['StageName']}"
                                    ))
                                else:
                                    self.apigateway_list.append(self.create_apigateway_item(
                                        'APIGateway.1',
                                        'API Gateway REST and WebSocket API execution logging should be enabled',
                                        'passed',
                                        'MEDIUM',
                                        'available',
                                        f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/stages/{items['StageName']}"
                                    ))
        except ClientError as e:
            print(f"Error: {e}")

    @DecoratorClass.my_decorator
    def apigateway_two(self) -> None:
        try:
            if not self.apigateway_client.get_rest_apis()['items']:  # Check if no stages found
                self.apigateway_list.append(self.create_apigateway_item(
                    'APIGateway.2',
                    'API Gateway REST API stages should be configured to use SSL certificates for backend authentication',
                    'not_found',
                    'MEDIUM',
                    'not_available',
                    'not_found'
                ))
            response = self.apigateway_client.get_rest_apis()
            for response_detail in response['items']:
                stage_response = self.apigateway_client.get_stages(restApiId=response_detail['id'])
                for item in stage_response['item']:
                    if 'clientCertificateId' not in item:
                        self.apigateway_list.append(self.create_apigateway_item(
                            'APIGateway.2',
                            'API Gateway REST API stages should be configured to use SSL certificates for backend authentication',
                            'failed',
                            'MEDIUM',
                            'not_available',
                            f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                        ))
                    else:
                        self.apigateway_list.append(self.create_apigateway_item(
                            'APIGateway.2',
                            'API Gateway REST API stages should be configured to use SSL certificates for backend authentication',
                            'passed',
                            'MEDIUM',
                            'not_available',
                            f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                        ))
            while 'position' in response:
                response = self.apigateway_client.get_rest_apis(position=response['position'])
                for response_detail in response['items']:
                    stage_response = self.apigateway_client.get_stages(restApiId=response_detail['id'])
                    for item in stage_response['item']:
                        if 'clientCertificateId' not in item:
                            self.apigateway_list.append(self.create_apigateway_item(
                                'APIGateway.2',
                                'API Gateway REST API stages should be configured to use SSL certificates for backend authentication',
                                'failed',
                                'MEDIUM',
                                'not_available',
                                f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                            ))
                        else:
                            self.apigateway_list.append(self.create_apigateway_item(
                                'APIGateway.2',
                                'API Gateway REST API stages should be configured to use SSL certificates for backend authentication',
                                'passed',
                                'MEDIUM',
                                'not_available',
                                f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                            ))
        except ClientError as e:
            print(f"Error: {e}")

    @DecoratorClass.my_decorator
    def apigateway_three(self) -> None:
        try:
            if not self.apigateway_client.get_rest_apis()['items']:  # Check if no stages found
                self.apigateway_list.append(self.create_apigateway_item(
                    'APIGateway.3',
                    'API Gateway REST API stages should have AWS X-Ray tracing enabled',
                    'not_found',
                    'LOW',
                    'available',
                    'not_found'
                ))
            response = self.apigateway_client.get_rest_apis()
            for response_detail in response['items']:
                stage_response = self.apigateway_client.get_stages(restApiId=response_detail['id'])
                for item in stage_response['item']:
                    if item['tracingEnabled']  == False:
                        self.apigateway_list.append(self.create_apigateway_item(
                            'APIGateway.3',
                            'API Gateway REST API stages should have AWS X-Ray tracing enabled',
                            'failed',
                            'LOW',
                            'available',
                            f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                        ))
                    else:
                        self.apigateway_list.append(self.create_apigateway_item(
                            'APIGateway.3',
                            'API Gateway REST API stages should have AWS X-Ray tracing enabled',
                            'passed',
                            'LOW',
                            'available',
                            f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                        ))
            while 'position' in response:
                response = self.apigateway_client.get_rest_apis(position=response['position'])
                for response_detail in response['items']:
                    stage_response = self.apigateway_client.get_stages(restApiId=response_detail['id'])
                    for item in stage_response['item']:
                        if item['tracingEnabled']  == False:
                            self.apigateway_list.append(self.create_apigateway_item(
                                'APIGateway.3',
                                'API Gateway REST API stages should have AWS X-Ray tracing enabled',
                                'failed',
                                'LOW',
                                'available',
                                f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                            ))
                        else:
                            self.apigateway_list.append(self.create_apigateway_item(
                                'APIGateway.3',
                                'API Gateway REST API stages should have AWS X-Ray tracing enabled',
                                'passed',
                                'LOW',
                                'available',
                                f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                            ))
        except ClientError as e:
            print(f"Error: {e}")

    @DecoratorClass.my_decorator
    def apigateway_four(self) -> None:
        try:
            if not self.apigateway_client.get_rest_apis()['items']:  # Check if no stages found
                self.apigateway_list.append(self.create_apigateway_item(
                    'APIGateway.4',
                    'API Gateway should be associated with a WAF Web ACL',
                    'not_found',
                    'MEDIUM',
                    'not_available',
                    'not_found'
                ))
            response = self.apigateway_client.get_rest_apis()
            for response_detail in response['items']:
                stage_response = self.apigateway_client.get_stages(restApiId=response_detail['id'])
                for item in stage_response['item']:
                    if 'webAclArn' not in item:
                        self.apigateway_list.append(self.create_apigateway_item(
                            'APIGateway.4',
                            'API Gateway should be associated with a WAF Web ACL',
                            'failed',
                            'MEDIUM',
                            'not_available',
                            f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                        ))
                    else:
                        self.apigateway_list.append(self.create_apigateway_item(
                            'APIGateway.4',
                            'API Gateway should be associated with a WAF Web ACL',
                            'passed',
                            'MEDIUM',
                            'not_available',
                            f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                        ))
            while 'position' in response:
                response = self.apigateway_client.get_rest_apis(position=response['position'])
                for response_detail in response['items']:
                    stage_response = self.apigateway_client.get_stages(restApiId=response_detail['id'])
                    for item in stage_response['item']:
                        if 'webAclArn' not in item:
                            self.apigateway_list.append(self.create_apigateway_item(
                                'APIGateway.4',
                                'API Gateway should be associated with a WAF Web ACL',
                                'failed',
                                'MEDIUM',
                                'not_available',
                                f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                            ))
                        else:
                            self.apigateway_list.append(self.create_apigateway_item(
                                'APIGateway.4',
                                'API Gateway should be associated with a WAF Web ACL',
                                'passed',
                                'MEDIUM',
                                'not_available',
                                f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                            ))
        except ClientError as e:
            print(f"Error: {e}")

    @DecoratorClass.my_decorator
    def apigateway_five(self) -> None:
        try:
            if not self.apigateway_client.get_rest_apis()['items']:  # Check if no stages found
                self.apigateway_list.append(self.create_apigateway_item(
                    'APIGateway.5',
                    'API Gateway REST API cache data should be encrypted at rest',
                    'not_found',
                    'MEDIUM',
                    'not_available',
                    'not_found'
                ))
            response = self.apigateway_client.get_rest_apis()
            for response_detail in response['items']:
                stage_response = self.apigateway_client.get_stages(restApiId=response_detail['id'])
                for item in stage_response['item']:
                    if item['methodSettings'] == {}:
                        self.apigateway_list.append(self.create_apigateway_item(
                            'APIGateway.5',
                            'API Gateway REST API cache data should be encrypted at rest',
                            'failed',
                            'MEDIUM',
                            'not_available',
                            f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                        ))
                    else:
                        for method in item['methodSettings']:
                            if item['methodSettings'][method]['cacheDataEncrypted'] == False:
                                self.apigateway_list.append(self.create_apigateway_item(
                                    'APIGateway.5',
                                    'API Gateway REST API cache data should be encrypted at rest',
                                    'failed',
                                    'MEDIUM',
                                    'not_available',
                                    f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                                ))
                            else:
                                self.apigateway_list.append(self.create_apigateway_item(
                                    'APIGateway.5',
                                    'API Gateway REST API cache data should be encrypted at rest',
                                    'passed',
                                    'MEDIUM',
                                    'not_available',
                                    f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                                ))
            while 'position' in response:
                response = self.apigateway_client.get_rest_apis(position=response['position'])
                for response_detail in response['items']:
                    stage_response = self.apigateway_client.get_stages(restApiId=response_detail['id'])
                    for item in stage_response['item']:
                        if item['methodSettings'] == {}:
                            self.apigateway_list.append(self.create_apigateway_item(
                                'APIGateway.5',
                                'API Gateway REST API cache data should be encrypted at rest',
                                'failed',
                                'MEDIUM',
                                'not_available',
                                f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                            ))
                        else:
                            for method in item['methodSettings']:
                                if item['methodSettings'][method]['cacheDataEncrypted'] == False:
                                    self.apigateway_list.append(self.create_apigateway_item(
                                        'APIGateway.5',
                                        'API Gateway REST API cache data should be encrypted at rest',
                                        'failed',
                                        'MEDIUM',
                                        'not_available',
                                        f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                                    ))
                                else:
                                    self.apigateway_list.append(self.create_apigateway_item(
                                        'APIGateway.5',
                                        'API Gateway REST API cache data should be encrypted at rest',
                                        'passed',
                                        'MEDIUM',
                                        'not_available',
                                        f"arn:aws:apigateway:{self.session_region}::/restapis/{response_detail['id']}/stages/{item['stageName']}"
                                    ))
        except ClientError as e:
            print(f"Error: {e}")

    @DecoratorClass.my_decorator
    def apigateway_eight(self) -> None:
        try:
            if not self.apigatewayv2_client.get_apis()['Items'] \
            and not [response_detail \
            for response_detail in self.apigatewayv2_client.get_apis()['Items'] \
            if response_detail['ProtocolType'] == "HTTP"]:  # Check if no stages found
                self.apigateway_list.append(self.create_apigateway_item(
                    'APIGateway.8',
                    'API Gateway routes should specify an authorization type',
                    'not_found',
                    'MEDIUM',
                    'not_available',
                    'not_found'
                ))
            response = self.apigatewayv2_client.get_apis()
            for response_detail in response['Items']:
                if response_detail['ProtocolType'] == "HTTP":
                    stage_response = self.apigatewayv2_client.get_routes(ApiId=response_detail['ApiId'])
                    for items in stage_response['Items']:
                        if items['AuthorizationType'] == "NONE":
                            self.apigateway_list.append(self.create_apigateway_item(
                                'APIGateway.8',
                                'API Gateway routes should specify an authorization type',
                                'failed',
                                'MEDIUM',
                                'not_available',
                                f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/routes/{items['RouteId']}"
                            ))
                        else:
                            self.apigateway_list.append(self.create_apigateway_item(
                                'APIGateway.8',
                                'API Gateway routes should specify an authorization type',
                                'passed',
                                'MEDIUM',
                                'not_available',
                                f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/routes/{items['RouteId']}"
                            ))
                while 'NextToken' in stage_response:
                    stage_response = self.apigatewayv2_client.get_apis(NextToken=response['NextToken'])
                    for items in stage_response['Items']:
                        if items['AuthorizationType'] == "NONE":
                            self.apigateway_list.append(self.create_apigateway_item(
                                'APIGateway.8',
                                'API Gateway routes should specify an authorization type',
                                'failed',
                                'MEDIUM',
                                'not_available',
                                f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/routes/{items['RouteId']}"
                            ))
                        else:
                            self.apigateway_list.append(self.create_apigateway_item(
                                'APIGateway.8',
                                'API Gateway routes should specify an authorization type',
                                'passed',
                                'MEDIUM',
                                'not_available',
                                f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/routes/{items['RouteId']}"
                            ))
            while 'NextToken' in response:
                response = self.apigatewayv2_client.get_apis(NextToken=response['NextToken'])
                for response_detail in response['Items']:
                    if response_detail['ProtocolType'] == "HTTP":
                        stage_response = self.apigatewayv2_client.get_routes(ApiId=response_detail['ApiId'])
                        for items in stage_response['Items']:
                            if items['AuthorizationType'] == "NONE":
                                self.apigateway_list.append(self.create_apigateway_item(
                                    'APIGateway.8',
                                    'API Gateway routes should specify an authorization type',
                                    'failed',
                                    'MEDIUM',
                                    'not_available',
                                    f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/routes/{items['RouteId']}"
                                ))
                            else:
                                self.apigateway_list.append(self.create_apigateway_item(
                                    'APIGateway.8',
                                    'API Gateway routes should specify an authorization type',
                                    'passed',
                                    'MEDIUM',
                                    'not_available',
                                    f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/routes/{items['RouteId']}"
                                ))
                    while 'NextToken' in stage_response:
                        stage_response = self.apigatewayv2_client.get_apis(NextToken=response['NextToken'])
                        for items in stage_response['Items']:
                            if items['AuthorizationType'] == "NONE":
                                self.apigateway_list.append(self.create_apigateway_item(
                                    'APIGateway.8',
                                    'API Gateway routes should specify an authorization type',
                                    'failed',
                                    'MEDIUM',
                                    'not_available',
                                    f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/routes/{items['RouteId']}"
                                ))
                            else:
                                self.apigateway_list.append(self.create_apigateway_item(
                                    'APIGateway.8',
                                    'API Gateway routes should specify an authorization type',
                                    'passed',
                                    'MEDIUM',
                                    'not_available',
                                    f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/routes/{items['RouteId']}"
                                ))
        except ClientError as e:
            print(f"Error: {e}")

    @DecoratorClass.my_decorator
    def apigateway_nine(self) -> None:
        try:
            if not self.apigatewayv2_client.get_apis()['Items'] \
            and not [response_detail \
            for response_detail in self.apigatewayv2_client.get_apis()['Items'] \
            if response_detail['ProtocolType'] == "HTTP"]:  # Check if no stages found
                self.apigateway_list.append(self.create_apigateway_item(
                    'APIGateway.9',
                    'Access logging should be configured for API Gateway V2 Stages',
                    'not_found',
                    'MEDIUM',
                    'available',
                    'not_found'
                ))
            response = self.apigatewayv2_client.get_apis()
            for response_detail in response['Items']:
                if response_detail['ProtocolType'] == "HTTP":
                    stage_response = self.apigatewayv2_client.get_stages(ApiId=response_detail['ApiId'])
                    for items in stage_response['Items']:
                        if 'AccessLogSettings' not in items:
                            self.apigateway_list.append(self.create_apigateway_item(
                                'APIGateway.9',
                                'Access logging should be configured for API Gateway V2 Stages',
                                'failed',
                                'MEDIUM',
                                'available',
                                f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/stages/{items['StageName']}"
                            ))
                        else:
                            self.apigateway_list.append(self.create_apigateway_item(
                                'APIGateway.9',
                                'Access logging should be configured for API Gateway V2 Stages',
                                'passed',
                                'MEDIUM',
                                'available',
                                f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/stages/{items['StageName']}"
                            ))
                    while 'NextToken' in stage_response:
                        stage_response = self.apigatewayv2_client.get_stages(ApiId=response_detail['ApiId'], \
                                                                                NextToken=stage_response['NextToken'])
                        for items in stage_response['Items']:
                            if 'AccessLogSettings' not in items:
                                self.apigateway_list.append(self.create_apigateway_item(
                                    'APIGateway.9',
                                    'Access logging should be configured for API Gateway V2 Stages',
                                    'failed',
                                    'MEDIUM',
                                    'available',
                                    f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/stages/{items['StageName']}"
                                ))
                            else:
                                self.apigateway_list.append(self.create_apigateway_item(
                                    'APIGateway.9',
                                    'Access logging should be configured for API Gateway V2 Stages',
                                    'passed',
                                    'MEDIUM',
                                    'available',
                                    f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/stages/{items['StageName']}"
                                ))
            while 'NextToken' in response:
                response = self.apigatewayv2_client.get_apis(NextToken=response['NextToken'])
                for response_detail in response['Items']:
                    if response_detail['ProtocolType'] == "HTTP":
                        stage_response = self.apigatewayv2_client.get_stages(ApiId=response_detail['ApiId'])
                        for items in stage_response['Items']:
                            if 'AccessLogSettings' not in items:
                                self.apigateway_list.append(self.create_apigateway_item(
                                    'APIGateway.9',
                                    'Access logging should be configured for API Gateway V2 Stages',
                                    'failed',
                                    'MEDIUM',
                                    'available',
                                    f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/stages/{items['StageName']}"
                                ))
                            else:
                                self.apigateway_list.append(self.create_apigateway_item(
                                    'APIGateway.9',
                                    'Access logging should be configured for API Gateway V2 Stages',
                                    'passed',
                                    'MEDIUM',
                                    'available',
                                    f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/stages/{items['StageName']}"
                                ))
                        while 'NextToken' in stage_response:
                            stage_response = self.apigatewayv2_client.get_stages(ApiId=response_detail['ApiId'], \
                                                                                    NextToken=stage_response['NextToken'])
                            for items in stage_response['Items']:
                                if 'AccessLogSettings' not in items:
                                    self.apigateway_list.append(self.create_apigateway_item(
                                        'APIGateway.9',
                                        'Access logging should be configured for API Gateway V2 Stages',
                                        'failed',
                                        'MEDIUM',
                                        'available',
                                        f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/stages/{items['StageName']}"
                                    ))
                                else:
                                    self.apigateway_list.append(self.create_apigateway_item(
                                        'APIGateway.9',
                                        'Access logging should be configured for API Gateway V2 Stages',
                                        'passed',
                                        'MEDIUM',
                                        'available',
                                        f"arn:aws:apigateway:{self.session_region}::/apis/{response_detail['ApiId']}/stages/{items['StageName']}"
                                    ))
        except ClientError as e:
            print(f"Error: {e}")

class CrossAccountAPIGatewayAutoRemediation:
    def __init__(self) -> None:
        self.apigateway_client = UseCrossAccount().client('apigateway')
        self.apigatewayv2_client = UseCrossAccount().client('apigatewayv2')
        self.iam_client = UseCrossAccount().client('iam')
        self.kms_client = UseCrossAccount().client('kms')
        self.logs_client = UseCrossAccount().client('logs')
        self.session_region = UseCrossAccount().session_region_name
        self.session_account = UseCrossAccount().client('sts').get_caller_identity().get('Account')
        
        # Variables use to detect and create CloudWatch role for API Gateway if not attach
        self.api_gw_cloudwatch_error_message = "CloudWatch Logs role ARN must be set in account settings to enable logging"
        self.role_name = 'api_gateway_cloudwatch_log_role'
        self.policy_name = 'AmazonAPIGatewayPushToCloudWatchLogs'
        self.trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "apigateway.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }

        # Variables use to check KMS key arn or create one if not exists
        self.automate_key_description = "Automate Security Remediation Key with Best Practices"
        self.policy_document = {
            "Version": "2012-10-17",
            "Id": "key-default-1",
            "Statement": [
                {
                    "Sid": "Enable IAM User Permissions",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{self.session_account}:root"
                    },
                    "Action": "kms:*",
                    "Resource": "*"
                },
                {
                    "Sid": "Enable CloudWatch Log Group Permissions",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "*"
                    },
                    "Action": [
                        "kms:Encrypt*",
                        "kms:Decrypt*",
                        "kms:ReEncrypt*",
                        "kms:GenerateDataKey*",
                        "kms:Describe*"
                    ],
                    "Resource": f"arn:aws:kms:{self.session_region}:{self.session_account}:key/*"
                }
            ]
        }
        
        # Run auto remediation
        self.remediate_apigateway_one()
        self.remediate_apigateway_three()
        self.remediate_apigateway_nine()

    def get_api_gateway_cloudwatch_arn(self) -> str:
        try:
            response = self.iam_client.get_role(
                RoleName=self.role_name
            )
            apigw_role_arn = response['Role']['Arn']
            return apigw_role_arn
        except ClientError as e:
            if e.response['Error']['Code'] == "NoSuchEntity":
                iam_role_response = self.iam_client.create_role(
                    RoleName=self.role_name,
                    AssumeRolePolicyDocument=json.dumps(self.trust_policy)
                )
                self.iam_client.attach_role_policy(
                    RoleName=self.role_name,
                    PolicyArn=f'arn:aws:iam::aws:policy/service-role/{self.policy_name}'
                )
                apigw_role_arn = iam_role_response['Role']['Arn']
                sleep(10)
                return apigw_role_arn
            else:
                print(f"Error: {e}")
                return ""

    def update_apigateway_account_cloudwatch(self) -> None:
        try:
            api_gateway_cloudwatch_arn = self.get_api_gateway_cloudwatch_arn()
            self.apigateway_client.update_account(
                patchOperations=[
                    {
                        'op': 'replace',
                        'path': '/cloudwatchRoleArn',
                        'value': api_gateway_cloudwatch_arn
                    }
                ]
            )
        except ClientError as e:
            print(f"Error: {e}")

    def remediate_apigateway_one_version_one(self, id: str, stage: str) -> None:
        try:
            self.apigateway_client.update_stage(
                restApiId=id,
                stageName=stage,
                patchOperations=[
                    {
                        'op': 'replace',
                        'path': '/*/*/logging/loglevel',
                        'value': 'INFO'
                    }
                ]
            )
            print(f"Auto remediated for APIGateway.1: arn:aws:apigateway:{self.session_region}::/restapis/{id}/stages/{stage}")
        except ClientError as e:
            if self.api_gw_cloudwatch_error_message in e.response['Error']['Message']:
                self.update_apigateway_account_cloudwatch()
                self.apigateway_client.update_stage(
                    restApiId=id,
                    stageName=stage,
                    patchOperations=[
                        {
                            'op': 'replace',
                            'path': '/*/*/logging/loglevel',
                            'value': 'INFO'
                        }
                    ]
                )
                print(f"Auto remediated for APIGateway.1: arn:aws:apigateway:{self.session_region}::/restapis/{id}/stages/{stage}")
            else:
                print(f"Error: {e}")

    def remediate_apigateway_one_version_two(self, id: str, stage: str) -> None:
        try:
            self.apigatewayv2_client.update_stage(
                ApiId=id,
                StageName=stage,
                DefaultRouteSettings={
                    'LoggingLevel': 'INFO'
                }
            )
            print(f"Auto remediated for APIGateway.1: arn:aws:apigateway:{self.session_region}::/apis/{id}/stages/{stage}")
        except ClientError as e:
            if self.api_gw_cloudwatch_error_message in e.response['Error']['Message']:
                self.update_apigateway_account_cloudwatch()
                self.apigatewayv2_client.update_stage(
                    ApiId=id,
                    StageName=stage,
                    DefaultRouteSettings={
                        'LoggingLevel': 'INFO'
                    }
                )
                print(f"Auto remediated for APIGateway.1: arn:aws:apigateway:{self.session_region}::/apis/{id}/stages/{stage}")
            else:
                print(f"Error: {e}")

    def remediate_apigateway_one(self) -> None:
        try:
            response = self.apigateway_client.get_rest_apis()
            for response_detail in response['items']:
                stage_response = self.apigateway_client.get_stages(restApiId=response_detail['id'])
                for item in stage_response['item']:
                    for _ in item['methodSettings']:
                        if item['methodSettings'][_]['loggingLevel'] == "OFF":
                            self.remediate_apigateway_one_version_one(response_detail['id'], item['stageName'])
                for _ in stage_response['item']:
                    if _['methodSettings'] == {}:
                        self.remediate_apigateway_one_version_one(response_detail['id'], _['stageName'])
            while 'position' in response:
                response = self.apigateway_client.get_rest_apis(position=response['position'])
                for response_detail in response['items']:
                    stage_response = self.apigateway_client.get_stages(restApiId=response_detail['id'])
                    for item in stage_response['item']:
                        for _ in item['methodSettings']:
                            if item['methodSettings'][_]['loggingLevel'] == "OFF":
                                self.remediate_apigateway_one_version_one(response_detail['id'], item['stageName'])
                    for _ in stage_response['item']:
                        if _['methodSettings'] == {}:
                            self.remediate_apigateway_one_version_one(response_detail['id'], _['stageName'])
            response = self.apigatewayv2_client.get_apis()
            for response_detail in response['Items']:
                if response_detail['ProtocolType'] == "WEBSOCKET":
                    stage_response = self.apigatewayv2_client.get_stages(ApiId=response_detail['ApiId'])
                    for _ in stage_response['Items']:
                        if _['DefaultRouteSettings']['LoggingLevel'] == "OFF":
                            self.remediate_apigateway_one_version_two(response_detail['ApiId'], _['StageName'])
                    while 'NextToken' in stage_response:
                        stage_response = self.apigatewayv2_client.get_stages(ApiId=response_detail['ApiId'], NextToken=stage_response['NextToken'])
                        for _ in stage_response['Items']:
                            if _['DefaultRouteSettings']['LoggingLevel'] == "OFF":
                                self.remediate_apigateway_one_version_two(response_detail['ApiId'], _['StageName'])
            while 'NextToken' in response:
                response = self.apigatewayv2_client.get_apis(NextToken=response['NextToken'])
                for response_detail in response['Items']:
                    if response_detail['ProtocolType'] == "WEBSOCKET":
                        stage_response = self.apigatewayv2_client.get_stages(ApiId=response_detail['ApiId'])
                        for _ in stage_response['Items']:
                            if _['DefaultRouteSettings']['LoggingLevel'] == "OFF":
                                self.remediate_apigateway_one_version_two(response_detail['ApiId'], _['StageName'])
                        while 'NextToken' in stage_response:
                            stage_response = self.apigatewayv2_client.get_stages(ApiId=response_detail['ApiId'], NextToken=stage_response['NextToken'])
                            for _ in stage_response['Items']:
                                if _['DefaultRouteSettings']['LoggingLevel'] == "OFF":
                                    self.remediate_apigateway_one_version_two(response_detail['ApiId'], _['StageName'])
        except ClientError as e:
            print(f"Error: {e}")

    def remediate_apigateway_three_action(self, id: str, stage: str) -> None:
        try:
            self.apigateway_client.update_stage(
                restApiId=id,
                stageName=stage,
                patchOperations=[
                    {
                        'op': 'replace',
                        'path': '/tracingEnabled',
                        'value': 'true'
                    }
                ]
            )
            print(f"Auto remediated for APIGateway.3: arn:aws:apigateway:{self.session_region}::/restapis/{id}/stages/{stage}")
        except ClientError as e:
            print(f"Error: {e}")

    def remediate_apigateway_three(self):
        try:
            response = self.apigateway_client.get_rest_apis()
            for response_detail in response['items']:
                stage_response = self.apigateway_client.get_stages(restApiId=response_detail['id'])
                [self.remediate_apigateway_three_action(response_detail['id'], \
                _['stageName']) \
                for _ in stage_response['item'] \
                if _['tracingEnabled'] == False]
            while 'position' in response:
                response = self.apigateway_client.get_rest_apis(position=response['position'])
                for response_detail in response['items']:
                    stage_response = self.apigateway_client.get_stages(restApiId=response_detail['id'])
                    [self.remediate_apigateway_three_action(response_detail['id'], \
                    _['stageName']) \
                    for _ in stage_response['item'] \
                    if _['tracingEnabled'] == False]
        except ClientError as e:
            print(f"Error: {e}")

    def create_kms_key(self) -> str:
        response = self.kms_client.create_key()
        key_id = response['KeyMetadata']['KeyId']
        key_arn = response['KeyMetadata']['Arn']
        self.kms_client.update_key_description(
            KeyId=key_id,
            Description=self.automate_key_description
        )
        # Attach the key policy to the created key
        self.kms_client.put_key_policy(
            KeyId=key_id,
            PolicyName='default',
            Policy=json.dumps(self.policy_document)
        )
        self.kms_client.create_alias(
            AliasName="alias/AutomateSecurityRemediationKey",
            TargetKeyId=key_id
        )
        self.kms_client.enable_key_rotation(
            KeyId=key_id
        )
        return key_arn

    def create_cloudwatch_log_group(self, id: str, stage: str) -> None:
        try:
            key_list: list[dict] = []
            response = self.kms_client.list_keys()
            key_list.extend(_ for _ in response['Keys'])
            while 'NextMarker' in response:
                response = self.kms_client.list_keys(Marker=response['NextMarker'])
                key_list.extend(_ for _ in response['Keys'])
            kms_key_arn_check = [_['KeyArn'] \
                    for _ in key_list \
                    if self.kms_client.describe_key(KeyId=_['KeyId'])['KeyMetadata']['Description'] == self.automate_key_description]
            if kms_key_arn_check:
                kms_key_arn = kms_key_arn_check[0]
            else:
                kms_key_arn = self.create_kms_key()
            self.logs_client.create_log_group(
                logGroupName=f"API-Gateway-Access-Logs_{id}/{stage}",
                kmsKeyId=kms_key_arn
            )
            self.logs_client.put_retention_policy(
                logGroupName=f"API-Gateway-Access-Logs_{id}/{stage}",
                retentionInDays=7
            )
        except ClientError as e:
            print(f"Error: {e}")

    def remediate_apigateway_nine_action(self, id: str, stage: str) -> None:
        try:
            converted_stage = stage.replace("$","")
            log_group_arn = f"arn:aws:logs:{self.session_region}:{self.session_account}:log-group:API-Gateway-Access-Logs_{id}/{converted_stage}"
            self.apigatewayv2_client.update_stage(
                ApiId=id,
                StageName=stage,
                AccessLogSettings={
                    'DestinationArn': log_group_arn,
                    'Format': '$context.identity.sourceIp - - [$context.requestTime] "$context.httpMethod $context.routeKey $context.protocol" $context.status $context.responseLength $context.requestId'
                }
            )
            print(f"Auto remediated for APIGateway.9: arn:aws:apigateway:{self.session_region}::/apis/{id}/stages/{stage}")
        except ClientError as e:
            if e.response['Error']['Code'] == "NotFoundException":
                converted_stage = stage.replace("$","")
                log_group_arn = f"arn:aws:logs:{self.session_region}:{self.session_account}:log-group:API-Gateway-Access-Logs_{id}/{converted_stage}"
                self.create_cloudwatch_log_group(id, converted_stage)
                self.apigatewayv2_client.update_stage(
                    ApiId=id,
                    StageName=stage,
                    AccessLogSettings={
                        'DestinationArn': log_group_arn,
                        'Format': '$context.identity.sourceIp - - [$context.requestTime] "$context.httpMethod $context.routeKey $context.protocol" $context.status $context.responseLength $context.requestId'
                    }
                )
                print(f"Auto remediated for APIGateway.9: arn:aws:apigateway:{self.session_region}::/apis/{id}/stages/{stage}")
            else:
                print(f"Error: {e}")

    def remediate_apigateway_nine(self) -> None:
        try:
            response = self.apigatewayv2_client.get_apis()
            for response_detail in response['Items']:
                if response_detail['ProtocolType'] == "HTTP":
                    stage_response = self.apigatewayv2_client.get_stages(ApiId=response_detail['ApiId'])
                    for _ in stage_response['Items']:
                        if 'AccessLogSettings' not in _:
                            self.remediate_apigateway_nine_action(response_detail['ApiId'], _['StageName'])
                    while 'NextToken' in stage_response:
                        stage_response = self.apigatewayv2_client.get_stages(ApiId=response_detail['ApiId'], \
                                                                                NextToken=stage_response['NextToken'])
                        for _ in stage_response['Items']:
                            if 'AccessLogSettings' not in _:
                                self.remediate_apigateway_nine_action(response_detail['ApiId'], _['StageName'])
            while 'NextToken' in response:
                response = self.apigatewayv2_client.get_apis(NextToken=response['NextToken'])
                for response_detail in response['Items']:
                    if response_detail['ProtocolType'] == "HTTP":
                        stage_response = self.apigatewayv2_client.get_stages(ApiId=response_detail['ApiId'])
                        for _ in stage_response['Items']:
                            if 'AccessLogSettings' not in _:
                                self.remediate_apigateway_nine_action(response_detail['ApiId'], _['StageName'])
                        while 'NextToken' in stage_response:
                            stage_response = self.apigatewayv2_client.get_stages(ApiId=response_detail['ApiId'], \
                                                                                    NextToken=stage_response['NextToken'])
                            for _ in stage_response['Items']:
                                if 'AccessLogSettings' not in _:
                                    self.remediate_apigateway_nine_action(response_detail['ApiId'], _['StageName'])
        except ClientError as e:
            print(f"Error: {e}")