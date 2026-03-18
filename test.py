import boto3
import json

wafv2_client = boto3.client('wafv2')
apigw_client = boto3.client('apigateway')

def evaluate_compliance(config_item):
    # Get API Gateway REST API
    rest_api_id = config_item['configuration']['id']

    # Check stages for WebACL associations
    stages = apigw_client.get_stages(restApiId=rest_api_id)

    for stage in stages['item']:
        web_acl_arn = stage.get('webAclArn')

        if not web_acl_arn:
            return 'NON_COMPLIANT', 'No WAFv2 WebACL attached'

        # Get WebACL configuration
        web_acl = wafv2_client.get_web_acl(
            Id=web_acl_arn.split('/')[-2],
            Name=web_acl_arn.split('/')[-1],
            Scope='REGIONAL'
        )

        # Check for Log4j protection rule
        has_log4j_protection = False
        for rule in web_acl['WebACL']['Rules']:
            if 'AWSManagedRulesKnownBadInputsRuleSet' in str(rule):
                has_log4j_protection = True
                break

        if not has_log4j_protection:
            return 'NON_COMPLIANT', 'WebACL missing Log4j AMR protection'

    return 'COMPLIANT', 'WebACL configured with Log4j protection'
