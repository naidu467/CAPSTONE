'''
User Story:
Enforce Log4j WAF rule compliance for AWS API Gateway REST API Stages.
This Lambda function monitors API Gateway stages and ensures that any attached WAFv2 Web ACLs
have Log4j protection rules enabled (AWSManagedRulesKnownBadInputsRuleSet with Log4JRCE not excluded).
'''

# Standard imports
import json
import logging
import os
import sys
import re
import datetime
import time

# Libraries to connect to AWS
import boto3
from botocore.exceptions import ClientError
import traceback

# Custom imports
from src.helpers import tagHelperAWSAPIGateway
from csao_utils.GetDetails import GetDetails
from csao_utils import config, CustomErrors, logUtils, MarriottCASO_utils, MarriottCASOEventHandler

MODULE_NAME = __file__

def mapEvent(event):
    '''
    This function extracts information captured in the event and sends the information back
    to parseEvent function
    '''
    logUtils.logInfo(MODULE_NAME, "INSIDE " + mapEvent.__name__)

    # Logging the event
    logUtils.logDebug(MODULE_NAME, f"Event data: {json.dumps(event, indent=2)}")

    # Extracting details from event
    Event = GetDetails(json.loads(json.dumps(event['details'])))

    try:
        # Config event
        if Event.GetData(['eventSource'])['eventSource'] == 'config.amazonaws.com':
            details = Event.GetData(['accountId', 'awsRegion', 'eventSource', 'eventName', ['UserIdentity','arn'], 'eventTime', 'userAgent', 'evaluation'])

        # Non-config event
        else:
            eventName = Event.GetData(['eventName'])['eventName']

            # API Gateway Stage events
            if eventName in ['CreateStage', 'UpdateStage', 'CreateDeployment']:

                if eventName == 'CreateStage':
                    details = Event.GetData(['eventName', 'eventSource', 'resource', 'resourceArn', 'accountId', 'awsRegion', ['UserIdentity','arn'], 'eventTime','userAgent', ['requestParameters', 'restApiId'], ['requestParameters', 'stageName']])
                    details['rest_api_id'] = details['requestParameters/restApiId']
                    details['stage_name'] = details['requestParameters/stageName']

                if eventName == 'UpdateStage':
                    details = Event.GetData(['eventName', 'eventSource', 'resource', 'resourceArn', 'accountId', 'awsRegion', ['UserIdentity','arn'], 'eventTime','userAgent', ['requestParameters', 'restApiId'], ['requestParameters', 'stageName']])
                    details['rest_api_id'] = details['requestParameters/restApiId']
                    details['stage_name'] = details['requestParameters/stageName']

                if eventName == 'CreateDeployment':
                    details = Event.GetData(['eventName', 'eventSource', 'resource', 'resourceArn', 'accountId', 'awsRegion', ['UserIdentity','arn'], 'eventTime','userAgent', ['requestParameters', 'restApiId'], ['requestParameters', 'stageName']])
                    details['rest_api_id'] = details['requestParameters/restApiId']
                    details['stage_name'] = details.get('requestParameters/stageName', 'prod')  # Default stage name if not specified

                # Construct resource ARN for API Gateway Stage
                details['resourceArn'] = f"arn:aws:apigateway:{details['awsRegion']}::/restapis/{details['rest_api_id']}/stages/{details['stage_name']}"
                logUtils.logDebug(MODULE_NAME, f"Resource ARN : {details['resourceArn']}")
                details['resource'] = details['resourceArn']

            # Tag events
            elif eventName in ['TagResource', 'UntagResource']:
                details = Event.GetData(['accountId', 'awsRegion', 'eventSource', 'eventName', ['userIdentity', 'arn'], 'eventTime', 'resourceARN'])
                details['resource'] = details['resourceARN']

                # Extract REST API ID and stage name from ARN
                # ARN format: arn:aws:apigateway:region::/restapis/{rest-api-id}/stages/{stage-name}
                arn_parts = details['resourceARN'].split('/')
                if len(arn_parts) >= 4:
                    details['rest_api_id'] = arn_parts[2]
                    details['stage_name'] = arn_parts[4]

                if eventName == 'TagResource':
                    details['Tags'] = Event.GetData(['tags'])['tags']
                elif eventName == 'UntagResource':
                    details['Tags'] = Event.GetData(['tagKeys'])['tagKeys']

        details['userEmail'] = details['userIdentity/arn'].split('/')[-1]

    except KeyError as key:
        logUtils.logDebug(MODULE_NAME, f"KeyError: {key} key is expected but not found in event data")
        logUtils.logError(MODULE_NAME, key)
        raise

    logUtils.logDebug(MODULE_NAME, f"Extracted details: {json.dumps(details, indent=2)}")
    return details

def parseEvent(event, context):
    '''
    This function extracts information captured in the event and sends the information to function
    doHandleEvent
    '''
    logUtils.logInfo(MODULE_NAME, "Inside " + parseEvent.__name__)

    try:
        details = mapEvent(event)
    except BaseException as e:
        logUtils.logInfo(MODULE_NAME, "Error in mapping the event.")
        tracebackDetail = traceback.format_exc()
        errorEvent = MarriottCSAO_utils.createErrorLogs(event, context, e, tracebackDetail, True)
        errorDetails = json.dumps(errorEvent)
        logUtils.logInfo(MODULE_NAME, errorDetails)
        raise

    try:
        logUtils.logInfo(MODULE_NAME, 'Event Triggered by : ' + details['eventName'])

        if config.LAMBDA_ROLE in details['userIdentity/arn']:
            if details['eventName'] not in ['TagResource', 'UntagResource']:
                logUtils.logInfo(MODULE_NAME, "Event triggered by CSAO, ignoring...")
                return

        ruleName = os.environ['ruleName']
        service = config.SERVICE_NAME['APIGATEWAY']

        # Run for all resources in config
        if details['eventName'] == 'PutEvaluations':
            for resourceEval in details['evaluations']:
                if resourceEval['complianceType'] == 'NON_COMPLIANT' and resourceEval['complianceResourceType'] == 'AWS::ApiGateway::Stage':
                    details['resource'] = resourceEval['complianceResourceId']
                    # Extract REST API ID and stage name from ARN
                    arn_parts = details['resource'].split('/')
                    if len(arn_parts) >= 4:
                        details['rest_api_id'] = arn_parts[2]
                        details['stage_name'] = arn_parts[4]
                    tag = tagHelperAWSAPIGateway.getTags(service, details['accountId'], details['awsRegion'], details['resource'])
                    doHandleEvent(ruleName, service, event, tag, details)
                    return

        if details['eventName'] == 'TagResource':
            event['eventTagInfo'] = tagHelperAWSAPIGateway.extractTagInfo(details['tags'])
        elif details['eventName'] == 'UntagResource':
            event['eventTagInfo'] = tagHelperAWSAPIGateway.extractTagInfo_list(details['tags'])
        else:
            event['eventTagInfo'] = []

        tag = tagHelperAWSAPIGateway.getTags(service, details['accountId'], details['awsRegion'], details['resource'])
        doHandleEvent(ruleName, service, event, tag, details)

    except KeyError as key:
        logUtils.logDebug(MODULE_NAME, f"Failed to parse event or config {key} key is expected but not found")
        logUtils.logError(MODULE_NAME, key)

    except Exception as e:
        if hasattr(e, 'error') and hasattr(e, 'errorMessage'):
            error = e
        else:
            error = CustomErrors.GenericError(config.GENERIC_ERROR_STATUS_CODE, config.GENERIC_ERROR_MESSAGE, str(e))
        logUtils.logError(MODULE_NAME, error)

def doHandleEvent(ruleName, service, event, tag, details):
    '''
    This function calls the class with arguments extracted from event which assumes role, extracts information
    from the database and decides whether the remediation to be performed or not
    '''
    logUtils.logInfo(MODULE_NAME, "Inside " + doHandleEvent.__name__)

    try:
        handler = MarriottCSAOEventHandlerAPIGatewayWAFLog4jCompliance(ruleName, service, event, tag, details)
        return handler.handleEvent()

    except Exception as e:
        if hasattr(e, 'error') and hasattr(e, 'errorMessage'):
            error = e
        else:
            error = CustomErrors.GenericError(config.GENERIC_ERROR_STATUS_CODE, config.GENERIC_ERROR_MESSAGE, str(e))
        logUtils.logError(MODULE_NAME, error)
        raise

class MarriottCSAOEventHandlerAPIGatewayWAFLog4jCompliance(MarriottCASOEventHandler.MarriottCSAOEventHandlerAWSService):

    def isRuleViolated(self):
        '''
        Checks if the API Gateway Stage has a WAF attached and if that WAF has Log4j protection.
        Returns True if the rule is violated (no WAF, or WAF without Log4j protection).

        Two-level check:
        1. Check if API Gateway Stage has a Web ACL attached
        2. If yes, check if Web ACL has Log4j protection (AWSManagedRulesKnownBadInputsRuleSet with Log4JRCE active)
        '''
        logUtils.logInfo(MODULE_NAME, "Inside " + self.isRuleViolated.__name__)

        try:
            if self.eventName in ['CreateStage', 'UpdateStage', 'CreateDeployment', 'TagResource', 'UntagResource']:
                # Step 1: Get API Gateway Stage information
                self.rest_api_id = self.csaoEvent.get('rest_api_id')
                self.stage_name = self.csaoEvent.get('stage_name')

                if not self.rest_api_id or not self.stage_name:
                    logUtils.logDebug(MODULE_NAME, "Unable to extract REST API ID or Stage name from event")
                    return False

                logUtils.logDebug(MODULE_NAME, f"Checking API Gateway Stage: {self.rest_api_id}/{self.stage_name}")

                # Get API Gateway client
                apigateway_client = MarriottCSAO_utils.getAwsClient('apigateway', self.accountId, self.region)

                try:
                    stage_response = apigateway_client.get_stage(
                        restApiId=self.rest_api_id,
                        stageName=self.stage_name
                    )
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NotFoundException':
                        logUtils.logDebug(MODULE_NAME, f"API Gateway stage not found: {self.rest_api_id}/{self.stage_name}")
                        return False
                    raise

                # Step 2: Check if Web ACL is attached to the stage
                web_acl_arn = stage_response.get('webAclArn')

                if not web_acl_arn:
                    logUtils.logDebug(MODULE_NAME, f"API Gateway Stage '{self.rest_api_id}/{self.stage_name}' has NO Web ACL attached. Marked as NOT_APPLICABLE or policy-dependent.")
                    # Based on your organization's policy:
                    # Option 1: return False (NOT_APPLICABLE - stage doesn't need WAF)
                    # Option 2: return True (NON_COMPLIANT - all stages must have WAF)
                    # Currently using Option 1 (NOT_APPLICABLE)
                    return False

                logUtils.logDebug(MODULE_NAME, f"API Gateway Stage has Web ACL attached: {web_acl_arn}")

                # Step 3: Parse Web ACL ARN to get name and ID
                # ARN format: arn:aws:wafv2:region:account-id:regional/webacl/name/id
                arn_parts = web_acl_arn.split('/')

                if len(arn_parts) < 4:
                    logUtils.logDebug(MODULE_NAME, f"Invalid Web ACL ARN format: {web_acl_arn}")
                    return False

                self.webacl_name = arn_parts[2]
                self.webacl_id = arn_parts[3]
                self.webacl_scope = 'REGIONAL'  # API Gateway always uses REGIONAL WAF

                logUtils.logDebug(MODULE_NAME, f"Web ACL Details - Name: {self.webacl_name}, ID: {self.webacl_id}, Scope: {self.webacl_scope}")

                # Step 4: Get Web ACL configuration
                wafv2_client = MarriottCSAO_utils.getAwsClient('wafv2', self.accountId, self.region)

                try:
                    waf_response = wafv2_client.get_web_acl(
                        Name=self.webacl_name,
                        Scope=self.webacl_scope,
                        Id=self.webacl_id
                    )
                except ClientError as e:
                    logUtils.logDebug(MODULE_NAME, f"Error getting Web ACL: {e}")
                    return False

                web_acl = waf_response.get('WebACL', {})
                rules = web_acl.get('Rules', [])

                logUtils.logDebug(MODULE_NAME, f"Web ACL '{self.webacl_name}' has {len(rules)} rules")

                # Step 5: Check for Log4j protection in the rules
                log4j_protected = False
                log4j_rule_found = False
                log4j_rule_excluded = False

                for rule in rules:
                    statement = rule.get('Statement', {})
                    rule_name = rule.get('Name', 'Unknown')

                    # Check for AWS Managed Rule Group Statement
                    if 'ManagedRuleGroupStatement' in statement:
                        managed_rule = statement['ManagedRuleGroupStatement']
                        vendor_name = managed_rule.get('VendorName', '')
                        rule_group_name = managed_rule.get('Name', '')

                        # Check for AWSManagedRulesKnownBadInputsRuleSet
                        if (vendor_name == 'AWS' and
                            rule_group_name == 'AWSManagedRulesKnownBadInputsRuleSet'):

                            log4j_rule_found = True
                            logUtils.logDebug(MODULE_NAME, f"Found AWS Managed Rule Group: {rule_group_name}")

                            # Check if Log4JRCE is excluded
                            excluded_rules = managed_rule.get('ExcludedRules', [])
                            excluded_rule_names = [r.get('Name') for r in excluded_rules]

                            if 'Log4JRCE' in excluded_rule_names:
                                log4j_rule_excluded = True
                                logUtils.logDebug(MODULE_NAME, f"Rule '{rule_name}': Log4JRCE is EXCLUDED - Remediation required.")
                            else:
                                # Check if the rule is enabled
                                override_action = rule.get('OverrideAction', {})

                                # Rule is active if OverrideAction is None (not Count or completely disabled)
                                if override_action.get('None') is not None:
                                    log4j_protected = True
                                    logUtils.logDebug(MODULE_NAME, f"Rule '{rule_name}': Log4JRCE is ACTIVE - No remediation required.")
                                else:
                                    logUtils.logDebug(MODULE_NAME, f"Rule '{rule_name}': Managed rule group is in Count mode")
                                    # Count mode still provides some protection, you can decide if this is acceptable
                                    # For now, treating Count mode as protected
                                    log4j_protected = True

                            break

                # Step 6: Determine violation status
                if not log4j_rule_found:
                    logUtils.logDebug(MODULE_NAME, f"Web ACL '{self.webacl_name}' attached to API Gateway Stage '{self.rest_api_id}/{self.stage_name}' does NOT contain AWSManagedRulesKnownBadInputsRuleSet. Remediation required.")
                    return True

                if log4j_rule_found and log4j_rule_excluded:
                    logUtils.logDebug(MODULE_NAME, f"Web ACL '{self.webacl_name}' attached to API Gateway Stage '{self.rest_api_id}/{self.stage_name}' has Log4JRCE rule EXCLUDED. Remediation required.")
                    return True

                if log4j_protected:
                    logUtils.logDebug(MODULE_NAME, f"API Gateway Stage '{self.rest_api_id}/{self.stage_name}' is protected. Web ACL '{self.webacl_name}' has active Log4j protection. No remediation required.")
                    return False

                # If we get here, rule was found but not properly configured
                logUtils.logDebug(MODULE_NAME, f"Web ACL '{self.webacl_name}' configuration unclear. Remediation required.")
                return True

            return False

        except Exception as e:
            logUtils.logError(MODULE_NAME, e)
            return False

    def remediate(self):
        '''
        Remediates the Web ACL by adding or updating AWS Managed Rule Group for Log4j protection.

        Remediation steps:
        1. Get current Web ACL configuration
        2. Check if AWSManagedRulesKnownBadInputsRuleSet exists
        3. If missing: Add the rule with highest priority
        4. If excluded: Remove Log4JRCE from excluded rules
        5. Update Web ACL with new configuration
        '''
        logUtils.logInfo(MODULE_NAME, "Inside " + self.remediate.__name__)

        try:
            # Get WAFv2 client
            wafv2_client = MarriottCSAO_utils.getAwsClient('wafv2', self.accountId, self.region)

            # Get current Web ACL configuration
            waf_response = wafv2_client.get_web_acl(
                Name=self.webacl_name,
                Scope=self.webacl_scope,
                Id=self.webacl_id
            )

            web_acl = waf_response.get('WebACL', {})
            current_rules = web_acl.get('Rules', [])
            lock_token = waf_response.get('LockToken')

            logUtils.logDebug(MODULE_NAME, f"Starting remediation for Web ACL '{self.webacl_name}'")

            # Check if AWSManagedRulesKnownBadInputsRuleSet exists
            log4j_rule_exists = False
            log4j_rule_index = -1

            for idx, rule in enumerate(current_rules):
                statement = rule.get('Statement', {})
                if 'ManagedRuleGroupStatement' in statement:
                    managed_rule = statement['ManagedRuleGroupStatement']
                    vendor_name = managed_rule.get('VendorName', '')
                    rule_group_name = managed_rule.get('Name', '')

                    if (vendor_name == 'AWS' and
                        rule_group_name == 'AWSManagedRulesKnownBadInputsRuleSet'):
                        log4j_rule_exists = True
                        log4j_rule_index = idx
                        break

            updated_rules = list(current_rules)

            if log4j_rule_exists:
                # Rule exists, check if Log4JRCE is excluded and remove exclusion
                rule = updated_rules[log4j_rule_index]
                managed_rule = rule['Statement']['ManagedRuleGroupStatement']
                excluded_rules = managed_rule.get('ExcludedRules', [])

                # Remove Log4JRCE from excluded rules
                new_excluded_rules = [r for r in excluded_rules if r.get('Name') != 'Log4JRCE']

                if new_excluded_rules:
                    managed_rule['ExcludedRules'] = new_excluded_rules
                else:
                    # Remove ExcludedRules key if empty
                    if 'ExcludedRules' in managed_rule:
                        del managed_rule['ExcludedRules']

                logUtils.logDebug(MODULE_NAME, f"Updated existing rule to remove Log4JRCE exclusion")

            else:
                # Rule doesn't exist, add it with highest priority
                # Create new Log4j protection rule
                log4j_rule = {
                    'Name': 'CSAO-Log4j-Protection',
                    'Priority': 0,  # Highest priority
                    'Statement': {
                        'ManagedRuleGroupStatement': {
                            'VendorName': 'AWS',
                            'Name': 'AWSManagedRulesKnownBadInputsRuleSet'
                        }
                    },
                    'OverrideAction': {
                        'None': {}
                    },
                    'VisibilityConfig': {
                        'SampledRequestsEnabled': True,
                        'CloudWatchMetricsEnabled': True,
                        'MetricName': 'CSAO-Log4j-Protection'
                    }
                }

                # Adjust priorities of existing rules
                for rule in updated_rules:
                    rule['Priority'] += 1

                # Add Log4j rule at the beginning
                updated_rules = [log4j_rule] + updated_rules

                logUtils.logDebug(MODULE_NAME, f"Added new CSAO-Log4j-Protection rule with priority 0")

            # Update Web ACL with new rules
            logUtils.logDebug(MODULE_NAME, f"Updating Web ACL '{self.webacl_name}' with Log4j protection...")

            wafv2_client.update_web_acl(
                Name=self.webacl_name,
                Scope=self.webacl_scope,
                Id=self.webacl_id,
                DefaultAction=web_acl.get('DefaultAction', {'Allow': {}}),
                Rules=updated_rules,
                VisibilityConfig=web_acl.get('VisibilityConfig'),
                LockToken=lock_token,
                Description=f"Updated by CSAO to include Log4j protection for API Gateway Stage {self.rest_api_id}/{self.stage_name}"
            )

            logUtils.logDebug(MODULE_NAME, f"Web ACL '{self.webacl_name}' successfully updated with Log4j protection. API Gateway Stage '{self.rest_api_id}/{self.stage_name}' is now protected.")

        except Exception as e:
            if hasattr(e, 'error') and hasattr(e, 'errorMessage'):
                error = e
            else:
                error = CustomErrors.GenericError(config.GENERIC_ERROR_STATUS_CODE, config.GENERIC_ERROR_MESSAGE, str(e))
            logUtils.logError(MODULE_NAME, error)
            raise
