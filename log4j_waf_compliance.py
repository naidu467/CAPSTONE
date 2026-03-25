'''
User Story:
Enforce Log4j WAF rule compliance for AWS WAF Web ACLs to protect against Log4j vulnerabilities.
This Lambda function monitors WAF Web ACLs and ensures they have Log4j protection rules enabled.
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
from src.helpers import tagHelperAWSWAF
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

            # Create event, Update event
            if eventName in ['CreateWebACL', 'UpdateWebACL']:

                if eventName == 'CreateWebACL':
                    details = Event.GetData(['eventName', 'eventSource', 'resource', 'resourceArn', 'accountId', 'awsRegion', ['UserIdentity','arn'], 'eventTime','userAgent', ['requestParameters', 'name']])
                    details['webacl_name'] = details['requestParameters/name']

                if eventName == 'UpdateWebACL':
                    details = Event.GetData(['eventName', 'eventSource', 'resource', 'resourceArn', 'accountId', 'awsRegion', ['UserIdentity','arn'], 'eventTime','userAgent', ['requestParameters', 'name'], ['requestParameters', 'id']])
                    details['webacl_name'] = details['requestParameters/name']
                    details['webacl_id'] = details['requestParameters/id']

                # Construct resource ARN for WAF Web ACL
                details['resourceArn'] = f"arn:aws:wafv2:{details['awsRegion']}:{details['accountId']}:*/webacl/{details['webacl_name']}/*"
                logUtils.logDebug(MODULE_NAME, f"Resource ARN : {details['resourceArn']}")
                details['resource'] = details['resourceArn']

            # Tag events
            elif eventName in ['TagResource', 'UntagResource']:
                details = Event.GetData(['accountId', 'awsRegion', 'eventSource', 'eventName', ['userIdentity', 'arn'], 'eventTime', 'resourceARN'])
                details['resource'] = details['resourceARN']

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
        service = config.SERVICE_NAME['WAF']

        # Run for all resources in config
        if details['eventName'] == 'PutEvaluations':
            for resourceEval in details['evaluations']:
                if resourceEval['complianceType'] == 'NON_COMPLIANT' and resourceEval['complianceResourceType'] == 'AWS::WAFv2::WebACL':
                    details['resource'] = resourceEval['complianceResourceId']
                    tag = tagHelperAWSWAF.getTags(service, details['accountId'], details['awsRegion'], details['resource'])
                    doHandleEvent(ruleName, service, event, tag, details)
                    return

        if details['eventName'] == 'TagResource':
            event['eventTagInfo'] = tagHelperAWSWAF.extractTagInfo(details['tags'])
        elif details['eventName'] == 'UntagResource':
            event['eventTagInfo'] = tagHelperAWSWAF.extractTagInfo_list(details['tags'])
        else:
            event['eventTagInfo'] = []

        tag = tagHelperAWSWAF.getTags(service, details['accountId'], details['awsRegion'], details['resource'])
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
        handler = MarriottCSAOEventHandlerLog4jWAFCompliance(ruleName, service, event, tag, details)
        return handler.handleEvent()

    except Exception as e:
        if hasattr(e, 'error') and hasattr(e, 'errorMessage'):
            error = e
        else:
            error = CustomErrors.GenericError(config.GENERIC_ERROR_STATUS_CODE, config.GENERIC_ERROR_MESSAGE, str(e))
        logUtils.logError(MODULE_NAME, error)
        raise

class MarriottCSAOEventHandlerLog4jWAFCompliance(MarriottCASOEventHandler.MarriottCSAOEventHandlerAWSService):

    def isRuleViolated(self):
        '''
        Checks if the Web ACL has Log4j protection rules enabled.
        Returns True if the rule is violated (Log4j protection missing or disabled).
        '''
        logUtils.logInfo(MODULE_NAME, "Inside " + self.isRuleViolated.__name__)

        try:
            if self.eventName in ['CreateWebACL', 'UpdateWebACL', 'TagResource', 'UntagResource']:
                # Extract Web ACL name from resource ARN
                self.webacl_name = self.csaoEvent['resourceArn'].split('/')[-2]

                # Get Web ACL details
                # For regional WAF (ALB, API Gateway)
                try:
                    response = self.client.get_web_acl(
                        Name=self.webacl_name,
                        Scope='REGIONAL',
                        Id=self.webacl_id if hasattr(self, 'webacl_id') else self._get_webacl_id()
                    )
                except:
                    # Try CloudFront scope if regional fails
                    response = self.client.get_web_acl(
                        Name=self.webacl_name,
                        Scope='CLOUDFRONT',
                        Id=self.webacl_id if hasattr(self, 'webacl_id') else self._get_webacl_id()
                    )

                web_acl = response.get('WebACL', {})
                rules = web_acl.get('Rules', [])

                # Define standard Log4j rule patterns
                self.standard_log4j_rule_patterns = [
                    'log4j',
                    'Log4Shell',
                    'CVE-2021-44228',
                    'CVE-2021-45046',
                    'CVE-2021-45105',
                    'jndi'
                ]

                # Check if any rule matches Log4j protection patterns
                log4j_rule_found = False
                log4j_rule_enabled = False

                for rule in rules:
                    rule_name = rule.get('Name', '').lower()

                    # Check if rule name contains Log4j protection keywords
                    for pattern in self.standard_log4j_rule_patterns:
                        if pattern.lower() in rule_name:
                            log4j_rule_found = True

                            # Check if the rule is enabled (not overridden)
                            rule_action = rule.get('Action', {})
                            override_action = rule.get('OverrideAction', {})

                            # Rule is enabled if it has Block or Count action, not None
                            if rule_action.get('Block') or rule_action.get('Count') or \
                               override_action.get('None'):
                                log4j_rule_enabled = True
                                break

                    if log4j_rule_enabled:
                        break

                # Check for AWS Managed Rule Groups that include Log4j protection
                managed_rule_groups_with_log4j = [
                    'AWSManagedRulesKnownBadInputsRuleSet',
                    'AWSManagedRulesCommonRuleSet'
                ]

                for rule in rules:
                    statement = rule.get('Statement', {})
                    managed_rule_group = statement.get('ManagedRuleGroupStatement', {})

                    if managed_rule_group:
                        vendor_name = managed_rule_group.get('VendorName', '')
                        rule_group_name = managed_rule_group.get('Name', '')

                        if vendor_name == 'AWS' and rule_group_name in managed_rule_groups_with_log4j:
                            log4j_rule_found = True

                            # Check if the managed rule group is not completely disabled
                            override_action = rule.get('OverrideAction', {})
                            if override_action.get('None') or override_action.get('Count'):
                                log4j_rule_enabled = True
                                break

                # Determine violation status
                if not log4j_rule_found:
                    logUtils.logDebug(MODULE_NAME, f"Web ACL '{self.webacl_name}' does not have any Log4j protection rules. Remediation required.")
                    return True

                if log4j_rule_found and not log4j_rule_enabled:
                    logUtils.logDebug(MODULE_NAME, f"Web ACL '{self.webacl_name}' has Log4j protection rules but they are disabled. Remediation required.")
                    return True

                if log4j_rule_found and log4j_rule_enabled:
                    logUtils.logDebug(MODULE_NAME, f"Web ACL '{self.webacl_name}' has active Log4j protection rules. No remediation required.")
                    return False

            return False

        except Exception as e:
            logUtils.logError(MODULE_NAME, e)
            return False

    def _get_webacl_id(self):
        '''
        Helper method to retrieve Web ACL ID from the Web ACL name.
        '''
        logUtils.logInfo(MODULE_NAME, "Inside " + self._get_webacl_id.__name__)

        try:
            # Try REGIONAL scope first
            try:
                response = self.client.list_web_acls(Scope='REGIONAL')
                web_acls = response.get('WebACLs', [])

                for acl in web_acls:
                    if acl['Name'] == self.webacl_name:
                        return acl['Id']
            except:
                pass

            # Try CLOUDFRONT scope
            response = self.client.list_web_acls(Scope='CLOUDFRONT')
            web_acls = response.get('WebACLs', [])

            for acl in web_acls:
                if acl['Name'] == self.webacl_name:
                    return acl['Id']

            raise Exception(f"Web ACL '{self.webacl_name}' not found")

        except Exception as e:
            logUtils.logError(MODULE_NAME, e)
            raise

    def remediate(self):
        '''
        Remediates the Web ACL by adding AWS Managed Rule Group for Log4j protection.
        '''
        logUtils.logInfo(MODULE_NAME, "Inside " + self.remediate.__name__)

        try:
            # Get current Web ACL configuration
            webacl_id = self._get_webacl_id()

            # Try REGIONAL scope first
            scope = 'REGIONAL'
            try:
                response = self.client.get_web_acl(
                    Name=self.webacl_name,
                    Scope=scope,
                    Id=webacl_id
                )
            except:
                # Fall back to CLOUDFRONT scope
                scope = 'CLOUDFRONT'
                response = self.client.get_web_acl(
                    Name=self.webacl_name,
                    Scope=scope,
                    Id=webacl_id
                )

            web_acl = response.get('WebACL', {})
            current_rules = web_acl.get('Rules', [])
            lock_token = response.get('LockToken')

            # Create new Log4j protection rule using AWS Managed Rule Group
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
            for rule in current_rules:
                rule['Priority'] += 1

            # Add Log4j rule at the beginning
            updated_rules = [log4j_rule] + current_rules

            # Update Web ACL with new rules
            logUtils.logDebug(MODULE_NAME, f"Adding Log4j protection rule to Web ACL '{self.webacl_name}'...")

            self.client.update_web_acl(
                Name=self.webacl_name,
                Scope=scope,
                Id=webacl_id,
                DefaultAction=web_acl.get('DefaultAction', {'Allow': {}}),
                Rules=updated_rules,
                VisibilityConfig=web_acl.get('VisibilityConfig'),
                LockToken=lock_token,
                Description=f"Updated by CSAO to include Log4j protection"
            )

            logUtils.logDebug(MODULE_NAME, f"Web ACL '{self.webacl_name}' successfully updated with Log4j protection rule.")

        except Exception as e:
            if hasattr(e, 'error') and hasattr(e, 'errorMessage'):
                error = e
            else:
                error = CustomErrors.GenericError(config.GENERIC_ERROR_STATUS_CODE, config.GENERIC_ERROR_MESSAGE, str(e))
            logUtils.logError(MODULE_NAME, error)
            raise
