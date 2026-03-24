'''
User Story:
'''

# Standard imports
import json
import logging
import os
import sys
import re
import datetime
import time

# Libraries to coonnect to AWS
import boto3
from botocore.exceptions import ClientError
import traceback

#Custom imports
from src.helpers import tagHelperAWSAthena
from csao_utils.GetDetails import GetDetails
from csao_utils import config, CustomErrors, logUtils, MarriottCASO_utils, MarriottCASOEventHandler
from csao_utils.config import KeyPolicy

MODULE_NAME = __file__

def mapEvent(event):
    '''
    This function extracts information captured in the event and sends the information back
    to parseEvent function
    '''
    logUtils.loginfo(MODULE_NAME, "INSIDE " + mapEvent.__name__)

    #Logging the event
    logUtils.logDebug(MODULE_NAME, f"Event data: {json.dumps(event, indent=2)}")

    #Extracting details from event
    Event = GetDetails(json.loads(json.dumps(event['details'])))

    try:
        #Config event
        if Event.GetData(['eventSource'])['eventSource'] == 'config.amazonaws.com'
            details = Event.GetData(['accountId', 'awsRegion', 'eventSource', 'eventName', ['UserIdentity','arn'], 'eventTime', 'userAgent', 'eveluation'])

        #Non-config event
        else:
            eventName = Event.GetData(['eventName'])['eventName']

            # Create event, Update event
            if eventName in ['CreateWorkGroup', 'UpdateWorkGroup']:
                
                if eventName == 'CreateWorkGroup':
                    details = Event.GetData(['eventName', 'eventSource', 'resource', 'resourceArn', 'accountId', 'awsRegion', ['UserIdentity','arn'], 'eventTime','userAgent', ['requestparameters', 'name']])
                    details['workgroup_name'] = details['requestparameters/name']

                if eventName == 'UpdateWorkGroup':
                    details = Event.GetData(['eventName', 'eventSource', 'resource', 'resourceArn', 'accountId', 'awsRegion', ['UserIdentity','arn'], 'eventTime','userAgent', ['requestparameters', 'workGroup']])
                    details['workgroup_name'] = details['requestparameters/workGroup']
                
                details['resourceArn'] = f"arn:aws:athena:{details['awsRegion']}:{details['accountId']}:workgroup/{details['workgroup_name']}"
                logUtils.logDebug(MODULE_NAME, f"Resource ARN : {details['resourceArn']}")
                details['resource'] = details['resourceArn']

            # Tag events
            elif eventName in ['TagResorce', 'UntagResource']
                details = Event.GetData(['accountId', 'awsRegion', 'eventSource', 'eventName', ['userIdentity', 'arn'], 'eventTime', 'resourceARN'])
                details['resource'] = details['resourceARN']

                if eventName == 'TagResource':
                    details['Tags'] = Event.GetData(['Tags'])['tags']
                elif eventName == 'UntagResource':
                    details['Tags'] = Event.GetData(['TagsKeys'])['tagsKeys']
                
        details['userEmail'] = details['userIdentity/arn'].split('/')[-1]
        
    except KeyError as key:
        logUtils.logDebug(MODULE_NAME, f"KeyError: {key} key is expected but not found in event data") 
        logUtils.logError (MODULE_NAME, key)
        raise
    
    logUtils.logDebug (MODULE_NAME, f"Extracted details: {json.dumps(details, indent=2)}")
    return details

def parseEvent (event, context):
    '''
    This function extracts information captured in the event and sends the information to function 
    doHandleEvent
    '''
    logUtils.logInfo(MODULE_NAME, "Inside " + parseEvent.__name__) 
    
    try:
        details = mapEvent(event)
    except BaseException as e:
        logUtils. logInfo(MODULE_NAME, "Error in mapping the event".)
        tracebackDetail = traceback.format_exc()
        errorEvent = MarriottCSAO_utils.createErrorLogs(event, context, e, tracebackDetail, True)
        errorDetails = json.dumps(errorEvent)
        logUtils.logInfo (MODULE_NAME, errorDetails)
        raise

    try:
        logUtils.logInfo(MODULE_NAME, 'Event Triggered by : ' + details[ 'eventName']) 
        
        if config.LAMBDA_ROLE in details[ 'userIdentity/arn']:
            if details[ 'eventName'] not in ['TagResource', 'UntagResource']: 
                logUtils.logInfo(MODULE_NAME, "Event triggered by CSAO, ignoring...")
                return

        ruleName = os environ[ 'ruleName']
        service = config SERVICE_NAME['ATHENA']

        #Run for all resources in config
        if details['eventName'] == 'PutEvaluations': 
            for resourceEval in details['evaluations']:
                if resourceEval['complianceType'] = 'NON_COMPLIANT' and resourceEval['complianceResourceType'] == 'AWS:: Athena: : Workgroup':
                    details['resource'] = resourceEval['complianceResourceId']
                    tag = tagHelperAWSAthena.getTags(service, details['accountId'], details['awsRegion'], details['resource'])
                    doHandleEvent(ruleName, service, event, tag, details)
                    return

        if details['eventName'] = 'TagResource':
            event ['eventTagInfo'] = tagHelperAWSAthena.extractTagInfo(details['tags'])
        elif details['eventName'] == 'UntagResource':
            event ['eventTagInfo'] = tagHelperAWSAthena.extractTagInfo_list(details['tags'])
        else:
            event ['eventTagInfo'] = []

        tag = tagHelperAWSAthena.getTags(service, details['accountId'], details['awsRegion'], details[ 'resource'])
        doHandleEvent (ruleName, service, event, tag, details)
    
    except KeyError as key:
        logUtils.logDebug (MODULE_NAME, f"Failed to parse event or config {key} key is expected but not found") 
        logUtils.logError (MODULE_NAME, key)

    except Exception as e:
        if hasattr(e, 'error') and hasattr(e, 'errorMessage'):
            error = e
        else:
            error = customErrors.GenericError(config.GENERIC_ERROR_STATUS_CODE, config.GENERIC_ERROR_MESSAGE, str(e))
        logUtils.logError (MODULE_NAME, error)

def doHandleEvent(ruleName, service, event, tag, details):
    '''
    This function calls the class with arguments extracted from event which assume. role, extract information 
    from the database and decide whether the remediation to be performed or not
    '''
    logUtils.logInfo(MODULE_NAME, "Inside " + doHandleEvent.__name__)

    try:
        handler = MarriottCSAOEventHandlerCMKencryptAWSAthena(ruleName, service, event, tag, details)
        return handler.handleEvent()

    except Exception as e:
        if hasattr(e, 'error') and hasattr(e, 'errorMessage'):
            error = e
        else:
            error = customErrors.GenericError(config.GENERIC_ERROR_STATUS_CODE, config.GENERIC_ERROR_MESSAGE, str(e))
        logUtils. logError (MODULE_NAME, error)
        raise

class MarriottCSA0EventHandlerCMKencryptAWSAthena(MARRIOTTCSA0EventHandler.MARRIOTTCSA0EventHandlerAWSService):

    def isRuleViolated(self):
        
        logUtils.logInfo(MODULE_NAME, "Inside" + self.isRuleViolated._name_)

        try:
            if self.eventName in ['CreateWorkGroup', 'UpdateWorkGroup', 'TagResource', 'UntagResource'] :
                self.workgroup_name = self.csaoEvent['resourceArn'].split('/')[-1]
                response = self.client.get_work_group(WorkGroup=self.workgroup_name)
                encryption_configuration = response.get('WorkGroup', {}).get( 'Configuration', {}).get('ResultConfiguration', {}).get('EncryptionConfigration', {})
                self.encryption_option = encryption_configuration.get('EncryptionOption', 'None')
                self.standard_encryption_option = 'SSE_KMS'
                self.standard_kms_key_arn = self.kms_key_arn_check()
                
                # Compare curent encryption option with the standard one.
                if self.encryption_option in ['NoEncryption', 'SSE_S3', 'CSE_KMS', 'None'] :
                    logUtils.logDebug(MODULE_NAME, f"The current encryption option associated with the Workgroup '{self.workgroup_name}' is : {self.encryption_option} and is not following the standard encryption SSE_KMS. Remediation required.")
                    return True

                elif self.encryption_option == self.standard_encryption_option:
                    curr_kms_key_arn = encryption_configuration.get( 'KmsKey')
                    
                    if not curr_kms_key_arn:
                        logUtils.1ogDebug(MODULE_NAME, f"Workgroup '{self.workgroup_name}' is using standard encryption option {self.standard_encryption_option} for query results, but no KMS key is associated with it. KMS key ARN: {curr_kms_key_arn}\n Remediation required.")
                        return True
                    if curr_kms_key_arn == self.standard_kms_key_arn :
                        logUtils.logDebug(MODULE_NAME, f"Workgroup '{self.workgroup_name}' is using standard encryption option {self.standard_encryption_option} for query results with CSAO standard CMK. KMS key ARN: {curr_kms_key_arn}\n No remediation required.")
                        return False

                    if curr_kms_key_arn |= self.standard_kms_key_arn :
                        kmsClient = MarriottCSAO_utils.getAwsClient('kms', self.accountId, self.region)
                        key_metadata = kmsClient.describe_key(KeyId=curr_kms_key_arn)
                        key_manager = key_metadata[ 'KeyMetadata' ]['KeyManager' ]
                    
                    if key_manager.upper() == 'CUSTOMER'
                        logUtils. logDebug(MODULE_NAME, f"Workgroup '{self.workgroup_name}' is using standard encryption option {self.standard_encryption_option} for query results with CSAO standard Customer Managed Key. KMS key ARN: {curr_kms_key_arn}\n No remediation required.")
                        return False
                    else:
                        LogUtils. LogDebug(MODULE_NAME, f"Workgroup '(self-workgroup_name)' is using standard encryption option {self.standard_encryption_option} for query results with CSAO standard AWS Managed Key. KMS key ARN: {curr_kms_key_arn}\n Remediation required.")
                        return True
            
            return False

        except Exception as e:
            logUtils.logError(MODULE_NAME, e)
            return False


    def kms_key_arn_check(self):
            
            #this method will check if the CSAO standard CMK is existing and enabled, also it will retrun the corresponding kms_key_arn.
                
            logUtils.logInfo(MODULE_NAME, "Inside" + self.kms_key_arn_check.__name__)
            kmsClient = MarriottCSAO_utils.getAwsClient('kms', self.accountid, self.region)
            csao_kms_key_alias = "alias/" + config.MARRIOTT_CSAO_KMS_KEY + self.accountId
                
            try:
                    
                #checking if the key exists
                    
                describeKeyResponse = kmsClient.describe_key(KeyId=csao_kms_key_alias)|
                keyId = describeKeyResponse['KeyMetadata' ]['KeyId']
                    
                    if describeKeyResponse[ "KeyMetadata"]['Enabled']:
                        logUtils.logInfo(MODULE_NAME, "Key already exists with status Enabled !")
                        kms_key_arn = kmsClient.describe_key(KeyId=csao_kms_key_alias) ['KeyMetadata']['Arn']
                        return kms_key_arn
                    else:
                        logUtils.logInfo(MODULE_NAME, "Key exists, but was Disabled.")
                        keyEnableResponse = kmsClient.enable_key(KeyId=keyId)
                        
                        if keyEnableResponse[ 'ResponseMetadata' ]['HTTPStatusCode'] ==200:
                            logUtils.logInfo(MODULE_NAME, "Key is now Enabled.")
                            kms_key_arn = kmsClient describe_key(KeyId=csao_kms_key_alias) ['KeyMetadata']['Arn']
                            return kms_key_arn
                                
            except:

                #key doesn't exist, creating 
                    try:
                        keyPolicy = KeyPolicy.replace('accountId', self.accountid)
                        createKeyResponse = kmsClient.create_key(Policy= keyPolicy,Description='New key created by CSAO remediation',
                        KeyUsage='ENCRYPT_DECRYPT',CustomerMasterKeySpec= 'SYMMETRIC_DEFAULT' Origin='AWS_KMS', MultiRegion=True)
                        
                        keyId = createKeyResponse[ 'KeyMetadata ' ]['KeyId']
                        logUtils. ogInfo (MODULE_NAME, "Created New Key!")
                        createAliasResponse = kmsClient.create_alias(AliasName = csao_kms_key_alias,TargetKeyId = keyid)
                        
                        enableKeyRotationResponse = kmsClient.enable_key_rotation(KeyId = keyId)
                        kms_key_arn = kmsClient describe_key(KeyId=csao_kms_key_alias)['KeyMetadata']['Arn']
                        return kms_key_arn

                except Exception as e:
                logUtils.logError (MODULE_NAME, error)
    
    def remediate(self):
                
                logUtils.logInfo(MODULE_NAME, "Inside " + self. remediate.__name__)
                
                try:
                    # Remediate: Update the workgroup's encryption configuration

                    logUtils. logDebug(MODULE_NAME, f"Updating encryption opion for workgroup '{self.workgroup_name}' with {self.standard_encryption_option}...")
                    encryption_configuration = ('EncryptionOption': self.standard_encryption_option)
                    encryption_configuration['KmsKey'] = self.standard_kms_key_arn
                    self.client.update_work_group(WorkGroup=self.workgroup_name,ConfigurationUpdates={'ResultConfigurationUpdates': {'Encryptioncon_Configuration' :encryption_configuration}},Description=f"Updated encryption configration to {self.standard_encryption_option}")
                    
                    logUtils. logDebug(MODULE_NAME, f"Workgroup '{self.workgroup_name}' got successfully updated to {self.standard_encryption _option} encryption with CSAO Standard CMK.")
                
                except Exception as e:
                    if hasattr(e, 'error') and hasattr(e, 'errorMessage'):
                        error = e
                    else:
                    error = customErrors.GenericError (config-GENERIC_ERROR_STATUS_CODE, config-GENERIC ERROR MESSAGE, str(e))
                logUtils.logError (MODULE_NAME, error)



