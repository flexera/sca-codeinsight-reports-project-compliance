'''
Copyright 2020 Flexera Software LLC
See LICENSE.TXT for full license text
SPDX-License-Identifier: MIT

Author : sgeary  
Created On : Fri Aug 07 2020
File : report_data.py
'''

import logging
import CodeInsight_RESTAPIs.project.get_project_inventory
import CodeInsight_RESTAPIs.component.get_component_details

logger = logging.getLogger(__name__)

#-------------------------------------------------------------------#
def gather_data_for_report(baseURL, projectID, authToken, reportName):
    logger.info("Entering gather_data_for_report")


    # Create a dictionary containing the inveotry data using name/version strings as keys
    inventoryData = {}

    # Get details for  project
    try:
        projectInventoryResponse = CodeInsight_RESTAPIs.project.get_project_inventory.get_project_inventory_details(baseURL, projectID, authToken)
    except:
        logger.error("    No project ineventory response!")
        print("No project inventory response.")
        return -1

    projectName = projectInventoryResponse["projectName"]
    inventoryItems = projectInventoryResponse["inventoryItems"]
    totalNumberIventory = len(inventoryItems)
    currentItem = 0

    for inventoryItem in inventoryItems:
        currentItem +=1

        # Compliance issues
        complianceIssuesType = []
        complianceIssuesMessage = []

        inventoryItemName = inventoryItem["name"]

        componentName = inventoryItem["componentName"]

        componentId = inventoryItem["componentId"]

        inventoryPriority = inventoryItem["priority"]

        # Component version
        componentVersionName = inventoryItem["componentVersionName"]
        componentVersionDetails = getVersionData(baseURL, componentId, componentVersionName, authToken)
        if componentVersionName == "N/A":
            complianceIssuesType.append("Unknown version")
            complianceIssuesMessage.append("This item has an unknown version. Additional analysis is recommended.")
        elif componentVersionDetails["isOldVersion"]:
            complianceIssuesType.append("Old version")
            complianceIssuesMessage.append("This item has an old version. Upgrading to a more recent version is recommended.")

        selectedLicenseName = inventoryItem["selectedLicenseName"]

        selectedLicenseSPDXIdentifier = inventoryItem["selectedLicenseSPDXIdentifier"]

        selectedLicensePriority = inventoryItem["selectedLicensePriority"]
        if selectedLicensePriority == 1:
            complianceIssuesType.append("P1 license")
            complianceIssuesMessage.append("This item has a viral or strong copyleft license. Depnding on your usage there may be additional oblilgations. Please consult with your legal team.")

        componentUrl = inventoryItem["componentUrl"]

        selectedLicenseUrl = inventoryItem["selectedLicenseUrl"]

        inventoryID = inventoryItem["id"]

        inventoryReviewStatus = inventoryItem["inventoryReviewStatus"]
        if inventoryReviewStatus == "Rejected":
            complianceIssuesType.append("Item rejected")
            complianceIssuesMessage.append("This item has been rejected for use. Please consult with your legal and/or security team for further guidance.")

        logger.debug("Processing iventory items %s of %s" %(currentItem, totalNumberIventory))
        logger.debug("    %s" %(inventoryItemName))
        
        try:
            vulnerabilities = inventoryItem["vulnerabilities"]
            vulnerabilityData = get_vulnerability_summary(vulnerabilities)
            numVulnerabilities = 0;
            try:
                numCriticalVulnerabilities = vulnerabilityData["numCriticalVulnerabilities"]
                numVulnerabilities += numCriticalVulnerabilities
                numHighVulnerabilities = vulnerabilityData["numHighVulnerabilities"]
                numVulnerabilities += numHighVulnerabilities
                numMediumVulnerabilities = vulnerabilityData["numMediumVulnerabilities"]
                numVulnerabilities += numMediumVulnerabilities
                numLowVulnerabilities = vulnerabilityData["numLowVulnerabilities"]
                numVulnerabilities += numLowVulnerabilities
                numNoneVulnerabilities = vulnerabilityData["numNoneVulnerabilities"]
                numVulnerabilities += numNoneVulnerabilities
            except:
                logger.debug("    No vulnerability data")

            if (numVulnerabilities > 0):
                complianceIssuesType.append("Security vulnerabilities")
                complianceIssuesMessage.append("This item has associated security vulnerabilites. Please consult with your security team for further guidance.")

        except:
            logger.debug("No vulnerabilies for %s - %s" %(componentName, componentVersionName))
            vulnerabilityData = ""

        if selectedLicenseSPDXIdentifier != "":
            selectedLicenseName = selectedLicenseSPDXIdentifier

        inventoryData[inventoryItemName] = {
            "componentName" : componentName,
            "componentVersionName" : componentVersionName,
            "componentVersionDetails" : componentVersionDetails,
            "selectedLicenseName" : selectedLicenseName,
            "vulnerabilityData" : vulnerabilityData,
            "selectedLicensePriority" : selectedLicensePriority,
            "inventoryPriority" : inventoryPriority,
            "componentUrl" : componentUrl,
            "selectedLicenseUrl" : selectedLicenseUrl,
            "inventoryID" : inventoryID,
            "inventoryReviewStatus" : inventoryReviewStatus,
            "inventorycomplianceIssuesType" : complianceIssuesType,
            "inventorycomplianceIssuesMessage" : complianceIssuesMessage
        }
            

    reportData = {}
    reportData["reportName"] = reportName
    reportData["projectID"] = projectID
    reportData["projectName"] = projectName
    reportData["inventoryData"] = inventoryData
    reportData["baseURL"] = baseURL

    logger.info("Exiting gather_data_for_report")

    return reportData


#----------------------------------------------------------------------
def get_vulnerability_summary(vulnerabilities):
    logger.info("Entering get_vulnerability_summary")

    numCriticalVulnerabilities = 0
    numHighVulnerabilities = 0
    numMediumVulnerabilities = 0
    numLowVulnerabilities = 0
    numNoneVulnerabilities = 0
    vulnerabilityData = {}

    for vulnerability in vulnerabilities:

        vulnerabilityCvssV3Severity = vulnerability["vulnerabilityCvssV3Severity"]

        if vulnerabilityCvssV3Severity == "CRITICAL":
            numCriticalVulnerabilities +=1
        elif vulnerabilityCvssV3Severity == "HIGH":
            numHighVulnerabilities +=1
        elif vulnerabilityCvssV3Severity == "MEDIUM":
            numMediumVulnerabilities +=1
        elif vulnerabilityCvssV3Severity == "LOW":
            numLowVulnerabilities +=1
        elif vulnerabilityCvssV3Severity == "N/A":
            numNoneVulnerabilities +=1
        elif vulnerabilityCvssV3Severity == "NONE":
            numNoneVulnerabilities +=1            
        else:
            logger.error("Unknown vulnerability severity: %s" %vulnerabilityCvssV3Severity)

    vulnerabilityData["numCriticalVulnerabilities"] = numCriticalVulnerabilities
    vulnerabilityData["numHighVulnerabilities"] = numHighVulnerabilities
    vulnerabilityData["numMediumVulnerabilities"] = numMediumVulnerabilities
    vulnerabilityData["numLowVulnerabilities"] = numLowVulnerabilities
    vulnerabilityData["numNoneVulnerabilities"] = numNoneVulnerabilities

    return vulnerabilityData


#---------------------------------------------------------------------#
def getVersionData(baseURL, componentId, componentVersionName, authToken):
    logger.info("Entering getVersionData")

    MAX_ALLOWED_NUMBER_BACK = 5

    isOldVersion = False

    # Get details for component
    try:
        componentDataResponse = CodeInsight_RESTAPIs.component.get_component_details.get_component_details(baseURL, componentId, authToken)
    except:
        logger.error("    No component details response!")
        print("No component details response.")
        return -1

    versions = []
    versionToSkip = ["unknown", "custom", "any version", "sample"]
    for version in componentDataResponse["data"]["versionList"]:
        version = version["name"]
        if version.lower() not in versionToSkip:
            versions.append(version)

    versions.sort(reverse=True)

    counter = 0
    for v in versions:
        counter += 1
        if v == componentVersionName:
            break

    if counter > MAX_ALLOWED_NUMBER_BACK:
        isOldVersion = True

    versionDetails = {}
    versionDetails["isOldVersion"] = isOldVersion
    versionDetails["numBack"] = counter
    versionDetails["latestVersion"] = versions[0]
    versionDetails["maxAllowedNumBack"] = MAX_ALLOWED_NUMBER_BACK

    logger.debug(versionDetails)

    return versionDetails
