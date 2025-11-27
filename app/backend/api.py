import json
from app.backend.API_interfaces.SA_interface import Interface_Secure_Annex
from app.backend.API_interfaces.SA_Interpret import SecureAnnex_interpretator
import app.backend.API_interfaces.VirusTotalInterface as vt
from app.backend.API_interfaces.OPSWAT2 import scan_file as opswat_scan_file
from app.backend.utils import ExtensionIDConverter, extension_retriver, download_crx
from app.backend.report_generator import generate_report
import hashlib
from app import constants
from pathlib import Path
import re
import os
import logging

logger = logging.getLogger(__name__)

#function that gather both inputs ID and filepath in one object
class FileFormat:
    def __init__(self):
        filePath = None
        ID = None

def apiCaller(value,submission_type):
    
    # In case it's missing an ID SA won't be called but the result structure still needs to be there
    result = []
    #instantiate a FileFormat object to store both path and ID
    fileFormat = FileFormat()


    if submission_type == "file":
        logger.info("Received a file, retreiving the Id ouf of the file")
        fileFormat.filePath = value
        try:
            fileFormat.ID = ExtensionIDConverter().convert_file_to_id(value)
        except ValueError:
            # Converter now returns None for unsupported inputs (e.g., raw ZIP without key);
            # keep ID empty and continue with file-based scanners.
            fileFormat.ID = None
            logger.warning("Unable to derive extension ID from file %s; continuing without ID", value)
    if submission_type == "id":
        logger.info("Received a ID, Downloading the file...")
        fileFormat.ID = value
        fileFormat.filePath = download_crx(value)

    if fileFormat.filePath == -1:
        return -1

    filehash = compute_file_hash(fileFormat.filePath)

    if fileFormat.ID is not None:
        logger.info("Calling Secure-Annex")
        sa_findings = preform_secure_annex_scan(fileFormat.ID)
        result.extend(sa_findings)
    else:
        logger.warning("Skipping Secure-Annex")
  
    #VT returns {"malware_types:[], score:int,"raw":{}"}
    if fileFormat.filePath != None:
        logger.info("Calling VirusTotal")
        VT_findings = vt.scan_file(fileFormat.filePath,filehash)

        result.extend(VT_findings)

        
        opswat_findings=opswat_scan_file(fileFormat.filePath)

        #TODO: remove following line when opswat refactoring is done:
        logger.warning("Hotfixing opswat result")
        opswat_findings = []

        result.extend(opswat_findings)


    logger.info("Retrieving permissions")
    
    #FIXME: Properly refactor extension retriever!!!
    #result["permissions"] = extension_retriver(fileFormat.filePath)
    #result["extension_id"] = fileFormat.ID
    if fileFormat.ID is None:
        logger.warning("Extension ID is empty")

    #result["file_path"] = fileFormat.filePath
    #result["file_hash"] = filehash
    logger.info("Generating report")

    report = generate_report(result)

    logger.info("Saving the report")
    ParseReport(report)

    return 0


def preform_secure_annex_scan(input):
    #Helper function to query SA and build json file
    client = Interface_Secure_Annex()
    interpreter = SecureAnnex_interpretator()
    path = Path(constants.SA_OUTPUT_FILE)

    client.perform_scan(input,path)

    #Parse the output
    parsed = interpreter.interpret_output()

    #Deliver verdict from SA also returns findings for later use
    return parsed

def compute_file_hash(file_path, algorithm='sha256'):
    hash_func = hashlib.new(algorithm)
    
    with open(file_path, 'rb') as file:
        # Read the file in chunks of 8192 bytes
        while chunk := file.read(8192):
            hash_func.update(chunk)
    
    return hash_func.hexdigest()
