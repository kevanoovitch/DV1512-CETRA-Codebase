import json
from app.backend.API_interfaces.SA_interface import Interface_Secure_Annex
from app.backend.API_interfaces.SA_Interpret import SecureAnnex_interpretator
import app.backend.API_interfaces.VirusTotalInterface as vt
from app.backend.API_interfaces.OPSWAT2 import scan_file as opswat_scan_file
from app.backend.utils import ExtensionIDConverter, extension_retriver, download_crx
from app.backend.report_generator import generate_report
from app.backend.database_parser import ParseReport
import hashlib
from app import constants
from pathlib import Path
import re
import os
import logging
from app.backend.utils.classlibrary import FileFormat
logger = logging.getLogger(__name__)


class ApiResult:
    def __init__(self):
        self.findings = []
        self.permissions = []
        self.file_hash=None
        self.extension_id=None
        self.file_format = FileFormat()
        self.behaviour_summary= None

def apiCaller(value,submission_type):
    api_result = ApiResult()

    #Check submission type
    if submission_type == "file":
        logger.info("Received a file, retreiving the Id ouf of the file")
        api_result.file_format.filePath = value
        try:
            api_result.file_format.ID = ExtensionIDConverter().convert_file_to_id(value)
        except ValueError:
            api_result.file_format.ID = None
            logger.warning("Unable to derive extension ID from file %s; continuing without ID", value)
    elif submission_type == "id":
        logger.info("Received a ID, Downloading the file...")
        api_result.file_format.ID = value
        api_result.file_format.filePath = download_crx(value)
        if api_result.file_format.filePath == None:
            return -1
    else:
        return -1

    api_result.file_hash = compute_file_hash(api_result.file_format.filePath)

    if(api_result.file_format.ID is not None):
        api_result.extension_id = api_result.file_format.ID
        logger.info("Calling Secure-Annex", extra={"extension_id": api_result.file_format.ID})
        sa_client = Interface_Secure_Annex()
        sa_findings = sa_client.perform_scan_and_interpret(api_result.file_format.ID)
        if sa_findings:
            api_result.findings.extend(sa_findings)
        else:
            logger.warning("Secure-Annex returned no findings", extra={"extension_id": api_result.file_format.ID})
    else:
        logger.warning("Skipping Secure-Annex couldn't retrieve ID")
  
    if api_result.file_format.filePath != None:
        logger.info("Calling VirusTotal")
        api_result.findings.extend(vt.scan_file(api_result.file_format.filePath,api_result.file_hash))
        logger.info("Calling OWASP")
        #FIXME: this
        #api_result.findings.extend(opswat_scan_file(api_result.file_format.filePath))

    logger.info("Getting file behaviour report from virustotal")

    api_result.behaviour_summary = vt.get_vt_behaviour_summary(api_result.file_hash)

    logger.info("Retrieving permissions")
    api_result.permissions = extension_retriver(api_result.file_format.filePath)

    #FIXME: uncomment and refactore report generator and parser
    logger.info("Generating report")
    
    #report = generate_report(api_result)
    logger.info("Saving the report")
    
    #ParseReport(report)

    return 0
def compute_file_hash(file_path, algorithm='sha256'):
    hash_func = hashlib.new(algorithm)
    
    with open(file_path, 'rb') as file:
        # Read the file in chunks of 8192 bytes
        while chunk := file.read(8192):
            hash_func.update(chunk)
    
    return hash_func.hexdigest()
