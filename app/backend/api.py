import json
from app.backend.API_interfaces.SA_interface import Interface_Secure_Annex
from app.backend.API_interfaces.SA_Interpret import SecureAnnex_interpretator
import app.backend.API_interfaces.VirusTotalInterface as vt
from app.backend.API_interfaces.OPSWAT2 import scan_file as opswat_scan_file
from app.backend.utils import ExtensionIDConverter, extension_retriver, download_crx
from app.backend.report_generator import generate_report
from app.backend.database_parser import ParseReport

from app import constants
from pathlib import Path
import re
import os


#function that gather both inputs ID and filepath in one object
class FileFormat:
    def __init__(self):
        filePath = None
        ID = None

def apiCaller(value, type):
    result={}

    Id_to_file_converter = ExtensionIDConverter()

    #Step 1, create an object that contain both the ID and the file path
    fileType = check_valid_input(value)

    #return -1 if file is invalid, let the frontend know that the inputted value is invalid
    if fileType == -1:
        return -1

    #instanstiate a FileFormat object to store both path and ID
    fileFormat = FileFormat()


    if fileType == 0:
        print("its an file")
        fileFormat.ID = Id_to_file_converter.convert_file_to_id(value)
        fileFormat.filePath = value
    if fileType == 1:
        print("its an ID")

        fileFormat.ID = value
        fileFormat.filePath = download_crx(value)


    if(fileFormat.ID is not None):
        SA = preform_secure_annex_scan(fileFormat.ID)
        if SA is not None :
            result["SA"] = SA
    #VT returns {"malware_types:[], score:int,"raw":{}"}
    result["VT"] = vt.scan_file(fileFormat.filePath)
    result["OWASP"]=opswat_scan_file(fileFormat.filePath)

    result["permissions"] = extension_retriver(fileFormat.filePath)
    result["extension_id"] = fileFormat.ID
    print(fileFormat.filePath)
    result["file_path"] = fileFormat.filePath



    report = generate_report(result)

    ParseReport(report)

#function checks wether the input is either a file or a chrome extension
#return 0 if file, 1 if chrome ID, -1 if neither.
def check_valid_input(value):
    # Chrome extension IDs are usually 32 lowercase letters (a–p)
    chrome_ext_pattern = re.compile(r'^[a-p]{32}$')

    if chrome_ext_pattern.match(value):
        return 1
    elif os.path.exists(value):
        return 0
    else:
        return -1

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
