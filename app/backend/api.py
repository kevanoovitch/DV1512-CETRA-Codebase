import json
from app.backend.API_interfaces.SA_interface import Interface_Secure_Annex
from app.backend.API_interfaces.SA_Interpret import SecureAnnex_interpretator
import app.backend.API_interface.VirusTotalInterface as vt
import app.backend.utils as ut

from app import constants
from pathlib import Path
import re
import os

from app.backend.API_interfaces.printer import pretty_print_sa_result
#function that gather both inputs ID and filepath in one object
class FileFormat:
    def __init__(self)
    filePath = None
    ID = None

def apiCaller(value):
    result={}

    #Step 1, create an object that contain both the ID and the file path    
    fileType = check_valid_input(value)
    
    #return -1 if file is invalid, let the frontend know that the inputted value is invalid
    if fileType == -1:
        return -1

    #instanstiate a FileFormat object to store both path and ID
    fileFormat = FileFormat()
   

    if filetype == 0:
        fileFormat.ID = utils.getExtensionID(value)
        fileFormat.filePath = value
    if filetype == 1:
        fileFormat.ID = value
        fileFormat.filePath = utils.get_Exstension_from_ID(value)


    if(fileFormat.ID is not None):
        SA = preform_secure_annex_scan(fileFormat.ID)
        if SA is not None :
            result["SA"] = SA
    
    result["VT"] = vt.scan_file(fileFormat.filePath)
    result["OWASP"]=owasp.function(fileFormat.filePath)


#function checks wether the input is either a file or a chrome extension
#return 0 if file, 1 if chrome ID, -1 if neither.
def check_valid_input(valueself):
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
