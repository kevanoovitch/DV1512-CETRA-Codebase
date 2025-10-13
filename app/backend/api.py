import json
from app.backend.API_interfaces.SA_interface import Interface_Secure_Annex
from app.backend.API_interfaces.SA_Interpret import SecureAnnex_interpretator
from app import constants
from pathlib import Path

from app.backend.utils.printer import pretty_print_sa_result
from app.backend.API_interfaces.VirusTotalInterface import scan_file


# === Secure Annex === #

def preform_secure_annex_scan(input):

    #Helper function to query SA and build json file
    
    

    client = Interface_Secure_Annex()
    interpreter = SecureAnnex_interpretator()
    path = Path(constants.SA_OUTPUT_FILE) 
    

    client.perform_scan(input,path)

    #Parse the output
    parsed = interpreter.interpret_output()
  
    #Deliver verdict from SA also returns findings for later use
    sa_verdict_int = parsed["score"]
   
    return sa_verdict_int
    

#TODO: bloat code
def print_secure_annex_scan(extension):
    

    client = Interface_Secure_Annex()
    

    client.print_analysis()
   
# === Virus Total === #

def prefrom_virus_total_scan(file_name):

    VT_verdict = scan_file(file_name)["score"]

    return VT_verdict


# === Helpers === #

def extension_converter():
    # TODO: implement a input converter i.e zip->webID & crx -> webID 
    pass 
