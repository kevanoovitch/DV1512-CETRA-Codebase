import json
from app.backend.API_interfaces.SA_interface import Interface_Secure_Annex
from app.backend.API_interfaces.SA_Interpret import SecureAnnex_interpretator
from app import constants
from pathlib import Path

from app.backend.API_interfaces.printer import pretty_print_sa_result

def preform_secure_annex_scan(extension):

    #Helper function to query SA and build json file

    client = Interface_Secure_Annex()
    interpreter = SecureAnnex_interpretator()

    path = Path(constants.SA_OUTPUT_FILE) 
    

    client.perform_scan(extension,path)

    #Parse the output
    parsed = interpreter.interpret_output()

    pretty_print_sa_result(parsed)
    
    #Deliver verdict from SA also returns findings for later use
    sa_verdict_int = parsed["score"]
    
    return sa_verdict_int
    


def print_secure_annex_scan(extension):
    

    client = Interface_Secure_Annex()
    

    client.print_analysis()
   





def extension_converter():
    # TODO: implement a input converter i.e zip->webID & crx -> webID 
    pass 
