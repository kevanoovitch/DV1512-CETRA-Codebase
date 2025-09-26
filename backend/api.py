import json
from backend.API_interfaces.SA_interface import ISecureAnnex
from backend.API_interfaces.SA_Interpret import SecureAnnex_interpretator
import constants
from pathlib import Path

from backend.API_interfaces.printer import pretty_print_sa_result

def preform_secure_annex_scan(extension):

    #Helper function to query SA and build json file

    client = ISecureAnnex(None,None)
    interpreter = SecureAnnex_interpretator()

    path = Path(constants.SA_OUTPUT_FILE) 
    

    client.perform_scan(extension,path)

    #Parse the output
    parsed = interpreter.interpret_output()

    pretty_print_sa_result(parsed)
    #TODO: Deliver verdict from SA


def print_secure_annex_scan(extension):
    #FIXME: and just call the SA function

    client = ISecureAnnex(None,None)
    path = constants.SA_OUTPUT_FILE 

    client.print_analysis()
   





def extension_converter():
    # TODO: implement a input converter i.e zip->webID & crx -> webID 
    pass 
