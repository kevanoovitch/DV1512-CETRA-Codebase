import json
from backend.API_interfaces.SA_interface import ISecureAnnex

import constants

def preform_secure_annex_scan(extension):

    #Helper function to query SA and build json file

    client = ISecureAnnex(None,None)

    path = constants.SA_OUTPUT_FILE 
    

    client.preform_scan(extension,path)

    #TODO: Call parser

    #TODO: Deliver verdict from SA


def print_secure_annex_scan(extension):
    #FIXME: and just call the SA function

    client = ISecureAnnex(None,None)
    path = constants.SA_OUTPUT_FILE 

    client.print_analysis()
   





def extension_converter():
    # TODO: implement a input converter i.e zip->webID & crx -> webID 
    pass 
