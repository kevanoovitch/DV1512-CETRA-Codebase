
from app.backend.api import preform_secure_annex_scan, prefrom_virus_total_scan
from app.backend.utils import extensionGetter 
from app import constants

from enum import Enum, auto
from pathlib import Path
import os
import re
from typing import Tuple, Union


class InputKind(Enum):
    ID = auto()
    ZIP = auto()
    CRX = auto()

EXTENSION_ID_RE = re.compile(r"^[a-z]{32}$")

class ReportGenerator:
    
    #FIXME: Move this fkn thing to API
    def scanExtension(self, input:str):
        """ Takes a string that is either a path or extensionID"""
        VT_score = 0
        SA_score = 0
        # Take input

        determined_input = self._classify_input(input)

        print(determined_input)

        if determined_input == InputKind.CRX or determined_input == InputKind.ZIP: 
            
            # pass the file to each API_int 

            SA_score = preform_secure_annex_scan(determined_input)
            VT_score = prefrom_virus_total_scan(determined_input)
            #TODO: Call Opswat

        elif determined_input == InputKind.ID: 
            SA_score = preform_secure_annex_scan(determined_input)
            
            # Download 
            rel_path_to_download = constants.UPLOADED_PATH + extensionGetter.download_crx(determined_input)
            


            VT_score = prefrom_virus_total_scan(rel_path_to_download)
 
            #TODO: Call Opswat

        # return final score 
        
        final_score = self._calculate_final_score(VT_score,SA_score)
        return final_score

    #TODO: Remove default value
    def _calculate_final_score(self, VT, SA, OP = 0):
        return (VT + SA + OP) / 3

    def _classify_input(self, value: str):            
        
        
        s = value.strip()
        if not s: 
            raise ValueError("input is empty.")

        # Expand ~ and resolve relative bits (without requiring existence first)
        p = Path(value).expanduser()

        # Check and return if its a valid file
        if p.exists() and p.is_file():
            suf = p.suffix.lower()
            if suf == ".zip":
                return (InputKind.ZIP, p.resolve())
            if suf == ".crx":
                return (InputKind.CRX, p.resolve())
            raise ValueError(f"Unsupported file type: {p.name} (expected .zip or .crx)")

        #If not a valid file or path try it as an extension ID
        if EXTENSION_ID_RE.fullmatch(s):
            return (InputKind.ID,s)
        
        # Did not match a file or ID
        raise ValueError("Input must be an exisiting .zip/.crx file path or a 32-letter lower ID")