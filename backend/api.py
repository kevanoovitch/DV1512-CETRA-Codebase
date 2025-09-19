import json
from backend.API_interfaces.SecureAnnexInterface import ISecureAnnex


def preform_secure_annex_scan(extension):
    client = ISecureAnnex(None, None)
    result = client.GetManifestRisks(extension)
    pretty_print_json(result)

def pretty_print_json(data):
    """
    Print JSON data in a pretty, indented format.
    Accepts dicts (Python objects) or JSON strings.
    """
    if isinstance(data, str):
        try:
            data = json.loads(data)
            print(json.dumps(data, indent=4, sort_keys=True))
            return
        except json.JSONDecodeError:
            # Not JSON; print raw string
            print(data)
            return
    print(json.dumps(data, indent=4, sort_keys=True))


def extension_converter():
    # TODO: implement a input converter i.e zip->webID & crx -> webID 
    pass 
