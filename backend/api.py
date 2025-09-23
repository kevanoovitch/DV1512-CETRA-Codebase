import json
from backend.API_interfaces.SecureAnnexInterface import ISecureAnnex
from rich import print as rprint, print_json
from rich.console import Console


def preform_secure_annex_scan(extension):
    #TODO: implement this function
    pass



def print_secure_annex_scan(extension):
    client = ISecureAnnex(None, None)
    console = Console()
    # Fetch and print manifest
    
    console.rule("[bold cyan]Manifest[/bold cyan]")
    result = client.fetch_manifest(extension)
    pretty_print_json(result)

    # fetch and print vulnerabilities
    console.rule("\n[bold magenta]Vulnerabilities[/bold magenta]")
   

    result = client.fetch_vulnerabilities(extension)
    pretty_print_json(result)

    # fetch & print Signatures
    console.rule("\n[bold magenta]Signatures[/bold magenta]")
    result = client.fetch_signatures(extension)
    pretty_print_json(result)

    # fetch and print urls
    console.rule("\n[bold magenta]URLs[/bold magenta]")
    
    result = client.fetch_urls(extension)
    pretty_print_json(result)

    # fetch and print AI-Analysis
    console.rule("\n[bold magenta]AI-Analysis[/bold magenta]")
    
    result = client.fetch_urls(extension)
    pretty_print_json(result)



def pretty_print_json(data):
    if isinstance(data, str):
        try:
            print_json(data)
            return
        except Exception:
            print(data)
            return
    print_json(json.dumps(data))


def extension_converter():
    # TODO: implement a input converter i.e zip->webID & crx -> webID 
    pass 
