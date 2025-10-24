from django.core.management.base import BaseCommand
from app.backend.api import apiCaller
from rich import print
from rich.pretty import pprint
import app.config as config
class Command(BaseCommand):
    help = "Run VirusTotal (VT) and Secure Annex (SA) scan"
    
    def handle(self, *args, **options):
        path = "app/uploaded/mil.crx"   # no flags needed
        print(f"[bold cyan] Running mil.crx through all APIs [green]{path}[/green]")
        if config.DEV_MODE is True:
            print(f"[bold red] Dev mode == True fkn idiot [/bold red]")
            #return
        
        apiCaller(path)