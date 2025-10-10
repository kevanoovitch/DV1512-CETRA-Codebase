from django.core.management.base import BaseCommand
from app.backend.report_generator import ReportGenerator
from rich import print
from rich.pretty import pprint

class Command(BaseCommand):
    help = "Run VirusTotal (VT) and Secure Annex (SA) scan"

    def handle(self, *args, **options):
        path = "app/uploaded/mil.crx"   # no flags needed
        print(f"[bold cyan]Running Secure Annex scan for[/bold cyan] [green]{path}[/green]")
        generator = ReportGenerator()
        res = generator.scanExtension(path)
        print("\n[bold yellow]Scan result:[/bold yellow]")
        pprint(res, expand_all=True)
