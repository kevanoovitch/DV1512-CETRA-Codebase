# app/management/commands/run_vt_demo.py

from django.core.management.base import BaseCommand
from app.backend.api import prefrom_virus_total_scan
from app import config

class Command(BaseCommand):
    help = "Run a VirusTotal scan for a local file."

    def handle(self, *args, **options):
        file_path = "app/uploaded/mil.crx"
        self.stdout.write(f"Running Secure Annex scan for {file_path}")
        try:
            prefrom_virus_total_scan(file_path)
        except FileNotFoundError:
            self.stderr.write(self.style.ERROR(f"File not found: {file_path}"))
            return

        self.stdout.write(self.style.SUCCESS("Scan complete."))
