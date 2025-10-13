from django.core.management.base import BaseCommand
from app.backend.report_generator import ReportGenerator
from rich import print
from rich.pretty import pprint

class Command(BaseCommand):
    help = "Final scoring with hardcoded values"

    def handle(self, *args, **options):
        
        gen = ReportGenerator()
        score = gen._calculate_final_score()
        print(f"final score: {score}")
 