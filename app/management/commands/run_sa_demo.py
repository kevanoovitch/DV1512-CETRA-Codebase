#!/usr/bin/env python3
import os
import django

# Setup Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "app.settings")
django.setup()

from app.backend.api import prefrom_virus_total_scan
from app import config

if __name__ == "__main__":
    path = "app/uploaded/mil.crx"
    print(f"Running Secure Annex scan for {path}")
    prefrom_virus_total_scan(path)

    
