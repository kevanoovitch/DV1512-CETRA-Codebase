# API Documentation

## Overview

CETRA does not expose a public API. All application functionality is accessed
through a Django-based Web UI. Internal endpoints coordinate extension analysis,
report generation, and data retrieval.

---

## Authentication

Authentication is handled using Django’s built-in authentication mechanism.
Access to analysis functionality and stored reports is restricted to
authenticated users.

---

## Internal Application Endpoints (High-Level)

- **Extension Submission**
  - Accepts Chrome Web Store IDs, ZIP files, or CRX files
  - Initiates the analysis workflow through the backend API router

- **Report Retrieval**
  - Displays stored analysis results in the Web UI
  - Supports exporting reports in JSON format

- **MITRE ATT&CK Analysis**
  - Initiates behavior mapping based on sandbox analysis results
  - Displays tactics and techniques through the Web UI

---

## External APIs

The system integrates with the following external services:

- **VirusTotal API** – malware detection and reputation analysis
- **OPSWAT MetaDefender API** – multi-engine malware scanning
- **SecureAnnex API** – sandbox-based behavioral analysis
- **Google Gemini API** – AI-assisted interpretation of findings

API credentials are provided via environment variables.
