# User Guide

This document describes how to use CETRA (Chrome Extension Threat & Risk Analyzer)
from an end-user perspective.

---

## Intended Users and Use Cases

CETRA is designed for anyone who wants to assess the security and trustworthiness
of Chrome extensions.

Typical users include:

- **End users** who want to verify whether a Chrome extension is safe to install.
- **Students** learning about software security and malware analysis.
- **Security analysts** investigating extension permissions, risks, and behavior.
- **Developers** who want to inspect what their own extensions expose.

---

## Getting Started

To use CETRA, the application must be running and the user must be authenticated.
Refer to the Deployment Guide for setup instructions.

Once logged in, the user is presented with the main navigation interface.

---

## Submitting an Extension for Analysis

The **Home** page serves as the primary analysis interface.

Users can submit a Chrome extension using one of the following methods:

- **Chrome Web Store ID**
- **ZIP file**
- **CRX file**

After submission, the system validates the input and initiates the analysis
workflow.

If a report for the same extension exists from the last 30 days, the user may
choose to either:
- Open the existing report, or
- Run a new analysis

Analysis typically takes a few minutes to complete.

---

## Viewing Analysis Results

Once the analysis is complete, CETRA presents a detailed result view including:

- Overall verdict and threat score
- Requested permissions
- Findings from external analysis services
- Malware family and category information

The system aggregates results from multiple sources to provide a unified view.

---

## History and Report Management

The **History** tab allows users to:

- View previously analyzed extensions
- Browse results using pagination
- Download analysis reports in JSON format

This enables users to retain and reuse analysis results for later review.

---

## MITRE ATT&CK Analysis

The **MITRE ATT&CK** tab provides deeper behavioral analysis.

For supported reports, users can:
- Initiate MITRE ATT&CK mapping
- View detected tactics and techniques
- Track analysis status (Not Started, Completed, Not Available)

MITRE analysis is based on sandbox and behavioral data from external services.

---

## Settings and Interface Features

The **Settings** page allows users to:

- Toggle between light and dark mode themes
- Adjust basic user interface preferences

Users can log out securely at any time using the logout option in the navigation
bar.

---

## Security Notes

- Authentication is required to access all analysis and reporting functionality.
- Multiple failed login attempts will trigger a temporary lockout with a cooldown
  period to reduce brute-force attempts.

---

## Summary

Using CETRA consists of submitting a Chrome extension, waiting for the analysis
to complete, and reviewing the aggregated results. The system is designed to be
simple to use while providing meaningful security insights into Chrome
extensions.
