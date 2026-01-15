# Threat Modeling

## Overview

Threat modeling was performed to identify and assess potential security threats
to the CETRA system. The analysis focused on user input, the Web UI, backend API
routing, and external API integrations.

The threat modeling process was conducted using OWASP Threat Dragon and follows
a STRIDE-based approach.

---

## Identified Threats and Mitigations

### User Input

#### Denial of Service (DDoS)
- **Threat Type:** Denial of Service
- **Description:** An attacker may attempt to overwhelm the system by submitting
  excessive files or requests.
- **Mitigation:** The system restricts users to submitting only one file at a
  time.
- **Risk Score:** 59 (Medium)

#### SQL Injection
- **Threat Type:** Tampering
- **Description:** Malicious input could be used to manipulate SQL queries.
- **Mitigation:** Input validation is enforced.
- **Risk Score:** 80 (High)

#### SQL Injection – Authentication
- **Threat Type:** Tampering / Authentication Bypass
- **Description:** Improper input handling may allow bypassing authentication.
- **Mitigation:** Input validation is enforced.
- **Risk Score:** 80 (High)

---

### Web UI Frontend

#### Spoofing
- **Threat Type:** Spoofing
- **Description:** Potential spoofing attempts against the frontend.
- **Mitigation:** Considered non-threatening as the software is not publicly
  deployed.
- **Risk Score:** 10 (Low)

#### Server Information Disclosure
- **Threat Type:** Information Disclosure
- **Description:** Server version information may be leaked via HTTP headers.
- **Mitigation:** Server configuration can be modified to remove or obfuscate
  identifying headers.
- **Risk Score:** 10 (Low)

---

### API Router

#### File Download Information Disclosure
- **Threat Type:** Information Disclosure
- **Description:** Improper file handling may expose sensitive files.
- **Mitigation:** Files should be validated before being downloaded.
- **Risk Score:** 20 (Low)

---

### API Interfaces

#### Man-in-the-Middle (MITM)
- **Threat Type:** Tampering
- **Description:** External API responses may be altered during transmission.
- **Mitigation:** API results should be validated before use.
- **Risk Score:** 40 (Low)

---

## Risk Assessment

Risk levels were assessed using CVSS v4.0 scoring where applicable.
High-risk threats were identified pr
