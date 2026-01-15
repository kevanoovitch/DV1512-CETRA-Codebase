
# Requirements and Scope

## Functional Requirements

The CETRA system fulfills the following functional requirements:

- The system accepts uploaded Chrome extensions for analysis.
- The system extracts an extension ID from uploaded data.
- The system submits scan requests to multiple external analysis services.
- The system aggregates results from multiple scanners.
- The system generates an analysis report.
- The system retrieves stored reports for later viewing.
- The system persists analysis results in a database.
- The system requires authentication to access the application, including
  generating and viewing analysis reports.

---

## Non-Functional Requirements

The system is designed to satisfy the following non-functional requirements:

- The system uses a modular, component-based architecture.
- The system supports integration with multiple external APIs.
- The system isolates untrusted file analysis from the core system.
- The system enforces authorization at the application level so that only
  authenticated users can access stored analysis reports.
- The system remains usable while long-running analyses are performed.
- The system validates uploaded files as Chrome extensions (e.g., presence and
  structure of `manifest.json`) and rejects invalid uploads.
- The system reduces supply-chain risk by restricting analysis inputs to Chrome
  Web Store extensions only.

---

## Security Scope and Limitations

The system enforces authentication and authorization at the application level.
Analysis results are stored in a local SQLite database, which is not encrypted
at rest.

As a result, users with direct operating system access to the host machine may
read database contents outside of the application. Passwords are stored using
secure cryptographic hashing.

Protecting data at rest (e.g., database encryption and OS-level access control)
is considered out of scope for the current prototype and would be required for a
production deployment.
