# SentinelScan

## Overview

SentinelScan is an automated web and port auditing system designed for system administrators to assess the security of authorized web applications and network hosts from a single platform. It simplifies the security assessment process by combining reconnaissance, network port auditing, web vulnerability scanning, and report generation into one automated workflow, reducing the need to operate multiple security tools independently.

## Goals

1. Develop a unified system that automates web application vulnerability scanning and network port auditing within a single workflow.
2. Enable system administrators to perform either full or customized security assessments through both a web interface and a command-line interface.
3. Generate structured security assessment reports that summarize identified findings and provide basic remediation recommendations.

## Core User Flow

1. The System Administrator launches SentinelScan through either the web interface or the command-line interface.
2. The user enters the target URL or IP address to be assessed.
3. The user selects either a Full Scan or a Custom Scan and configures the desired scanning modules.
4. SentinelScan validates the target and automatically executes the selected security assessment tasks.
5. The user monitors the scan progress until completion.
6. The system generates a consolidated security assessment report.
7. The user views the report and optionally downloads it as a PDF document.

## Features

### Automated Security Assessment

- Target validation and normalization.
- Reconnaissance and information gathering.
- Network port and service auditing.
- Web vulnerability scanning.
- Structured security report generation.

### User Interaction

- Web-based interface.
- Command-line interface (CLI).
- Full Scan and Custom Scan modes.
- Real-time scan progress monitoring.
- Report viewing and PDF export.

## Scope

### In Scope

- Automated reconnaissance of authorized targets.
- Network port and service auditing.
- Web application vulnerability scanning.
- Full Scan and Custom Scan execution.
- Scan progress monitoring.
- HTML report viewing and PDF report generation.
- Web and command-line interfaces.

### Out of Scope

- User authentication and account management.
- Database storage or scan history.
- Scheduled or recurring scans.
- Automated exploitation of discovered vulnerabilities.
- Continuous security monitoring.
- Distributed or cloud-based scanning.

## Success Criteria

1. A System Administrator can successfully perform a Full Scan or Custom Scan against an authorized target using either the web interface or the command-line interface.
2. SentinelScan automatically completes the selected security assessment tasks and generates a consolidated security assessment report.
3. The generated report can be viewed within the application and downloaded as a PDF document.
