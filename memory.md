# Memory — SentinelScan Backend Implementation

Last updated: July 21, 2026

## What was built

**Shared Models (backend/app/models/)**

- `enums.py` - TargetType, ScanMode, Severity, Status, Category enums
- `target.py` - Target model with original_input, normalized_target, target_type, protocol
- `scan_request.py` - ScanRequest model with target, scan_mode, enabled_modules
- `finding.py` - Finding model with title, description, severity, category, affected_target, recommendation
- `scan_result.py` - ScanResult model with module_name, status, execution_time, findings
- `report.py` - Report model with target, generated_at, scan_duration, overall_status, results
- `reachability_result.py` - ReachabilityResult model with reachable, response_time_ms, method_used
- `__init__.py` - Clean imports for all models

**Target Validation (backend/app/services/)**

- `target_validator.py` - TargetValidator class with URL, domain, IPv4, IPv6 validation
- Auto-prepends https:// for domains without protocol
- Returns normalized Target model with proper type detection
- Structured ValidationError for invalid inputs
- Uses Python standard library only (ipaddress, urllib.parse, re)

**Reachability Checker (backend/app/scanners/)**

- `reachability_checker.py` - ReachabilityChecker class with async HTTP/HTTPS and ICMP ping support
- Cross-platform support (Windows, Linux, macOS) with platform-specific ping commands
- Returns ReachabilityResult with reachable status, response time, and method used
- Structured ReachabilityError for system-level failures
- 10s timeout for HTTP requests, 4s timeout for ICMP ping with 2 packets
- Distinguishes expected failures (unreachable) from unexpected failures (system errors)

**Scan Module Interface (backend/app/scanners/)**

- `scan_module.py` - ScanModule abstract base class (ABC) defining the interface for all scan modules
- Abstract async scan() method with Target input and ScanResult output
- Runtime enforcement ensures concrete modules implement required methods
- Consistent method signatures across all scan modules for orchestrator coordination

**Scan Orchestrator (backend/app/orchestrator/)**

- `scan_orchestrator.py` - ScanOrchestrator class for coordinating concurrent scan module execution
- Accepts ScanModule instances as parameters for flexibility
- Supports Full Scan (all modules) and Custom Scan (selective modules) modes
- Uses asyncio.gather with concurrent execution for performance
- Fault-tolerant design - one module failure doesn't stop others
- Returns list of ScanResult objects from completed modules
- Includes logging for module start/completion events
- **Code quality fix:** Added Target type hints to method parameters
- **Code quality fix:** Fixed docstring inconsistency (removed incorrect "Raises: Exception")

**Scan Configuration (backend/app/services/)**

- `scan_configuration.py` - ScanConfiguration class for preparing scan requests
- Accepts available module names as parameter for validation
- Supports Full Scan mode (runs all available modules)
- Supports Custom Scan mode (runs only specified modules)
- Validates module names against available modules list
- Validates for duplicate module names in Custom Scan
- Structured ScanConfigurationError for invalid configurations
- Returns ScanRequest models compatible with Scan Orchestrator

**Port Scanner (backend/app/scanners/)**

- `port_scanner.py` - PortScanner class implementing ScanModule interface
- Async TCP port scanning using asyncio and Python socket library
- Configurable port range (start_port, end_port) with defaults 1-1024
- Configurable connection timeout per port (default 1.0s)
- Concurrent port scanning using asyncio.gather
- One Finding per open port with Category.PORT_SCANNING and Severity.INFO
- Constructor validation for port ranges (1-65535) and timeout > 0
- Socket cleanup with try-finally to prevent resource leaks
- Uses asyncio.get_running_loop() (current Python 3.13 compatible)
- Clamps port range to maximum valid port (65535)
- Graceful error handling with Status.FAILED on unexpected errors

**Service Detection (backend/app/scanners/)**

- `service_detection.py` - ServiceDetection class implementing ScanModule interface
- Async service detection using hybrid port/banner approach
- Accepts open_ports list as constructor parameter (from PortScanner results)
- Common service port mappings for SSH, HTTP, HTTPS, FTP, SMTP, POP3, IMAP, etc.
- Banner grabbing with configurable timeout (default 2.0s)
- Concurrent banner grabbing using asyncio.gather
- Hybrid detection: port-based lookup with banner confirmation (trusts banner over port)
- One Finding per detected service with Category.RECONNAISSANCE and Severity.INFO
- Unknown services reported as informational findings with partial banner info
- Constructor validation for empty list and invalid port numbers
- Socket cleanup with try-finally to prevent resource leaks
- Uses asyncio.get_running_loop() (current Python 3.13 compatible)
- Graceful error handling with Status.FAILED on unexpected errors

**HTTP Probe (backend/app/scanners/)**

- `http_probe.py` - HttpProbe class implementing ScanModule interface
- Async HTTP probing using httpx library
- Respects target protocol if specified (http:// or https://), otherwise tries HTTPS then HTTP
- Configurable timeout (default 10.0s) with validation
- Extracts final URL, status code, response time, redirect chain, server header, response headers
- Multiple findings: basic HTTP info, redirect chain (if exists), server header, response headers
- All findings use Category.WEB_SECURITY and Severity.INFO
- Redirect chain recorded as list of URLs with status codes
- Response headers recorded only from final response (not intermediate redirects)
- Graceful error handling with Status.FAILED on unreachable targets
- **Code quality fix:** Made probe_http() method public (renamed from \_probe_http) for reuse by other scanners

**Security Header Scanner (backend/app/scanners/)**

- `security_header_scanner.py` - SecurityHeaderScanner class implementing ScanModule interface
- Async security header analysis using httpx library
- Reuses HttpProbe.probe_http() for HTTP requests to avoid code duplication
- Analyzes 6 security headers: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- Reports missing headers with Severity.MEDIUM
- Validates header configurations:
  - CSP: warns on unsafe-inline/unsafe-eval
  - HSTS: warns on max-age < 31536000 or missing includeSubDomains
  - X-Frame-Options: warns on deprecated ALLOW-FROM
  - X-Content-Type-Options: warns if not nosniff
  - Referrer-Policy: warns on no-referrer/unsafe-url
  - Permissions-Policy: presence check only
- Configurable timeout (default 10.0s) with validation
- Graceful error handling with Status.FAILED on unreachable targets
- **Code quality fix:** Made determine_protocols() method public (renamed from \_determine_protocols) for reuse by other scanners
- **Code quality fix:** Fixed HSTS validation to only check includeSubDomains when max-age exists

**HTTP Method Scanner (backend/app/scanners/)**

- `http_method_scanner.py` - HTTPMethodScanner class implementing ScanModule interface
- Async HTTP method discovery using httpx library
- Reuses HttpProbe.determine_protocols() for protocol detection
- Tests 8 HTTP methods sequentially: GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD, TRACE
- Methods returning 405 Method Not Allowed are considered not supported
- Sends empty JSON body for POST/PUT/PATCH methods
- Identifies risky methods: PUT, DELETE, PATCH (Severity.MEDIUM)
- Identifies TRACE method as HIGH severity (potential XST attacks)
- Configurable timeout (default 10.0s) with validation
- Graceful error handling with Status.FAILED on unreachable targets

**SSL Scanner (backend/app/scanners/)**

- `ssl_scanner.py` - SSLScanner class implementing ScanModule interface
- SSL/TLS certificate analysis using Python's built-in ssl module and socket
- Extracts hostname and port from target URL (supports non-standard HTTPS ports)
- Retrieves certificate information: subject, issuer, valid from, expiration date, TLS version
- Detects expired certificates (Severity.HIGH)
- Detects certificates nearing expiration within 30 days (Severity.MEDIUM)
- Flags deprecated TLS versions (TLS 1.0, 1.1) as HIGH severity
- Returns Status.FAILED for HTTP targets (SSL/TLS requires HTTPS)
- Configurable timeout (default 10.0s) with validation
- Graceful error handling with Status.FAILED on certificate retrieval failures
- **Code quality fix:** Fixed datetime comparison error by making parsed SSL dates timezone-aware (UTC)
- **Code quality fix:** Added None checks before strftime() calls to prevent AttributeError
- **Code quality fix:** Fixed typo in near-expiry description
- **Code quality fix:** Made \_get_certificate_info() synchronous (uses blocking socket operations)
- **Code quality fix:** Added port extraction from target URL to support non-standard HTTPS ports

**Technology Detector (backend/app/scanners/)**

- `technology_detector.py` - TechnologyDetector class implementing ScanModule interface
- Technology detection using httpx and BeautifulSoup4
- Reuses HttpProbe.probe_http() and determine_protocols() for HTTP requests
- Analyzes HTTP response headers for technology indicators (web servers, programming languages, frameworks)
- Analyzes HTML source code for technology fingerprints (CMS, frontend frameworks)
- Analyzes response cookies for technology indicators (programming languages)
- Hardcoded detection rules for common technologies (nginx, Apache, WordPress, React, Vue, etc.)
- Configurable timeout (default 10.0s) with validation
- Graceful error handling with Status.FAILED on unreachable targets
- **Code quality fix:** Added response_body and cookies to HttpProbe.probe_http() return dict for TechnologyDetector

**Project Setup**

- Created `.gitignore` with Python, Node.js, Next.js, IDE exclusions
- Git branch "backend" created and pushed to origin
- Progress tracker updated
- Architecture.md updated to reflect backend/app/ structure
- Installed httpx dependency for async HTTP requests

## Decisions made

- Using Pydantic v2 for all data models
- TargetValidator uses only Python standard library (no external dependencies)
- ReachabilityChecker uses httpx for async HTTP and subprocess for ICMP ping
- Backend structure follows modular architecture: backend/app/models/, backend/app/services/, backend/app/scanners/
- All models include type hints and Field descriptions
- Validation errors are structured with custom ValidationError exception
- Reachability errors are structured with custom ReachabilityError exception
- Kept current backend/app/ structure (not backend/core/, backend/scanners/) and updated architecture.md to match
- Async implementation for reachability checker to align with overall async architecture
- PortScanner configuration via constructor parameters to respect ScanModule interface contract
- PortScanner uses asyncio.get_running_loop() for Python 3.13 compatibility
- PortScanner validates constructor parameters to prevent invalid configurations
- ServiceDetection accepts open_ports list as constructor parameter for orchestrator coordination
- ServiceDetection uses hybrid port/banner approach - port-based lookup with banner confirmation
- ServiceDetection trusts banner over port-based guess when available
- ServiceDetection reports unknown services as informational findings with banner info
- HttpProbe respects target protocol if specified, otherwise tries HTTPS then HTTP
- HttpProbe splits findings into multiple objects (basic info, redirect chain, server header, response headers) for better report structure
- HttpProbe records redirect chain as list of URLs with status codes
- HttpProbe records response headers only from final response, not intermediate redirects

## Problems solved

- Pydantic was not installed initially - user installed it in backend/.venv/
- Git branch setup required switching to backend branch before committing
- Test file cleanup - removed test_target_validator.py after verification
- **Bug fix:** Removed `://` from `_is_url` check - was accepting malformed URLs like `://example.com`
- Code review identified and fixed critical URL validation bug
- **Bug fix:** Changed ping response time parsing from `group(1)` (minimum) to `group(2)` (average) for Linux ping output
- Code review identified and fixed ping response time parsing bug
- **Code quality fix:** Removed unused `from typing import Literal` import in reachability_checker.py
- **Code quality fix:** Removed dead `except httpx.HTTPStatusError:` handler in reachability_checker.py
- **Code quality fix:** Added process cleanup on timeout in reachability_checker.py for proper resource management
- **Bug fix:** PortScanner used Category.NETWORK which doesn't exist - changed to Category.PORT_SCANNING
- **Code quality fix:** PortScanner resource leak - added try-finally for socket cleanup
- **Code quality fix:** PortScanner used deprecated asyncio.get_event_loop() - changed to asyncio.get_running_loop()
- **Code quality fix:** PortScanner missing constructor validation - added port range and timeout validation
- **Code quality fix:** PortScanner unused import - removed typing.Optional
- **Code quality fix:** PortScanner port range overflow - clamped to maximum valid port (65535)

## Current state

**Complete:**

- Shared Models implemented, tested, and verified
- Target Validation implemented, tested, and verified
- Reachability Checker implemented, tested, and verified
- Scan Module Interface implemented, tested, and verified
- Scan Orchestrator implemented, tested, and verified
- Scan Configuration implemented, tested, and verified
- Port Scanner implemented, tested, and verified
- Service Detection implemented, tested, and verified
- HTTP Probe implemented, tested, and verified
- Security Header Scanner implemented, tested, and verified
- HTTP Method Scanner implemented, tested, and verified
- SSL Scanner implemented, tested, and verified
- Technology Detector implemented, tested, and verified
- Git branch "backend" created and pushed to origin
- Architecture.md updated to match current structure
- Code reviews completed - critical bugs fixed

**In Progress:**

- Backend implementation (overall phase)

**Next:**

- Implement remaining concrete scan modules (HTTP Probe, Security Header Scanner, SSL Scanner, Technology Detector)
- Implement Report generation

## Next session starts with

Implement Report generation (context/feature-spec/17-report-generator.md) following the feature specification.

## Open questions

None currently.
