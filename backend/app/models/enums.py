from enum import Enum


class TargetType(str, Enum):
    """Types of targets that can be scanned."""
    DOMAIN = "domain"
    URL = "url"
    IPV4 = "ipv4"
    IPV6 = "ipv6"


class ScanMode(str, Enum):
    """Scan execution modes."""
    FULL = "full"
    CUSTOM = "custom"


class Severity(str, Enum):
    """Severity levels for security findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Status(str, Enum):
    """Execution status of scan modules."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Category(str, Enum):
    """Categories for security findings."""
    RECONNAISSANCE = "reconnaissance"
    PORT_SCANNING = "port_scanning"
    WEB_SECURITY = "web_security"
    SSL_TLS = "ssl_tls"
    TECHNOLOGY = "technology"
    MISCONFIGURATION = "misconfiguration"
