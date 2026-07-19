import re
import ipaddress
from urllib.parse import urlparse

from app.models.enums import TargetType
from app.models.target import Target


class ValidationError(Exception):
    """Raised when target validation fails."""
    
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


class TargetValidator:
    """Validates and normalizes scan targets."""
    
    # IPv4 regex pattern
    IPV4_PATTERN = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    
    # Domain regex pattern (simplified)
    DOMAIN_PATTERN = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
        r'[a-zA-Z]{2,}$'
    )
    
    # IPv6 regex pattern (simplified)
    IPV6_PATTERN = re.compile(
        r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|'
        r'^(?:(?:[0-9a-fA-F]{1,4}:){1,7}:|'
        r'(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'
        r'(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|'
        r'(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|'
        r'(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|'
        r'(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|'
        r'[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|'
        r':(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|'
        r'fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|'
        r'::(?:ffff(?::0{1,4}){0,1}:){0,1}'
        r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|'
        r'(?:[0-9a-fA-F]{1,4}:){1,4}:'
        r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$'
    )
    
    @staticmethod
    def validate(target_input: str) -> Target:
        """
        Validate and normalize a target input.
        
        Args:
            target_input: The raw target input from the user
            
        Returns:
            Target model with normalized data
            
        Raises:
            ValidationError: If the target is invalid
        """
        if not target_input or not isinstance(target_input, str):
            raise ValidationError("Target input must be a non-empty string")
        
        target_input = target_input.strip()
        
        if not target_input:
            raise ValidationError("Target input cannot be empty or whitespace")
        
        # Try to detect and validate as IPv4
        if TargetValidator._is_ipv4(target_input):
            return TargetValidator._validate_ipv4(target_input)
        
        # Try to detect and validate as IPv6
        if TargetValidator._is_ipv6(target_input):
            return TargetValidator._validate_ipv6(target_input)
        
        # Try to detect and validate as URL
        if TargetValidator._is_url(target_input):
            return TargetValidator._validate_url(target_input)
        
        # Try to detect and validate as domain
        if TargetValidator._is_domain(target_input):
            return TargetValidator._validate_domain(target_input)
        
        raise ValidationError(
            f"Invalid target: '{target_input}'. "
            "Must be a valid URL, domain, IPv4, or IPv6 address."
        )
    
    @staticmethod
    def _is_ipv4(target: str) -> bool:
        """Check if target looks like an IPv4 address."""
        return bool(TargetValidator.IPV4_PATTERN.match(target))
    
    @staticmethod
    def _is_ipv6(target: str) -> bool:
        """Check if target looks like an IPv6 address."""
        return bool(TargetValidator.IPV6_PATTERN.match(target))
    
    @staticmethod
    def _is_url(target: str) -> bool:
        """Check if target looks like a URL."""
        return target.startswith(('http://', 'https://'))
    
    @staticmethod
    def _is_domain(target: str) -> bool:
        """Check if target looks like a domain."""
        return bool(TargetValidator.DOMAIN_PATTERN.match(target))
    
    @staticmethod
    def _validate_ipv4(target: str) -> Target:
        """Validate and return IPv4 target."""
        try:
            ipaddress.IPv4Address(target)
        except ipaddress.AddressValueError:
            raise ValidationError(f"Invalid IPv4 address: '{target}'")
        
        return Target(
            original_input=target,
            normalized_target=target,
            target_type=TargetType.IPV4,
            protocol=None
        )
    
    @staticmethod
    def _validate_ipv6(target: str) -> Target:
        """Validate and return IPv6 target."""
        try:
            ipaddress.IPv6Address(target)
        except ipaddress.AddressValueError:
            raise ValidationError(f"Invalid IPv6 address: '{target}'")
        
        return Target(
            original_input=target,
            normalized_target=target,
            target_type=TargetType.IPV6,
            protocol=None
        )
    
    @staticmethod
    def _validate_url(target: str) -> Target:
        """Validate and normalize URL target."""
        try:
            parsed = urlparse(target)
            
            if not parsed.scheme or not parsed.netloc:
                raise ValidationError(f"Invalid URL: '{target}'")
            
            if parsed.scheme not in ('http', 'https'):
                raise ValidationError(
                    f"Unsupported protocol in URL: '{target}'. "
                    "Only http and https are supported."
                )
            
            normalized = f"{parsed.scheme}://{parsed.netloc}"
            
            return Target(
                original_input=target,
                normalized_target=normalized,
                target_type=TargetType.URL,
                protocol=parsed.scheme
            )
        except Exception as e:
            if isinstance(e, ValidationError):
                raise
            raise ValidationError(f"Invalid URL: '{target}'")
    
    @staticmethod
    def _validate_domain(target: str) -> Target:
        """Validate and normalize domain target."""
        # Auto-prepend https:// for domains
        normalized = f"https://{target}"
        
        return Target(
            original_input=target,
            normalized_target=normalized,
            target_type=TargetType.DOMAIN,
            protocol="https"
        )
