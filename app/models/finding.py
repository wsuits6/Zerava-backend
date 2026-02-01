"""
Zerava Security Scanner - Finding Model

This module defines the Finding data model representing a security vulnerability
or issue discovered during a scan.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
import uuid


@dataclass
class Finding:
    """
    Represents a security finding (vulnerability or issue).
    
    Attributes:
        id: Unique identifier for the finding
        title: Brief title describing the finding
        severity: Severity level (Critical, High, Medium, Low, Info)
        category: Category of the finding
        description: Detailed description of the issue
        impact: Potential impact if not addressed
        recommendation: High-level recommendation to fix
        fix_steps: List of specific steps to remediate
        affected_url: URL or endpoint where issue was found
        evidence: Additional evidence or proof of the finding
        cwe_id: Common Weakness Enumeration ID (if applicable)
        cvss_score: CVSS score (if applicable)
        references: List of reference URLs for more information
    """
    
    title: str
    severity: str
    category: str
    description: str
    impact: str
    recommendation: str
    id: str = field(default_factory=lambda: f"f-{uuid.uuid4().hex[:8]}")
    fix_steps: List[str] = field(default_factory=list)
    affected_url: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    references: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Validate finding data after initialization."""
        self._validate()
    
    def _validate(self):
        """
        Validate finding attributes.
        
        Raises:
            ValueError: If validation fails
        """
        valid_severities = ['Critical', 'High', 'Medium', 'Low', 'Info']
        if self.severity not in valid_severities:
            raise ValueError(f"Invalid severity. Must be one of: {valid_severities}")
        
        if not self.title:
            raise ValueError("Title is required")
        
        if not self.description:
            raise ValueError("Description is required")
        
        if self.cvss_score is not None and (self.cvss_score < 0 or self.cvss_score > 10):
            raise ValueError("CVSS score must be between 0 and 10")
    
    def add_fix_step(self, step: str) -> None:
        """
        Add a fix step to the finding.
        
        Args:
            step: Description of a remediation step
        """
        self.fix_steps.append(step)
    
    def add_evidence(self, key: str, value: Any) -> None:
        """
        Add evidence to the finding.
        
        Args:
            key: Evidence key/type
            value: Evidence value
        """
        self.evidence[key] = value
    
    def add_reference(self, url: str) -> None:
        """
        Add a reference URL.
        
        Args:
            url: Reference URL
        """
        if url not in self.references:
            self.references.append(url)
    
    def get_severity_weight(self) -> int:
        """
        Get numeric weight for severity level.
        
        Returns:
            Severity weight for scoring purposes
        """
        weights = {
            'Critical': 40,
            'High': 20,
            'Medium': 10,
            'Low': 5,
            'Info': 0
        }
        return weights.get(self.severity, 0)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert finding to dictionary representation.
        
        Returns:
            Dictionary containing finding data
        """
        return asdict(self)
    
    def to_summary_dict(self) -> Dict[str, Any]:
        """
        Convert finding to summary dictionary (for listing).
        
        Returns:
            Dictionary containing summary data
        """
        return {
            'id': self.id,
            'title': self.title,
            'severity': self.severity,
            'category': self.category,
            'affected_url': self.affected_url
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Finding':
        """
        Create a Finding instance from dictionary data.
        
        Args:
            data: Dictionary containing finding data
        
        Returns:
            Finding instance
        """
        # Remove any extra fields that aren't part of the dataclass
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered_data = {k: v for k, v in data.items() if k in valid_fields}
        
        return cls(**filtered_data)
    
    @classmethod
    def create_missing_security_header(
        cls,
        header_name: str,
        url: str,
        severity: str = 'Medium'
    ) -> 'Finding':
        """
        Factory method to create a finding for a missing security header.
        
        Args:
            header_name: Name of the missing header
            url: URL where header is missing
            severity: Severity level (default: Medium)
        
        Returns:
            Finding instance for missing security header
        """
        header_info = {
            'X-Frame-Options': {
                'impact': 'The site may be vulnerable to clickjacking attacks.',
                'recommendation': 'Set X-Frame-Options to DENY or SAMEORIGIN.',
                'fix_steps': [
                    'Configure your web server to send X-Frame-Options header',
                    'Set value to "DENY" to prevent all framing, or "SAMEORIGIN" to allow same-origin framing',
                    'Test using browser developer tools to verify header is present'
                ]
            },
            'X-Content-Type-Options': {
                'impact': 'The site may be vulnerable to MIME-type sniffing attacks.',
                'recommendation': 'Set X-Content-Type-Options to nosniff.',
                'fix_steps': [
                    'Configure your web server to send X-Content-Type-Options header',
                    'Set value to "nosniff"',
                    'Verify with browser developer tools'
                ]
            },
            'Strict-Transport-Security': {
                'impact': 'Connections may be downgraded to insecure HTTP.',
                'recommendation': 'Enable HSTS with a max-age of at least 31536000 seconds (1 year).',
                'fix_steps': [
                    'Configure your web server to send Strict-Transport-Security header',
                    'Set value to "max-age=31536000; includeSubDomains"',
                    'Consider adding "preload" directive for HSTS preload list inclusion'
                ]
            },
            'Content-Security-Policy': {
                'impact': 'The site may be vulnerable to XSS and data injection attacks.',
                'recommendation': 'Implement a Content Security Policy appropriate for your application.',
                'fix_steps': [
                    'Define a CSP policy that restricts resource loading',
                    'Start with a restrictive policy and refine as needed',
                    'Configure your web server to send Content-Security-Policy header',
                    'Test thoroughly to ensure functionality is not broken'
                ]
            },
            'X-XSS-Protection': {
                'impact': 'Browser XSS filters may not be enabled.',
                'recommendation': 'Set X-XSS-Protection to "1; mode=block".',
                'fix_steps': [
                    'Configure your web server to send X-XSS-Protection header',
                    'Set value to "1; mode=block"',
                    'Note: This header is deprecated in favor of CSP'
                ]
            },
            'Referrer-Policy': {
                'impact': 'Sensitive information in URLs may leak via referrer header.',
                'recommendation': 'Set Referrer-Policy to a restrictive value like "strict-origin-when-cross-origin".',
                'fix_steps': [
                    'Configure your web server to send Referrer-Policy header',
                    'Choose appropriate policy (e.g., "strict-origin-when-cross-origin")',
                    'Test to ensure external links and analytics still function'
                ]
            },
            'Permissions-Policy': {
                'impact': 'Browser features may be accessible to malicious scripts.',
                'recommendation': 'Set Permissions-Policy to restrict browser features.',
                'fix_steps': [
                    'Configure your web server to send Permissions-Policy header',
                    'Define which features should be allowed (e.g., "geolocation=(), microphone=()")',
                    'Test to ensure required features still work'
                ]
            }
        }
        
        info = header_info.get(header_name, {
            'impact': 'Security configuration may be weakened.',
            'recommendation': f'Consider adding the {header_name} header.',
            'fix_steps': [f'Research best practices for {header_name}', 'Configure the header appropriately']
        })
        
        return cls(
            title=f'Missing Security Header: {header_name}',
            severity=severity,
            category='Configuration',
            description=f'The server is not sending the {header_name} security header.',
            impact=info['impact'],
            recommendation=info['recommendation'],
            fix_steps=info['fix_steps'],
            affected_url=url
        )
    
    @classmethod
    def create_weak_tls(
        cls,
        version: str,
        url: str
    ) -> 'Finding':
        """
        Factory method to create a finding for weak TLS version.
        
        Args:
            version: TLS version (e.g., TLSv1.0)
            url: URL where weak TLS is enabled
        
        Returns:
            Finding instance for weak TLS
        """
        return cls(
            title=f'Weak TLS Version Enabled: {version}',
            severity='Critical',
            category='Encryption',
            description=f'{version} is enabled on the server. This version is deprecated and vulnerable to attacks.',
            impact='Allows downgrade attacks and weak encryption that can be exploited by attackers.',
            recommendation=f'Disable {version} and enable only TLS 1.2 and TLS 1.3.',
            fix_steps=[
                f'Update server configuration to disable {version}',
                'Enable only TLS 1.2 and TLS 1.3',
                'Test with SSL Labs (ssllabs.com/ssltest) to verify configuration',
                'Ensure all client applications support TLS 1.2+'
            ],
            affected_url=url,
            cwe_id='CWE-327'
        )
    
    def __repr__(self) -> str:
        """String representation of the finding."""
        return f"Finding(id='{self.id}', title='{self.title}', severity='{self.severity}')"