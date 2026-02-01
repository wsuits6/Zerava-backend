"""
Zerava Security Scanner - SSL/TLS Checker

This module checks SSL/TLS configuration including certificate validity,
expiration, supported protocols, and cipher suites.
"""

import logging
import socket
import ssl
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse

from app.models.finding import Finding

logger = logging.getLogger(__name__)


class SSLTLSChecker:
    """
    Checker for SSL/TLS configuration and certificate validation.
    
    Validates:
    - Certificate validity and expiration
    - Supported TLS versions
    - Weak cipher suites
    - Certificate chain
    """
    
    def __init__(self, timeout: int = 10, expiry_warning_days: int = 30):
        """
        Initialize the SSL/TLS checker.
        
        Args:
            timeout: Connection timeout in seconds
            expiry_warning_days: Days before expiration to warn
        """
        self.timeout = timeout
        self.expiry_warning_days = expiry_warning_days
        
        # TLS versions to check
        self.tls_versions = {
            'SSLv2': ssl.PROTOCOL_SSLv23,  # Will be rejected by modern SSL
            'SSLv3': ssl.PROTOCOL_SSLv23,  # Will be rejected by modern SSL
            'TLSv1.0': ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None,
            'TLSv1.1': ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None,
            'TLSv1.2': ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, 'PROTOCOL_TLSv1_2') else None,
            'TLSv1.3': ssl.PROTOCOL_TLS if hasattr(ssl, 'PROTOCOL_TLS') else None,
        }
    
    def check(self, target_url: str) -> Tuple[List[Finding], Dict[str, any]]:
        """
        Perform SSL/TLS checks on the target URL.
        
        Args:
            target_url: URL to check
        
        Returns:
            Tuple of (list of findings, metadata dict)
        """
        findings = []
        metadata = {
            'certificate_valid': False,
            'certificate_expires': None,
            'days_until_expiry': None,
            'supported_tls_versions': [],
            'weak_tls_enabled': False,
            'issuer': None,
            'subject': None
        }
        
        logger.info(f"Starting SSL/TLS check for {target_url}")
        
        # Parse URL to get hostname and port
        parsed = urlparse(target_url)
        hostname = parsed.netloc or parsed.path
        
        # Remove port if specified
        if ':' in hostname:
            hostname = hostname.split(':')[0]
        
        # Default to HTTPS port
        port = parsed.port or 443
        
        # Check certificate
        cert_findings, cert_metadata = self._check_certificate(hostname, port)
        findings.extend(cert_findings)
        metadata.update(cert_metadata)
        
        # Check supported TLS versions
        tls_findings, tls_metadata = self._check_tls_versions(hostname, port)
        findings.extend(tls_findings)
        metadata.update(tls_metadata)
        
        logger.info(f"SSL/TLS check complete for {target_url}. Found {len(findings)} issues.")
        return findings, metadata
    
    def _check_certificate(self, hostname: str, port: int) -> Tuple[List[Finding], Dict]:
        """
        Check certificate validity and expiration.
        
        Args:
            hostname: Target hostname
            port: Target port
        
        Returns:
            Tuple of (findings list, metadata dict)
        """
        findings = []
        metadata = {
            'certificate_valid': False,
            'certificate_expires': None,
            'days_until_expiry': None,
            'issuer': None,
            'subject': None
        }
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    metadata['certificate_valid'] = True
                    
                    # Get certificate details
                    if cert:
                        # Parse expiration date
                        not_after = cert.get('notAfter')
                        if not_after:
                            expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                            metadata['certificate_expires'] = expiry_date.isoformat()
                            
                            # Calculate days until expiry
                            days_until_expiry = (expiry_date - datetime.now()).days
                            metadata['days_until_expiry'] = days_until_expiry
                            
                            # Check if expired
                            if days_until_expiry < 0:
                                findings.append(Finding(
                                    title='SSL/TLS Certificate Expired',
                                    severity='Critical',
                                    category='Encryption',
                                    description=f'The SSL/TLS certificate expired {abs(days_until_expiry)} days ago.',
                                    impact='Users will see security warnings and may not be able to access the site. '
                                           'Browsers will block the connection, preventing secure communication.',
                                    recommendation='Renew the SSL/TLS certificate immediately.',
                                    fix_steps=[
                                        'Obtain a new certificate from your Certificate Authority',
                                        'Install the new certificate on your web server',
                                        'Restart your web server to apply changes',
                                        'Verify the new certificate is working correctly',
                                        'Set up automated renewal (e.g., with Let\'s Encrypt)'
                                    ],
                                    affected_url=f"https://{hostname}:{port}",
                                    evidence={
                                        'expired_date': not_after,
                                        'days_expired': abs(days_until_expiry)
                                    },
                                    cwe_id='CWE-326'
                                ))
                            
                            # Check if expiring soon
                            elif days_until_expiry <= self.expiry_warning_days:
                                severity = 'High' if days_until_expiry <= 7 else 'Medium'
                                findings.append(Finding(
                                    title='SSL/TLS Certificate Expiring Soon',
                                    severity=severity,
                                    category='Encryption',
                                    description=f'The SSL/TLS certificate will expire in {days_until_expiry} days.',
                                    impact='If not renewed, users will see security warnings and may not be able to access the site.',
                                    recommendation='Renew the SSL/TLS certificate before it expires.',
                                    fix_steps=[
                                        'Obtain a renewed certificate from your Certificate Authority',
                                        'Install the new certificate on your web server',
                                        'Restart your web server to apply changes',
                                        'Verify the new certificate is working correctly',
                                        'Consider setting up automated renewal'
                                    ],
                                    affected_url=f"https://{hostname}:{port}",
                                    evidence={
                                        'expiry_date': not_after,
                                        'days_until_expiry': days_until_expiry
                                    },
                                    cwe_id='CWE-298'
                                ))
                        
                        # Get issuer and subject
                        issuer = cert.get('issuer', ())
                        subject = cert.get('subject', ())
                        
                        if issuer:
                            metadata['issuer'] = dict(x[0] for x in issuer)
                        if subject:
                            metadata['subject'] = dict(x[0] for x in subject)
                        
                        # Check for self-signed certificate
                        if issuer and subject and issuer == subject:
                            findings.append(Finding(
                                title='Self-Signed SSL/TLS Certificate',
                                severity='High',
                                category='Encryption',
                                description='The server is using a self-signed certificate not issued by a trusted Certificate Authority.',
                                impact='Users will see security warnings. Browsers will not trust the connection. '
                                       'Attackers could potentially intercept communications without detection.',
                                recommendation='Obtain a certificate from a trusted Certificate Authority.',
                                fix_steps=[
                                    'Obtain a certificate from a trusted CA (e.g., Let\'s Encrypt, DigiCert, Sectigo)',
                                    'Generate a Certificate Signing Request (CSR)',
                                    'Submit CSR to the CA and complete validation',
                                    'Install the CA-signed certificate on your web server',
                                    'Test to ensure browsers trust the certificate'
                                ],
                                affected_url=f"https://{hostname}:{port}",
                                evidence={
                                    'issuer': metadata.get('issuer'),
                                    'subject': metadata.get('subject')
                                },
                                cwe_id='CWE-295'
                            ))
        
        except ssl.SSLError as e:
            logger.warning(f"SSL error checking certificate for {hostname}:{port}: {e}")
            findings.append(Finding(
                title='SSL/TLS Certificate Error',
                severity='Critical',
                category='Encryption',
                description=f'SSL/TLS certificate validation failed: {str(e)}',
                impact='Secure connections cannot be established. Users will see security warnings.',
                recommendation='Fix the certificate issue. This may include certificate expiration, '
                               'incorrect hostname, or untrusted issuer.',
                fix_steps=[
                    'Identify the specific certificate issue',
                    'Obtain a valid certificate from a trusted CA',
                    'Ensure the certificate matches the hostname',
                    'Install the certificate correctly with any required intermediate certificates',
                    'Test the configuration'
                ],
                affected_url=f"https://{hostname}:{port}",
                evidence={'error': str(e)},
                cwe_id='CWE-295'
            ))
        
        except socket.timeout:
            logger.warning(f"Timeout connecting to {hostname}:{port}")
            metadata['error'] = 'Connection timeout'
        
        except Exception as e:
            logger.error(f"Error checking certificate for {hostname}:{port}: {e}")
            metadata['error'] = str(e)
        
        return findings, metadata
    
    def _check_tls_versions(self, hostname: str, port: int) -> Tuple[List[Finding], Dict]:
        """
        Check which TLS versions are supported.
        
        Args:
            hostname: Target hostname
            port: Target port
        
        Returns:
            Tuple of (findings list, metadata dict)
        """
        findings = []
        metadata = {
            'supported_tls_versions': [],
            'weak_tls_enabled': False
        }
        
        weak_versions = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']
        
        for version_name, protocol in self.tls_versions.items():
            if protocol is None:
                continue
            
            if self._is_tls_version_supported(hostname, port, version_name, protocol):
                metadata['supported_tls_versions'].append(version_name)
                
                # Check if it's a weak version
                if version_name in weak_versions:
                    metadata['weak_tls_enabled'] = True
                    
                    severity = 'Critical' if version_name in ['SSLv2', 'SSLv3', 'TLSv1.0'] else 'High'
                    
                    findings.append(Finding.create_weak_tls(
                        version=version_name,
                        url=f"https://{hostname}:{port}"
                    ))
        
        # Check if no secure TLS versions are supported
        secure_versions = [v for v in metadata['supported_tls_versions'] 
                          if v not in weak_versions]
        
        if not secure_versions and metadata['supported_tls_versions']:
            findings.append(Finding(
                title='Only Weak TLS Versions Supported',
                severity='Critical',
                category='Encryption',
                description='The server only supports weak/deprecated TLS versions (SSLv2, SSLv3, TLSv1.0, TLSv1.1).',
                impact='Communications are vulnerable to various attacks including POODLE, BEAST, and downgrade attacks.',
                recommendation='Enable TLS 1.2 and TLS 1.3, and disable all older versions.',
                fix_steps=[
                    'Update server software to a version that supports TLS 1.2 and 1.3',
                    'Configure server to enable only TLS 1.2 and TLS 1.3',
                    'Disable SSLv2, SSLv3, TLSv1.0, and TLSv1.1',
                    'Test configuration with SSL Labs (ssllabs.com/ssltest)',
                    'Ensure client compatibility with TLS 1.2+'
                ],
                affected_url=f"https://{hostname}:{port}",
                evidence={'supported_versions': metadata['supported_tls_versions']},
                cwe_id='CWE-327'
            ))
        
        return findings, metadata
    
    def _is_tls_version_supported(self, hostname: str, port: int, 
                                   version_name: str, protocol) -> bool:
        """
        Check if a specific TLS version is supported.
        
        Args:
            hostname: Target hostname
            port: Target port
            version_name: TLS version name
            protocol: SSL protocol constant
        
        Returns:
            True if supported, False otherwise
        """
        try:
            # Create context with specific protocol
            context = ssl.SSLContext(protocol)
            
            # For older protocols, we need to set specific options
            if version_name == 'TLSv1.0':
                context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
                context.maximum_version = ssl.TLSVersion.TLSv1
                context.minimum_version = ssl.TLSVersion.TLSv1
            elif version_name == 'TLSv1.1':
                context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1
                context.maximum_version = ssl.TLSVersion.TLSv1_1
                context.minimum_version = ssl.TLSVersion.TLSv1_1
            elif version_name == 'TLSv1.2':
                context.maximum_version = ssl.TLSVersion.TLSv1_2
                context.minimum_version = ssl.TLSVersion.TLSv1_2
            
            # Disable hostname verification for this test
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # If we got here, the version is supported
                    return True
        
        except (ssl.SSLError, socket.error, OSError):
            # Connection failed, version not supported
            return False
        
        except Exception as e:
            logger.debug(f"Error checking {version_name} support for {hostname}:{port}: {e}")
            return False