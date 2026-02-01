"""
Zerava Security Scanner - Report Model

This module defines the Report data model representing the complete results
of a security scan, including all findings and summary statistics.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime
from app.models.scan import Scan
from app.models.finding import Finding


@dataclass
class Report:
    """
    Represents a complete security scan report.
    
    Attributes:
        scan: The associated Scan object
        findings: List of Finding objects
        summary: Summary statistics of findings by severity
        metadata: Additional metadata about the report
    """
    
    scan: Scan
    findings: List[Finding] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=lambda: {
        'totalFindings': 0,
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'info': 0
    })
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_finding(self, finding: Finding) -> None:
        """
        Add a finding to the report and update summary statistics.
        
        Args:
            finding: Finding object to add
        """
        self.findings.append(finding)
        self._update_summary()
    
    def add_findings(self, findings: List[Finding]) -> None:
        """
        Add multiple findings to the report.
        
        Args:
            findings: List of Finding objects to add
        """
        self.findings.extend(findings)
        self._update_summary()
    
    def _update_summary(self) -> None:
        """Update the summary statistics based on current findings."""
        self.summary = {
            'totalFindings': len(self.findings),
            'critical': sum(1 for f in self.findings if f.severity == 'Critical'),
            'high': sum(1 for f in self.findings if f.severity == 'High'),
            'medium': sum(1 for f in self.findings if f.severity == 'Medium'),
            'low': sum(1 for f in self.findings if f.severity == 'Low'),
            'info': sum(1 for f in self.findings if f.severity == 'Info')
        }
        
        # Update scan findings count
        self.scan.findings = {
            'critical': self.summary['critical'],
            'high': self.summary['high'],
            'medium': self.summary['medium'],
            'low': self.summary['low']
        }
    
    def get_findings_by_severity(self, severity: str) -> List[Finding]:
        """
        Get all findings of a specific severity level.
        
        Args:
            severity: Severity level to filter by
        
        Returns:
            List of findings matching the severity
        """
        return [f for f in self.findings if f.severity == severity]
    
    def get_findings_by_category(self, category: str) -> List[Finding]:
        """
        Get all findings of a specific category.
        
        Args:
            category: Category to filter by
        
        Returns:
            List of findings matching the category
        """
        return [f for f in self.findings if f.category == category]
    
    def get_critical_findings(self) -> List[Finding]:
        """Get all critical severity findings."""
        return self.get_findings_by_severity('Critical')
    
    def get_high_findings(self) -> List[Finding]:
        """Get all high severity findings."""
        return self.get_findings_by_severity('High')
    
    def get_medium_findings(self) -> List[Finding]:
        """Get all medium severity findings."""
        return self.get_findings_by_severity('Medium')
    
    def get_low_findings(self) -> List[Finding]:
        """Get all low severity findings."""
        return self.get_findings_by_severity('Low')
    
    def add_metadata(self, key: str, value: Any) -> None:
        """
        Add metadata to the report.
        
        Args:
            key: Metadata key
            value: Metadata value
        """
        self.metadata[key] = value
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert report to dictionary representation for API responses.
        
        Returns:
            Dictionary containing complete report data
        """
        return {
            'id': self.scan.id,
            'target': self.scan.target,
            'type': self.scan.scan_type,
            'date': self.scan.created_at.isoformat() + 'Z' if self.scan.created_at else None,
            'score': self.scan.score,
            'status': self.scan.status,
            'summary': self.summary,
            'findings': [f.to_dict() for f in self.findings],
            'metadata': self.metadata,
            'duration': self.scan.get_duration()
        }
    
    def to_summary_dict(self) -> Dict[str, Any]:
        """
        Convert report to summary dictionary (for listing).
        
        Returns:
            Dictionary containing summary data
        """
        return {
            'id': self.scan.id,
            'target': self.scan.target,
            'type': self.scan.scan_type,
            'date': self.scan.created_at.isoformat() + 'Z' if self.scan.created_at else None,
            'status': self.scan.status,
            'score': self.scan.score,
            'findings': {
                'critical': self.summary['critical'],
                'high': self.summary['high'],
                'medium': self.summary['medium'],
                'low': self.summary['low']
            }
        }
    
    def get_top_findings(self, limit: int = 5) -> List[Finding]:
        """
        Get the top N most severe findings.
        
        Args:
            limit: Maximum number of findings to return
        
        Returns:
            List of top findings sorted by severity
        """
        # Sort findings by severity weight (descending)
        sorted_findings = sorted(
            self.findings,
            key=lambda f: f.get_severity_weight(),
            reverse=True
        )
        return sorted_findings[:limit]
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get detailed statistics about the report.
        
        Returns:
            Dictionary containing various statistics
        """
        categories = {}
        for finding in self.findings:
            categories[finding.category] = categories.get(finding.category, 0) + 1
        
        return {
            'total_findings': self.summary['totalFindings'],
            'by_severity': {
                'critical': self.summary['critical'],
                'high': self.summary['high'],
                'medium': self.summary['medium'],
                'low': self.summary['low'],
                'info': self.summary['info']
            },
            'by_category': categories,
            'scan_duration': self.scan.get_duration(),
            'score': self.scan.score
        }
    
    @classmethod
    def from_scan(cls, scan: Scan) -> 'Report':
        """
        Create a Report instance from a Scan.
        
        Args:
            scan: Scan object
        
        Returns:
            Report instance
        """
        return cls(scan=scan)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Report':
        """
        Create a Report instance from dictionary data.
        
        Args:
            data: Dictionary containing report data
        
        Returns:
            Report instance
        """
        # Reconstruct scan object
        scan_data = {
            'id': data.get('id'),
            'target': data.get('target'),
            'scan_type': data.get('type'),
            'status': data.get('status', 'completed'),
            'score': data.get('score', 0),
            'findings': data.get('summary', {})
        }
        
        if data.get('date'):
            scan_data['created_at'] = datetime.fromisoformat(data['date'].replace('Z', '+00:00'))
        
        scan = Scan.from_dict(scan_data)
        
        # Reconstruct findings
        findings = [
            Finding.from_dict(f_data)
            for f_data in data.get('findings', [])
        ]
        
        report = cls(scan=scan)
        report.add_findings(findings)
        report.metadata = data.get('metadata', {})
        
        return report
    
    def __repr__(self) -> str:
        """String representation of the report."""
        return (f"Report(scan_id='{self.scan.id}', target='{self.scan.target}', "
                f"findings={self.summary['totalFindings']}, score={self.scan.score})")