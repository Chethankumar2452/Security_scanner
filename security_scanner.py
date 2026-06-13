"""
Comprehensive security scanning tool for:
- Port scanning
- Service enumeration
- SSL/TLS certificate analysis
- Vulnerability checking
- Network reconnaissance (ethical use only)
"""

import socket
import subprocess
import ssl
import json
from datetime import datetime
from typing import Dict, List, Tuple
import logging
from dataclasses import dataclass, asdict
import nmap
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s'
)
logger = logging.getLogger(__name__)


# ==================== SECURITY SCANNING CLASSES ====================

@dataclass
class PortScanResult:
    """Port scan result data structure."""
    host: str
    port: int
    service: str
    state: str  # 'open', 'closed', 'filtered'
    version: str = ""


@dataclass
class SSLCertificate:
    """SSL certificate information."""
    subject: str
    issuer: str
    version: int
    serial_number: str
    not_before: str
    not_after: str
    is_valid: bool
    days_until_expiry: int


class PortScanner:
    """Advanced port scanning tool."""
    
    # Common ports and their default services
    COMMON_PORTS = {
        21: 'FTP',
        22: 'SSH',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        5900: 'VNC',
        8080: 'HTTP-Proxy',
        8443: 'HTTPS-Alt',
        27017: 'MongoDB'
    }
    
    def __init__(self, host: str, timeout: int = 3):
        self.host = host
        self.timeout = timeout
        self.results = []
    
    def scan_port(self, port: int) -> PortScanResult:
        """
        Scan a single port.
        
        Args:
            port: Port number to scan
            
        Returns:
            PortScanResult with scanning information
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((self.host, port))
            sock.close()
            
            if result == 0:
                service = self.COMMON_PORTS.get(port, 'Unknown')
                logger.info(f"✓ Port {port} ({service}) is OPEN on {self.host}")
                return PortScanResult(
                    host=self.host,
                    port=port,
                    service=service,
                    state='open'
                )
            else:
                return PortScanResult(
                    host=self.host,
                    port=port,
                    service=self.COMMON_PORTS.get(port, 'Unknown'),
                    state='closed'
                )
        
        except socket.gaierror:
            logger.error(f"Hostname {self.host} could not be resolved")
            return None
        except Exception as e:
            logger.error(f"Error scanning port {port}: {str(e)}")
            return None
    
    def scan_ports(self, ports: List[int] = None, threads: int = 10) -> List[PortScanResult]:
        """
        Scan multiple ports concurrently.
        
        Args:
            ports: List of ports to scan (defaults to common ports)
            threads: Number of concurrent threads
            
        Returns:
            List of PortScanResult objects
        """
        if ports is None:
            ports = list(self.COMMON_PORTS.keys())
        
        logger.info(f"Starting scan on {self.host}:{ports} with {threads} threads...")
        
        results = []
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self.scan_port, port): port for port in ports}
            
            for future in as_completed(futures):
                result = future.result()
                if result and result.state == 'open':
                    results.append(result)
        
        self.results = results
        return results
    
    def get_open_ports(self) -> List[int]:
        """Get list of open ports found."""
        return [r.port for r in self.results if r.state == 'open']
    
    def get_report(self) -> Dict:
        """Generate scanning report."""
        open_ports = [r for r in self.results if r.state == 'open']
        return {
            'host': self.host,
            'scan_time': datetime.now().isoformat(),
            'total_scanned': len(self.results),
            'open_ports': len(open_ports),
            'ports': [asdict(r) for r in open_ports]
        }


class SSLChecker:
    """Check SSL/TLS certificates."""
    
    def __init__(self, host: str, port: int = 443):
        self.host = host
        self.port = port
    
    def get_certificate(self) -> Tuple[bool, SSLCertificate]:
        """
        Retrieve and parse SSL certificate.
        
        Returns:
            Tuple of (success, SSLCertificate object)
        """
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.host, self.port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()
                    cert_bin = ssock.getpeercert(binary_form=True)
            
            # Parse certificate info
            subject = dict(x[0] for x in cert['subject'])
            issuer = dict(x[0] for x in cert['issuer'])
            
            # Calculate days until expiry
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_until_expiry = (not_after - datetime.now()).days
            
            ssl_cert = SSLCertificate(
                subject=subject.get('commonName', 'N/A'),
                issuer=issuer.get('commonName', 'N/A'),
                version=cert.get('version', 0),
                serial_number=cert.get('serialNumber', 'N/A'),
                not_before=cert.get('notBefore', 'N/A'),
                not_after=cert.get('notAfter', 'N/A'),
                is_valid=days_until_expiry > 0,
                days_until_expiry=days_until_expiry
            )
            
            logger.info(f"✓ SSL Certificate retrieved for {self.host}")
            return True, ssl_cert
        
        except Exception as e:
            logger.error(f"Error retrieving SSL certificate: {str(e)}")
            return False, None
    
    def check_certificate_validity(self) -> Dict:
        """Check certificate validity and expiry."""
        success, cert = self.get_certificate()
        
        if not success:
            return {'valid': False, 'error': 'Could not retrieve certificate'}
        
        warnings = []
        
        if not cert.is_valid:
            warnings.append(f"Certificate is expired! ({cert.days_until_expiry} days ago)")
        elif cert.days_until_expiry < 30:
            warnings.append(f"Certificate expires soon! ({cert.days_until_expiry} days)")
        
        return {
            'valid': cert.is_valid,
            'subject': cert.subject,
            'issuer': cert.issuer,
            'days_until_expiry': cert.days_until_expiry,
            'not_after': cert.not_after,
            'warnings': warnings
        }


class VulnerabilityChecker:
    """Check for common vulnerabilities."""
    
    VULNERABILITY_CHECKS = {
        'ssl_versions': {
            'description': 'Check for deprecated SSL versions',
            'severity': 'HIGH'
        },
        'weak_ciphers': {
            'description': 'Check for weak encryption ciphers',
            'severity': 'HIGH'
        },
        'heartbleed': {
            'description': 'Check for Heartbleed vulnerability (CVE-2014-0160)',
            'severity': 'CRITICAL'
        },
        'default_credentials': {
            'description': 'Check for default credentials on common services',
            'severity': 'HIGH'
        },
        'banner_grabbing': {
            'description': 'Gather service version information',
            'severity': 'MEDIUM'
        }
    }
    
    def __init__(self, host: str):
        self.host = host
        self.vulnerabilities = []
    
    def check_ssl_vulnerability(self) -> List[Dict]:
        """Check for SSL/TLS vulnerabilities."""
        vulnerabilities = []
        
        try:
            ssl_checker = SSLChecker(self.host)
            cert_result = ssl_checker.check_certificate_validity()
            
            if not cert_result['valid']:
                vulnerabilities.append({
                    'name': 'Invalid SSL Certificate',
                    'severity': 'CRITICAL',
                    'description': 'SSL certificate is invalid or expired',
                    'details': cert_result.get('warnings', [])
                })
            
            if cert_result['days_until_expiry'] < 30:
                vulnerabilities.append({
                    'name': 'Soon-to-Expire Certificate',
                    'severity': 'MEDIUM',
                    'description': f"Certificate expires in {cert_result['days_until_expiry']} days"
                })
        
        except Exception as e:
            logger.warning(f"Could not check SSL: {str(e)}")
        
        return vulnerabilities
    
    def check_common_vulnerabilities(self, open_ports: List[int]) -> List[Dict]:
        """Check for common vulnerabilities on open ports."""
        vulnerabilities = []
        
        # Common vulnerable ports and services
        vulnerable_services = {
            21: 'FTP (Unencrypted)',
            23: 'Telnet (Unencrypted)',
            25: 'SMTP (Open Relay Risk)',
            80: 'HTTP (No Encryption)',
            445: 'SMB (Ransomware Risk)',
            3389: 'RDP (Brute Force Risk)',
            27017: 'MongoDB (Often Unauth)'
        }
        
        for port in open_ports:
            if port in vulnerable_services:
                vulnerabilities.append({
                    'name': f'Potentially Vulnerable Service',
                    'port': port,
                    'service': vulnerable_services[port],
                    'severity': 'MEDIUM',
                    'recommendation': f'Check configuration and access controls for {vulnerable_services[port]}'
                })
        
        return vulnerabilities
    
    def generate_report(self, open_ports: List[int]) -> Dict:
        """Generate comprehensive vulnerability report."""
        ssl_vulns = self.check_ssl_vulnerability()
        service_vulns = self.check_common_vulnerabilities(open_ports)
        
        all_vulnerabilities = ssl_vulns + service_vulns
        
        critical_count = len([v for v in all_vulnerabilities if v.get('severity') == 'CRITICAL'])
        high_count = len([v for v in all_vulnerabilities if v.get('severity') == 'HIGH'])
        
        return {
            'host': self.host,
            'scan_time': datetime.now().isoformat(),
            'summary': {
                'total_vulnerabilities': len(all_vulnerabilities),
                'critical': critical_count,
                'high': high_count,
                'risk_level': 'CRITICAL' if critical_count > 0 else 'HIGH' if high_count > 0 else 'MEDIUM'
            },
            'vulnerabilities': all_vulnerabilities,
            'recommendations': self._get_recommendations(all_vulnerabilities)
        }
    
    def _get_recommendations(self, vulnerabilities: List[Dict]) -> List[str]:
        """Get security recommendations based on findings."""
        recommendations = [
            "✓ Regularly update all services and software",
            "✓ Use firewall rules to restrict unnecessary ports",
            "✓ Enable SSL/TLS on all services",
            "✓ Change default credentials immediately",
            "✓ Implement intrusion detection system",
            "✓ Enable security auditing and logging",
            "✓ Conduct regular security assessments"
        ]
        
        if any('SSL' in v.get('name', '') for v in vulnerabilities):
            recommendations.append("✓ Install valid SSL certificate with proper configuration")
        
        return recommendations


# ==================== MAIN SECURITY SCANNER ====================

class SecurityScanner:
    """Complete security scanning orchestrator."""
    
    def __init__(self, host: str):
        self.host = host
        self.port_scanner = PortScanner(host)
        self.ssl_checker = SSLChecker(host)
        self.vuln_checker = VulnerabilityChecker(host)
    
    def run_full_scan(self, ports: List[int] = None) -> Dict:
        """
        Run complete security scan.
        
        Args:
            ports: List of ports to scan
            
        Returns:
            Complete security assessment report
        """
        logger.info(f"\n{'='*60}")
        logger.info(f"Starting Security Scan on {self.host}")
        logger.info(f"{'='*60}\n")
        
        # 1. Port Scan
        logger.info("Phase 1: Port Scanning...")
        open_ports = self.port_scanner.scan_ports(ports)
        port_report = self.port_scanner.get_report()
        
        # 2. SSL Check
        logger.info("\nPhase 2: SSL/TLS Analysis...")
        ssl_report = self.ssl_checker.check_certificate_validity()
        
        # 3. Vulnerability Check
        logger.info("\nPhase 3: Vulnerability Assessment...")
        vuln_report = self.vuln_checker.generate_report(
            self.port_scanner.get_open_ports()
        )
        
        # Combine reports
        full_report = {
            'scan_date': datetime.now().isoformat(),
            'target': self.host,
            'port_scan': port_report,
            'ssl_analysis': ssl_report,
            'vulnerability_assessment': vuln_report,
            'overall_risk': vuln_report['summary']['risk_level']
        }
        
        return full_report
    
    def save_report(self, report: Dict, filename: str = None):
        """Save report to JSON file."""
        if filename is None:
            filename = f"security_report_{self.host}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"\n✓ Report saved to {filename}")
        return filename


# ==================== USAGE ====================

if __name__ == "__main__":
    import sys
    
    print("""
    ╔════════════════════════════════════════════════════════╗
    ║         ETHICAL SECURITY SCANNER v1.0                  ║
    ║  Only use this tool on systems you own or have         ║
    ║  permission to test. Unauthorized scanning is illegal! ║
    ╚════════════════════════════════════════════════════════╝
    """)
    
    # Usage
    target_host = input("Enter target host to scan: ").strip()
    
    if not target_host:
        target_host = "scanme.nmap.org"  # Public test target
        print(f"Using default target: {target_host}")
    
    # Run scan
    scanner = SecurityScanner(target_host)
    report = scanner.run_full_scan()
    
    # Save report
    filename = scanner.save_report(report)
    
    # Print summary
    print(f"\n{'='*60}")
    print("SCAN SUMMARY")
    print(f"{'='*60}")
    print(f"Target: {report['target']}")
    print(f"Open Ports: {report['port_scan']['open_ports']}")
    print(f"Vulnerabilities Found: {report['vulnerability_assessment']['summary']['total_vulnerabilities']}")
    print(f"Overall Risk Level: {report['overall_risk']}")
    print(f"Report saved to: {filename}")
    
    # Print recommendations
    print(f"\n📋 RECOMMENDATIONS:")
    for rec in report['vulnerability_assessment']['recommendations']:
        print(f"  {rec}")
