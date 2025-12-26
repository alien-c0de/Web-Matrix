"""
Improved SSL Certificate Analyzer
Enhanced validation, scoring, and error handling
"""

import ssl
import socket
from colorama import Fore, Style
from OpenSSL import crypto
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import ExtendedKeyUsageOID
import hashlib
from datetime import datetime, timezone
from time import perf_counter
import traceback
from typing import Dict, List, Tuple, Optional
import re

from util.config_uti import Configuration
from util.issue_config import Issue_Config
from util.report_util import Report_Utility


class SSL_Certificate:
    """Enhanced SSL Certificate analyzer with comprehensive validation"""
    
    Error_Title = None

    def __init__(self, url: str = None, domain: str = None):
        self.url = url
        self.domain = domain
        self._cert_cache = None  # Cache certificate data

    async def Get_SSL_Certificate(self, port: int = 443):
        """
        Main method to fetch and analyze SSL certificate
        Returns: [table_html, analysis_html]
        """
        config = Configuration()
        self.Error_Title = config.SSL_CERTIFICATE
        output = []

        try:
            start_time = perf_counter()
            
            # Get certificate with comprehensive validation
            cert_data = await self._fetch_certificate_with_validation(port)
            
            if not cert_data['success']:
                error_msg = cert_data.get('error', 'Unknown error')
                print(f"⚠️ {config.MODULE_SSL_CERTIFICATE} - Warning: {error_msg}")
                output = await self.__empty_output(error_msg)
                return output
            
            # Extract certificate details
            cert_details = await self._extract_certificate_details(cert_data['certificate'])
            
            # Add trust validation results
            cert_details['is_trusted'] = cert_data.get('is_trusted', False)
            cert_details['is_self_signed'] = cert_data.get('is_self_signed', False)
            cert_details['trust_error'] = cert_data.get('trust_error')
            cert_details['days_until_expiry'] = cert_data.get('days_until_expiry')
            cert_details['san_domains'] = cert_data.get('san_domains', [])
            
            # Generate HTML output
            output = await self.__html_table(cert_details)
            
            elapsed_time = round(perf_counter() - start_time, 2)
            print(f"✅ {config.MODULE_SSL_CERTIFICATE} has been successfully completed in {elapsed_time} seconds.")
            
            return output
            
        except Exception as ex:
            error_type, error_message, tb = ex.__class__.__name__, str(ex), traceback.extract_tb(ex.__traceback__)
            error_details = tb[-1]
            file_name = error_details.filename
            method_name = error_details.name
            line_number = error_details.lineno

            error_msg = f"❌ {self.Error_Title} => ERROR in method '{method_name}' at line {line_number} : {error_type}: {error_message}"
            print(error_msg)
            output = await self.__empty_output(error_message)
            return output

    async def _fetch_certificate_with_validation(self, port: int = 443) -> Dict:
        """
        Fetch certificate with comprehensive validation
        Returns dict with success status, certificate, and validation results
        """
        result = {
            'success': False,
            'certificate': None,
            'is_trusted': False,
            'is_self_signed': False,
            'trust_error': None,
            'days_until_expiry': None,
            'san_domains': []
        }
        
        try:
            # Step 1: Try with validation (checks against system trust store)
            context_validated = ssl.create_default_context()
            cert_bin = None
            
            try:
                with socket.create_connection((self.domain, port), timeout=10) as sock:
                    with context_validated.wrap_socket(sock, server_hostname=self.domain) as ssock:
                        cert_bin = ssock.getpeercert(binary_form=True)
                        result['is_trusted'] = True  # If we get here, certificate is trusted
                        
            except ssl.SSLCertVerificationError as e:
                # Certificate validation failed - try without validation to get cert details
                result['trust_error'] = str(e.verify_message)
                result['is_trusted'] = False
                
            except ssl.SSLError as e:
                result['trust_error'] = f"SSL Error: {str(e)}"
                result['is_trusted'] = False
            
            # Step 2: If validation failed, get certificate without validation
            if cert_bin is None:
                context_unvalidated = ssl.create_default_context()
                context_unvalidated.check_hostname = False
                context_unvalidated.verify_mode = ssl.CERT_NONE
                
                try:
                    with socket.create_connection((self.domain, port), timeout=10) as sock:
                        with context_unvalidated.wrap_socket(sock, server_hostname=self.domain) as ssock:
                            cert_bin = ssock.getpeercert(binary_form=True)
                except Exception as e:
                    result['error'] = f"Cannot retrieve certificate: {str(e)}"
                    return result
            
            # Step 3: Parse certificate
            if cert_bin:
                cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                result['certificate'] = cert
                result['success'] = True
                
                # Check if self-signed
                result['is_self_signed'] = self._is_certificate_self_signed(cert)
                
                # Calculate days until expiry
                now = datetime.now(timezone.utc)
                if cert.not_valid_after_utc > now:
                    result['days_until_expiry'] = (cert.not_valid_after_utc - now).days
                else:
                    result['days_until_expiry'] = -((now - cert.not_valid_after_utc).days)
                
                # Get SAN domains
                result['san_domains'] = self._extract_san_domains(cert)
            
            return result
            
        except socket.timeout:
            result['error'] = f"Connection timeout after 10 seconds"
            return result
            
        except socket.gaierror as e:
            result['error'] = f"DNS resolution failed: {str(e)}"
            return result
            
        except ConnectionRefusedError:
            result['error'] = f"Connection refused on port {port}"
            return result
            
        except Exception as e:
            result['error'] = f"Unexpected error: {str(e)}"
            return result

    def _is_certificate_self_signed(self, cert: x509.Certificate) -> bool:
        """
        Enhanced self-signed certificate detection
        A certificate is self-signed if issuer == subject
        """
        try:
            return cert.issuer == cert.subject
        except Exception:
            return False

    def _extract_san_domains(self, cert: x509.Certificate) -> List[str]:
        """Extract Subject Alternative Names (SAN) from certificate"""
        try:
            san_extension = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            san = san_extension.value
            
            dns_names = []
            for name in san:
                if isinstance(name, x509.DNSName):
                    dns_names.append(name.value)
            
            return dns_names
            
        except x509.ExtensionNotFound:
            # No SAN extension, try to get CN from subject
            try:
                cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                if cn_attrs:
                    return [cn_attrs[0].value]
            except:
                pass
            return []
            
        except Exception:
            return []

    async def _extract_certificate_details(self, cert: x509.Certificate) -> Dict:
        """Extract all relevant details from certificate"""
        
        cert_details = {
            "Subject": cert.subject,
            "Issuer": cert.issuer,
            "Expires": cert.not_valid_after_utc,
            "Renewed": cert.not_valid_before_utc,
            "Serial Number": cert.serial_number,
        }

        # Compute SHA1 Fingerprint
        cert_bin = cert.public_bytes(encoding=x509.Encoding.DER)
        sha1_fingerprint = hashlib.sha1(cert_bin).hexdigest().upper()
        cert_details["Fingerprint"] = sha1_fingerprint

        # Extract Extended Key Usage (EKU)
        ext_key_usage = []
        try:
            eku_extension = cert.extensions.get_extension_for_oid(
                ExtensionOID.EXTENDED_KEY_USAGE
            )
            extended_usage = eku_extension.value
            
            for purpose in extended_usage:
                if purpose == ExtendedKeyUsageOID.SERVER_AUTH:
                    ext_key_usage.append("TLS Web Server Authentication")
                if purpose == ExtendedKeyUsageOID.CLIENT_AUTH:
                    ext_key_usage.append("TLS Web Client Authentication")
                    
        except x509.ExtensionNotFound:
            # EKU extension not present
            pass
        except Exception as e:
            print(f"⚠️ Warning: Could not extract Extended Key Usage: {e}")

        cert_details["Extended Key Usage"] = ext_key_usage
        
        return cert_details

    async def __html_table(self, cert_details: Dict):
        """Generate HTML table with certificate details"""
        rep_data = []
        html = ""
        
        if not cert_details:
            report_util = Report_Utility()
            table = await report_util.Empty_Table()
        else:
            # Extract subject
            subject = cert_details["Subject"]
            subject_cn = self._extract_name_attribute(subject, NameOID.COMMON_NAME)
            
            # Extract issuer
            issuer = cert_details["Issuer"]
            issuer_org = self._extract_name_attribute(issuer, NameOID.ORGANIZATION_NAME)
            if not issuer_org:
                issuer_org = self._extract_name_attribute(issuer, NameOID.COMMON_NAME)

            # Format dates
            expires_date = cert_details["Expires"]
            formatted_expire = expires_date.strftime('%d %B %Y').lstrip('0').replace(" 0", " ")
            
            renewed_date = cert_details["Renewed"]
            formatted_renew = renewed_date.strftime('%d %B %Y').lstrip('0').replace(" 0", " ")
            
            # Format serial number
            serial_number = hex(cert_details["Serial Number"])[2:].upper()
            
            # Format fingerprint with colons
            fingerprint = cert_details["Fingerprint"]
            formatted_fingerprint = ":".join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))
            
            # Extended Key Usage
            ext_key_usage = cert_details["Extended Key Usage"]
            TLS_Web_Server = "TLS Web Server Authentication" if "TLS Web Server Authentication" in ext_key_usage else ""
            TLS_Web_Client = "TLS Web Client Authentication" if "TLS Web Client Authentication" in ext_key_usage else ""
            TLS_OK = bool(TLS_Web_Server or TLS_Web_Client)

            # Get trust information
            is_trusted = cert_details.get('is_trusted', False)
            is_self_signed = cert_details.get('is_self_signed', False)
            trust_error = cert_details.get('trust_error')
            days_until_expiry = cert_details.get('days_until_expiry')
            san_domains = cert_details.get('san_domains', [])

            # Calculate score
            percentage, html = await self.__ssl_score(
                subject_cn, issuer_org, expires_date, renewed_date, 
                serial_number, fingerprint, TLS_Web_Server, TLS_Web_Client,
                is_trusted, is_self_signed, days_until_expiry, san_domains
            )
            
            # Build trust status indicator
            trust_status = ""
            if is_self_signed:
                trust_status = """<tr>
                    <td colspan="2" style="background-color: #fff3cd; padding: 10px; border-left: 4px solid #ffc107;">
                        <strong>⚠️ Self-Signed Certificate</strong><br>
                        <small>This certificate is self-signed and not trusted by public certificate authorities.</small>
                    </td>
                </tr>"""
            elif not is_trusted and trust_error:
                trust_status = f"""<tr>
                    <td colspan="2" style="background-color: #f8d7da; padding: 10px; border-left: 4px solid #dc3545;">
                        <strong>❌ Certificate Not Trusted</strong><br>
                        <small>{trust_error}</small>
                    </td>
                </tr>"""
            elif is_trusted:
                trust_status = """<tr>
                    <td colspan="2" style="background-color: #d4edda; padding: 10px; border-left: 4px solid #28a745;">
                        <strong>✅ Trusted Certificate</strong><br>
                        <small>Certificate is trusted by system certificate authorities.</small>
                    </td>
                </tr>"""
            
            # Build expiry warning
            expiry_warning = ""
            if days_until_expiry is not None:
                if days_until_expiry < 0:
                    expiry_warning = f"""<tr>
                        <td colspan="2" style="background-color: #f8d7da; padding: 10px; border-left: 4px solid #dc3545;">
                            <strong>❌ Certificate Expired</strong><br>
                            <small>Certificate expired {abs(days_until_expiry)} days ago</small>
                        </td>
                    </tr>"""
                elif days_until_expiry < 30:
                    expiry_warning = f"""<tr>
                        <td colspan="2" style="background-color: #fff3cd; padding: 10px; border-left: 4px solid #ffc107;">
                            <strong>⚠️ Certificate Expiring Soon</strong><br>
                            <small>Certificate expires in {days_until_expiry} days</small>
                        </td>
                    </tr>"""
            
            # Build SAN domains info
            san_info = ""
            if san_domains:
                domain_matches = self.domain in san_domains or any(
                    self._domain_matches_wildcard(self.domain, san) for san in san_domains
                )
                if not domain_matches:
                    san_info = f"""<tr>
                        <td colspan="2" style="background-color: #fff3cd; padding: 10px; border-left: 4px solid #ffc107;">
                            <strong>⚠️ Domain Mismatch</strong><br>
                            <small>Domain '{self.domain}' not found in certificate SAN</small>
                        </td>
                    </tr>"""
            
            table = f"""<table>
                    <tr>
                        <td colspan="2">
                            <div class="progress-bar-container">
                                <div class="progress" style="width: {percentage}%;">{percentage}%</div>
                            </div>
                        </td>
                    </tr>
                    {trust_status}
                    {expiry_warning}
                    {san_info}
                    <tr>
                        <td>Subject</td>
                        <td>{subject_cn}</td>
                    </tr>
                    <tr>
                        <td>Issuer</td>
                        <td>{issuer_org}</td>
                    </tr>
                    <tr>
                        <td>Expires</td>
                        <td>{formatted_expire}</td>
                    </tr>
                    <tr>
                        <td>Renewed</td>
                        <td>{formatted_renew}</td>
                    </tr>
                    <tr>
                        <td>Serial Num</td>
                        <td>{serial_number}</td>
                    </tr>
                    <tr>
                        <td>Fingerprint</td>
                        <td>{formatted_fingerprint}</td>
                    </tr>"""
            
            if TLS_OK:
                table += """<tr>
                        <td><h3>Extended Key Usage</h3></td>
                        <td></td>
                    </tr>"""
                if TLS_Web_Server:
                    table += f"""<tr>
                        <td>{TLS_Web_Server}</td>
                        <td>✅</td>
                    </tr>"""
                if TLS_Web_Client:
                    table += f"""<tr>
                        <td>{TLS_Web_Client}</td>
                        <td>✅</td>
                    </tr>"""
            
            table += "</table>"
        
        rep_data.append(table)
        rep_data.append(html)
        return rep_data

    def _extract_name_attribute(self, name: x509.Name, oid) -> str:
        """Extract specific attribute from x509.Name"""
        try:
            attributes = name.get_attributes_for_oid(oid)
            if attributes:
                return attributes[0].value
        except Exception:
            pass
        return ""

    def _domain_matches_wildcard(self, domain: str, pattern: str) -> bool:
        """Check if domain matches wildcard pattern (e.g., *.example.com)"""
        if not pattern.startswith('*.'):
            return domain.lower() == pattern.lower()
        
        # Convert wildcard to regex
        pattern_regex = pattern.replace('.', r'\.').replace('*', r'[^.]+')
        return bool(re.match(f'^{pattern_regex}$', domain, re.IGNORECASE))

    async def __ssl_score(self, subject: str, issuer: str, expire: datetime, 
                         renew: datetime, serial_number: str, fingerprint: str,
                         TLS_Web_Server: str, TLS_Web_Client: str,
                         is_trusted: bool, is_self_signed: bool,
                         days_until_expiry: int, san_domains: List[str]) -> Tuple[int, str]:
        """
        Calculate SSL certificate score with enhanced validation
        Returns: (percentage_score, html_analysis)
        """
        score = 0
        max_score = 10  # Increased to include new checks
        issues = []
        suggestions = []

        # 1. Check Subject matches domain
        normalized_subject = subject.replace(" ", "").lower()
        normalized_domain_part = self.domain.split('.')[0].lower()

        if normalized_domain_part in normalized_subject:
            score += 1
        else:
            issues.append(Issue_Config.ISSUE_SSL_SUBJECT)
            suggestions.append(Issue_Config.SUGGESTION_SSL_SUBJECT)

        # 2. Check Certificate Trust (NEW - Most Important)
        if is_trusted and not is_self_signed:
            score += 2  # Worth 2 points as it's critical
        else:
            if is_self_signed:
                issues.append("The certificate is self-signed and is not trusted by public certificate authorities.")
                suggestions.append("Obtain a certificate from a trusted Certificate Authority (CA) like Let's Encrypt, DigiCert, or Sectigo.")
            else:
                issues.append(Issue_Config.ISSUE_SSL_ISSUER)
                suggestions.append(Issue_Config.SUGGESTION_SSL_ISSUER)

        # 3. Check expiration date
        now = datetime.now(timezone.utc)
        if expire.replace(tzinfo=timezone.utc) < now:
            issues.append(Issue_Config.ISSUE_SSL_EXPIRES)
            suggestions.append(Issue_Config.SUGGESTION_SSL_EXPIRES)
        else:
            score += 1

        # 4. Check renewal date (not too old)
        cert_age_days = (now - renew.replace(tzinfo=timezone.utc)).days
        if cert_age_days > 365:
            issues.append(Issue_Config.ISSUE_SSL_RENEWED)
            suggestions.append(Issue_Config.SUGGESTION_SSL_RENEWED)
        else:
            score += 1

        # 5. Check expiry warning (NEW)
        if days_until_expiry is not None and 0 < days_until_expiry < 30:
            issues.append(f"Certificate expires in {days_until_expiry} days")
            suggestions.append("Renew the certificate before it expires to avoid service disruption.")
        elif days_until_expiry is not None and days_until_expiry >= 30:
            score += 1

        # 6. Check Serial Number
        if serial_number and isinstance(serial_number, str) and len(serial_number) > 0:
            score += 1
        else:
            issues.append(Issue_Config.ISSUE_SSL_SERIAL_NUM)
            suggestions.append(Issue_Config.SUGGESTION_SSL_SERIAL_NUM)

        # 7. Check Fingerprint (SHA1 should be 40 hex chars)
        if len(fingerprint) == 40 and all(c in '0123456789ABCDEF' for c in fingerprint):
            score += 1
        else:
            issues.append(Issue_Config.ISSUE_SSL_FINGERPRINT)
            suggestions.append(Issue_Config.SUGGESTION_SSL_FINGERPRINT)

        # 8. Check Extended Key Usage - Server Auth
        if "TLS Web Server Authentication" in TLS_Web_Server:
            score += 1
        else:
            issues.append(Issue_Config.ISSUE_SSL_TLS_WEB_SERVER_AUTH)
            suggestions.append(Issue_Config.SUGGESTION_SSL_TLS_WEB_SERVER_AUTH)

        # 9. Check Extended Key Usage - Client Auth (optional, 0.5 weight)
        if "TLS Web Client Authentication" in TLS_Web_Client:
            score += 0.5

        # 10. Check SAN includes current domain (NEW)
        domain_in_san = False
        if san_domains:
            domain_in_san = self.domain in san_domains or any(
                self._domain_matches_wildcard(self.domain, san) for san in san_domains
            )
        
        if domain_in_san:
            score += 0.5
        else:
            issues.append(f"Domain '{self.domain}' not found in certificate Subject Alternative Names")
            suggestions.append("Ensure the certificate includes all domains that will use it in the SAN field.")

        # Calculate percentage (normalize score to 0-100)
        percentage_score = int((score / max_score) * 100)

        # Generate analysis HTML
        report_util = Report_Utility()
        html_tags = await report_util.analysis_table(
            Configuration.ICON_SSL_CERTIFICATE,
            Configuration.MODULE_SSL_CERTIFICATE,
            issues,
            suggestions,
            percentage_score
        )

        return percentage_score, html_tags

    async def __empty_output(self, error: str):
        """Generate empty output with error message"""
        report_util = Report_Utility()
        table = await report_util.Empty_Table(f"Error: {error}", 100)
        return [table, ""]