import ssl
import socket
from colorama import Fore, Style
from OpenSSL import crypto
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
import hashlib
from datetime import datetime
from time import perf_counter
import traceback
from util.config_uti import Configuration
from util.issue_config import Issue_Config
from util.report_util import Report_Utility

class SSL_Certificate():
    Error_Title = None

    def __init__(self) -> None:
        pass    

    def __init__(self, url, domain):
        self.url = url
        self.domain = domain

    # Function to fetch and extract certificate details
    async def Get_SSL_Certificate(self, port: int = 443):
        config = Configuration()
        self.Error_Title = config.SSL_CERTIFICATE
        output = []

        try:
            # start_time = perf_counter()
            connection = ssl.create_default_context().wrap_socket(
                socket.socket(socket.AF_INET), server_hostname=self.domain
            )
            # connection = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname = self.domain)
            connection.connect((self.domain, port))

            # Get the certificate in binary form
            cert = connection.getpeercert(binary_form=True)
            # Load the certificate using the cryptography library
            cert_obj = x509.load_der_x509_certificate(cert, default_backend())

            # Extract the details from the certificate
            cert_details = {
                "Subject": cert_obj.subject,
                "Issuer": cert_obj.issuer,
                "Expires": cert_obj.not_valid_after_utc,
                "Renewed": cert_obj.not_valid_before_utc,
                "Serial Number": cert_obj.serial_number,
            }

            # Compute the Fingerprint (SHA-256)
            sha1_fingerprint = hashlib.sha1(cert).hexdigest().upper()
            cert_details["Fingerprint"] = sha1_fingerprint

            # Extract Extended Key Usage (EKU) for server and client authentication
            ext_key_usage = []
            for eku in cert_obj.extensions:
                if eku.oid == x509.oid.ExtensionOID.EXTENDED_KEY_USAGE:
                    extended_usage = eku.value
                    for purpose in extended_usage:
                        if purpose == x509.oid.ExtendedKeyUsageOID.SERVER_AUTH:
                            ext_key_usage.append("TLS Web Server Authentication")
                        if purpose == x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH:
                            ext_key_usage.append("TLS Web Client Authentication")

            cert_details["Extended Key Usage"] = ext_key_usage
            output = await self.__html_table(cert_details)
            # print(f"✅ {config.MODULE_SSL_CERTIFICATE} has been successfully completed in {round(perf_counter() - start_time, 2)} seconds.")
            print(f"✅ {config.MODULE_SSL_CERTIFICATE} has been successfully completed.")
            return output
        except Exception as ex:
            error_type, error_message, tb = ex.__class__.__name__, str(ex), traceback.extract_tb(ex.__traceback__)
            error_details = tb[-1]  # Get the last traceback entry (most recent call)
            file_name = error_details.filename
            method_name = error_details.name
            line_number = error_details.lineno

            error_msg = f"❌ {self.Error_Title} => ERROR in method '{method_name}' at line {line_number} : {error_type}: {error_message}"
            print(error_msg)
            output = await self.__empty_output(error_message)
            return output

        finally:
            connection.close()

    async def __html_table(self, cert_details):
        rep_data = []
        html = ""
        if not cert_details:
            report_util = Report_Utility()
            table = await report_util.Empty_Table()
        else:
            subject = cert_details["Subject"]
            attributes = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if attributes:
                subject = attributes[0].value
            else:
                subject = ""
            
            issuer = cert_details["Issuer"]
            attributes = issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
            if attributes:
                issuer = attributes[0].value
            else:
                issuer = ""

            expires_date = cert_details["Expires"]
            formatted_expire = expires_date.strftime('%d %B %Y').lstrip('0').replace(" 0", " ")
            renewed_date = cert_details["Renewed"]
            formatted_renew = renewed_date.strftime('%d %B %Y').lstrip('0').replace(" 0", " ")
            serial_number = hex(cert_details["Serial Number"])[2:].upper()
            fingerprint = cert_details["Fingerprint"]
            # Format the fingerprint with colons
            formatted_fingerprint = ":".join(fingerprint[i : i + 2] for i in range(0, len(fingerprint), 2))
            ext_key_usage = cert_details["Extended Key Usage"]

            # Rate Extended Key Usage (100% if both server and client auth are found)
            if ("TLS Web Server Authentication" in cert_details["Extended Key Usage"]
                and "TLS Web Client Authentication" in cert_details["Extended Key Usage"]):
                if "TLS Web Server Authentication" in cert_details["Extended Key Usage"]:
                    TLS_Web_Server = "TLS Web Server Authentication"

                if "TLS Web Client Authentication" in cert_details["Extended Key Usage"]:
                    TLS_Web_Client = "TLS Web Client Authentication"
                TLS_OK = True
            else:
                TLS_Web_Server = ""
                TLS_Web_Client = ""
                TLS_OK = False

            percentage, html = await self.__ssl_score(subject, issuer, expires_date, renewed_date, serial_number, fingerprint, TLS_Web_Server, TLS_Web_Client)
            table = (
                """<table>
                        <tr>
                            <td colspan="2">
                                <div class="progress-bar-container">
                                    <div class="progress" style="width: """+ str(percentage) +"""%;">"""+ str(percentage) +"""%</div>
                                </div>
                            </td>
                        </tr>
                        <tr>
                            <td>Subject</td>
                            <td>""" + str(subject) + """</td>
                        </tr>
                        <tr>
                            <td>Issuer</td>
                            <td>""" + str(issuer) + """</td>
                        </tr>
                        <tr>
                            <td>Expires</td>
                            <td>""" + str(formatted_expire) + """</td>
                        </tr>
                        <tr>
                            <td>Renewed</td>
                            <td>""" + str(formatted_renew) + """</td>
                        </tr>
                        <tr>
                            <td>Serial Num</td>
                            <td>""" + str(serial_number) + """</td>
                        </tr>
                        <tr>
                            <td>Fingerprint</td>
                            <td>""" + str(formatted_fingerprint) + """</td>
                        </tr>""" + ("""
                        <tr>
                            <td> <h3>Extended Key Usage</h3> </td>
                            <td></td>
                        </tr> 
                        <tr>
                            <td>""" + str(TLS_Web_Server) + """</td>
                            <td></td>
                        </tr>
                        <tr>
                            <td>""" + str(TLS_Web_Client) + """</td>
                            <td></td>
                        </tr>
                        """ if TLS_OK else "")  # Add this block only if TLS_OK is True
                + """
                </table>"""
            )
        rep_data.append(table)
        rep_data.append(html)
        return rep_data

    async def __load_trusted_organizations(self, port=443):
        try:
            context = ssl.create_default_context()

            with socket.create_connection((self.domain, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname = self.domain) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)

            cert = x509.load_der_x509_certificate(cert_bin, default_backend())

            # Self-signed check
            return cert.issuer == cert.subject

        except ssl.SSLError:
            # TLS failed, cannot determine self-signed reliably
            return False

        except Exception:
            return False

    # async def __is_issuer_organization_trusted(self, issuer_organization):
    #     trusted_organizations = await self.__load_trusted_organizations()
    #     return issuer_organization in trusted_organizations

    async def __ssl_score(self, subject, issuer, expire, renew, serial_number, fingerprint, TLS_Web_Server, TLS_Web_Client):
        score = 0
        max_score = 8  
        issues = []
        suggestions = []

        normalized_subject = subject.replace(" ", "").lower()
        # Extract domain part (before '.in') and normalize
        normalized_domain_part = self.domain.split('.')[0].lower()

        # Check if the domain part is contained in the subject
        if normalized_domain_part in normalized_subject:
            score += 1
        else:
            # if subject != "example.com":
            issues.append(Issue_Config.ISSUE_SSL_SUBJECT)
            suggestions.append(Issue_Config.SUGGESTION_SSL_SUBJECT)

        # Check Issuer validity
        # trusted_issuers = await self.__is_issuer_organization_trusted(issuer)  # Example trusted CAs
        trusted_issuers = await self.__load_trusted_organizations()
        if trusted_issuers:
            score += 1
        else:
            issues.append(Issue_Config.ISSUE_SSL_ISSUER)
            suggestions.append(Issue_Config.SUGGESTION_SSL_ISSUER)

        # Check expiration date
        if expire.replace(tzinfo=None) < datetime.now().replace(tzinfo=None):
            issues.append(Issue_Config.ISSUE_SSL_EXPIRES)
            suggestions.append(Issue_Config.SUGGESTION_SSL_EXPIRES)
        else:
            score += 1

        # Check renewal date
        if (datetime.now().replace(tzinfo=None) - renew.replace(tzinfo=None)).days > 365:
            issues.append(Issue_Config.ISSUE_SSL_RENEWED)
            suggestions.append(Issue_Config.SUGGESTION_SSL_RENEWED)
        else:
            score += 1

        # Check Serial Number (ensure it's alphanumeric and not empty)
        if not serial_number or not isinstance(serial_number, str) or not serial_number.isalnum():
            # if not serial_number or not serial_number.isalnum():
            issues.append(Issue_Config.ISSUE_SSL_SERIAL_NUM)
            suggestions.append(Issue_Config.SUGGESTION_SSL_SERIAL_NUM)
        else:
            score += 1

        # Check Fingerprint (ensure it's in the expected format, e.g., 'SHA1')
        if len(fingerprint) == 40 and all(c in fingerprint for c in fingerprint):
            score += 1
        else:
            issues.append(Issue_Config.ISSUE_SSL_FINGERPRINT)
            suggestions.append(Issue_Config.SUGGESTION_SSL_FINGERPRINT)

        # Check Extended Key Usage
        if "TLS Web Server Authentication" not in TLS_Web_Server:
            issues.append(Issue_Config.ISSUE_SSL_TLS_WEB_SERVER_AUTH)
            suggestions.append(Issue_Config.SUGGESTION_SSL_TLS_WEB_SERVER_AUTH)
        else:
            score += 1

        # Check Extended Key Usage
        if "TLS Web Client Authentication" not in TLS_Web_Client:
            issues.append(Issue_Config.ISSUE_SSL_TLS_WEB_CLIENT_AUTH)
            suggestions.append(Issue_Config.SUGGESTION_SSL_TLS_WEB_CLIENT_AUTH)
        else:
            score += 1

        percentage_score = (score / max_score) * 100

        report_util = Report_Utility()
        html_tags = await report_util.analysis_table(Configuration.ICON_SSL_CERTIFICATE, Configuration.MODULE_SSL_CERTIFICATE, issues, suggestions, int(percentage_score))

        return int(percentage_score), html_tags

    async def __empty_output(self, error):
        report_util = Report_Utility()
        table = await report_util.Empty_Table(f"Error: {error}", 100)
        
        return [table, ""]