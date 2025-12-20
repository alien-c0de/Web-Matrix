import asyncio
from datetime import datetime
import ssl
import socket
from colorama import Fore, Style
from time import perf_counter
import traceback
from util.config_uti import Configuration
from util.report_util import Report_Utility
from util.issue_config import Issue_Config

class TLS_Cipher_Suit:
    Error_Title = None
    
    def __init__(self,url, domain):
        self.url=url
        self.domain = domain

    async def Get_TLS_Cipher_Suit(self):
        config = Configuration()
        self.Error_Title = config.TLS_CIPHER_SUIT
        output = []
        try:
            # start_time = perf_counter()
            res = await self.__final_result(self.domain)
            output = await self.__html_table(res)
            # print(f"✅ {config.MODULE_TLS_CIPHER_SUITES} has been successfully completed in {round(perf_counter() - start_time, 2)} seconds.")
            print(f"✅ {config.MODULE_TLS_CIPHER_SUITES} has been successfully completed.")
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

    async def __final_result(self, domain):
        """ Retrieves TLS Certificate details using SSL """
        default = {
            'Domain Name': domain, 'Issuing Organization': None, 'Issue Date': None,
            'Expire Date': None, 'Serial Number': None, 'Protocol Version': None,
            'Cipher Suite': None, 'Public key length': None
        }

        return await asyncio.to_thread(self.__fetch_tls_details, domain, default)

    def __fetch_tls_details(self, domain, default):
        """ Runs TLS operations in a separate thread to avoid blocking """
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as s:
                    cert = s.getpeercert()
                    return {
                        'Domain Name': domain,
                        'Issuing Organization': cert.get('issuer', [['', 'Unknown']])[1][0][1],
                        'Issue Date': cert.get('notBefore', 'Unknown'),
                        'Expire Date': cert.get('notAfter', 'Unknown'),
                        'Serial Number': cert.get('serialNumber', 'Unknown'),
                        'Protocol Version': s.version(),
                        'Cipher Suite': s.cipher()[0],
                        'Public key length': s.cipher()[2]
                    }
        
        except (socket.timeout, ssl.SSLError, socket.gaierror) as e:
            print(f"TLS Error: {e}")
        return default
    
    async def __html_table(self, data):
        rep_data = []
        html = ""
        if not data:
            report_util = Report_Utility()
            table = await report_util.Empty_Table()
        else:
            domain = str(data['Domain Name'])
            issue_org = str(data['Issuing Organization'])
            issue_date = str(data['Issue Date'])
            expire_date = str(data['Expire Date'])
            sr_no = str(data['Serial Number'])
            protocol = str(data['Protocol Version'])
            cipher = str(data['Cipher Suite'])
            public_key = str(data['Public key length'])

            percentage, html = await self.__tls_score(data)

            table = (
                """<table>
                        <tr>
                            <td colspan="2">
                                <div class="progress-bar-container">
                                    <div class="progress" style="width:""" + str(percentage) + """%;">""" + str(percentage) + """%</div>
                                </div>
                            </td>
                        </tr>
                        <tr>
                            <td>Domain Name</td>
                            <td>""" + domain + """</td>
                        </tr>
                        <tr>
                            <td>Issuing Organization</td>
                            <td>""" + issue_org + """</td>
                        </tr>
                        <tr>
                            <td>Issue Date</td>
                            <td>""" + issue_date + """</td>
                        </tr>
                        <tr>
                            <td>Expire Date</td>
                            <td>""" + expire_date + """</td>
                        </tr>
                        <tr>
                            <td>Serial Number</td>
                            <td>""" + sr_no + """</td>
                        </tr>
                        <tr>
                            <td>Protocol Version</td>
                            <td >""" + protocol + """</td>
                        </tr>
                        <tr>
                            <td>Cipher Suite</td>
                            <td >""" + cipher + """</td>
                        </tr>
                        <tr>
                            <td>Public key length</td>
                            <td>""" + public_key + """</td>
                        </tr>
                </table>"""
            )
        rep_data.append(table)
        rep_data.append(html)
        return rep_data

    async def __tls_score(self, tls_details):
        """ Calculate vulnerability score based on TLS Cipher Suite details. """
        score = 0
        max_score = 6  # Maximum score based on different parameters
        issues = []
        suggestions = []
        html_tags = ""

        # Check Protocol Version
        if tls_details["Protocol Version"] == "TLSv1.3":
            score += 1
        else:
            issues.append(Issue_Config.ISSUE_TLS_CIPHER_SUIT_PROTOCOL)
            suggestions.append(Issue_Config.SUGGESTION_TLS_CIPHER_SUIT_PROTOCOL)

        # Check Cipher Suite
        secure_ciphers = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]
        if tls_details["Cipher Suite"] in secure_ciphers:
            score += 1
        else:
            issues.append(f"{Issue_Config.ISSUE_TLS_CIPHER_SUIT_SUITE} {tls_details['Cipher Suite']}")
            suggestions.append(Issue_Config.SUGGESTION_TLS_CIPHER_SUIT_SUITE)

        # Check Public Key Length
        if tls_details["Public key length"] >= 256:
            score += 1
        else:
            issues.append(f"{Issue_Config.ISSUE_TLS_CIPHER_SUIT_KEY} ({tls_details['Public key length']} bits).")
            suggestions.append(Issue_Config.SUGGESTION_TLS_CIPHER_SUIT_KEY)

        # Check Certificate Expiry
        expiry_date = datetime.strptime(tls_details["Expire Date"], "%b %d %H:%M:%S %Y GMT")
        days_left = (expiry_date - datetime.utcnow()).days

        if days_left > 180:
            score += 1
        else:
            issues.append(Issue_Config.ISSUE_TLS_CIPHER_SUIT_EXPIRY)
            suggestions.append(Issue_Config.SUGGESTION_TLS_CIPHER_SUIT_EXPIRY)

        # Check Issuing Organization (Trusted CA)
        trusted_CAs = ["Amazon", "DigiCert", "GlobalSign", "Let's Encrypt"]

        # Convert to lowercase for case-insensitive matching
        issuer_name = tls_details["Issuing Organization"].lower()
        # Check if any trusted CA name is a substring of the issuer
        if any(trusted_ca.lower() in issuer_name for trusted_ca in trusted_CAs):
            score += 1
        else:
            issues.append(Issue_Config.ISSUE_TLS_CIPHER_SUIT_TRUSTED)
            suggestions.append(Issue_Config.SUGGESTION_TLS_CIPHER_SUIT_TRUSTED)

        # Check Serial Number (Presence Check)
        if tls_details["Serial Number"]:
            score += 1
        else:
            issues.append(Issue_Config.ISSUE_TLS_CIPHER_SUIT_SERIAL_NO)
            suggestions.append(Issue_Config.SUGGESTION_TLS_CIPHER_SUIT_SERIAL_NO)

        # Calculate Percentage Score
        percentage_score = (score / max_score) * 100
        report_util = Report_Utility()
        html_tags = await report_util.analysis_table(Configuration.ICON_TLS_CIPHER_SUITES, Configuration.MODULE_TLS_CIPHER_SUITES, issues, suggestions, int(percentage_score))

        return int(percentage_score), html_tags
    
    async def __empty_output(self, error):
        report_util = Report_Utility()
        table = await report_util.Empty_Table(f"Error: {error}", 100)
        
        return [table, ""]
