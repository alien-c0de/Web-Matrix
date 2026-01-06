import dns.asyncresolver
from colorama import Fore, Style
from time import perf_counter
import traceback
from util.config_uti import Configuration
from util.report_util import Report_Utility
from util.issue_config import Issue_Config

class Mail_Records:

    Error_Title = None

    def __init__(self, url, domain):
        self.url = url
        self.domain = domain
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.nameservers = ["8.8.8.8", "1.1.1.1"]  # Google & Cloudflare DNS
        self.resolver.lifetime = 40  # Increase timeout

    async def Get_Mail_Records(self):
        config = Configuration()
        self.Error_Title = config.MAIL_CONFIGURATION
        output=""
        try:
            result = await self.__fetch_dns_records(self.domain)
            output = await self.__html_table(result)
            print(f"✅ {config.MODULE_EMAIL_CONFIGURATION} has been successfully completed.")
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

    async def __fetch_dns_records(self, domain):
        """Fetches MX, TXT, and other email security records asynchronously."""
        try:
            mx_records = await self.resolver.resolve(domain, 'MX')
            txt_records = await self.resolver.resolve(domain, 'TXT')
        except Exception as e:
            print(f"DNS Lookup Error for MX/TXT: {e}")
            mx_records = []
            txt_records = []

        mx_list = [(mx.exchange.to_text(), mx.preference) for mx in mx_records]
        txt_list = [txt.to_text().strip('"') for txt in txt_records]

        # Check for SPF in main domain TXT records
        spf_record = None
        for txt in txt_list:
            if txt.startswith('v=spf1'):
                spf_record = txt
                break

        # Check for DMARC record at _dmarc subdomain
        dmarc_record = None
        try:
            dmarc_records = await self.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            for record in dmarc_records:
                record_text = record.to_text().strip('"')
                if record_text.startswith('v=DMARC1'):
                    dmarc_record = record_text
                    break
        except dns.resolver.NXDOMAIN:
            pass  # Domain doesn't have DMARC - this is normal
        except dns.resolver.NoAnswer:
            pass  # No TXT records at _dmarc subdomain
        except Exception:
            pass  # Other DNS errors - silently continue

        # Check for DKIM - Try common selectors
        dkim_record = None
        common_selectors = ['default', 'google', 'k1', 's1', 's2', 'selector1', 'selector2', 'dkim', 'mail']
        
        for selector in common_selectors:
            try:
                dkim_records = await self.resolver.resolve(f'{selector}._domainkey.{domain}', 'TXT')
                for record in dkim_records:
                    record_text = record.to_text().strip('"')
                    if 'v=DKIM1' in record_text or 'p=' in record_text:
                        dkim_record = f"{selector}._domainkey.{domain}: {record_text}"
                        break
                if dkim_record:
                    break
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue  # Try next selector
            except Exception:
                continue  # Try next selector

        # Check for BIMI record at default._bimi subdomain
        bimi_record = None
        try:
            bimi_records = await self.resolver.resolve(f'default._bimi.{domain}', 'TXT')
            for record in bimi_records:
                record_text = record.to_text().strip('"')
                if record_text.startswith('v=BIMI1'):
                    bimi_record = record_text
                    break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass  # Domain doesn't have BIMI - this is normal (most don't)
        except Exception:
            pass  # Other DNS errors - silently continue

        # Detecting External Mail Services
        external_services = []
        for mx in mx_list:
            mx_lower = mx[0].lower()
            if "google" in mx_lower or "gmail" in mx_lower:
                external_services.append("Google Workspace")
            elif "outlook" in mx_lower or "office365" in mx_lower or "microsoft" in mx_lower:
                external_services.append("Microsoft 365")
            elif "zoho" in mx_lower:
                external_services.append("Zoho Mail")
            elif "protonmail" in mx_lower:
                external_services.append("ProtonMail")
            elif "mail.protection.outlook.com" in mx_lower:
                external_services.append("Microsoft 365")

        return {
            "mx_records": mx_list,
            "txt_records": txt_list,
            "external_services": list(set(external_services)),  # Remove duplicates
            "spf_record": spf_record,
            "dmarc_record": dmarc_record,
            "dkim_record": dkim_record,
            "bimi_record": bimi_record
        }

    async def __html_table(self, security_info):
        """Generates an HTML table with mail security details, MX records, and TXT records."""
        rep_data = []
        html = ""

        if not security_info:
            report_util = Report_Utility()
            table = await report_util.Empty_Table()
        else:
            
            mx_records = security_info['mx_records']
            external_services = security_info['external_services']
            txt_records = security_info['txt_records']
            
            # Get security record status
            spf = "Enabled" if security_info['spf_record'] else "Not Enabled"
            dkim = "Enabled" if security_info['dkim_record'] else "Not Enabled"
            dmarc = "Enabled" if security_info['dmarc_record'] else "Not Enabled"
            bimi = "Enabled" if security_info['bimi_record'] else "Not Enabled"
            
            percentage, html = await self.__security_score(spf, dkim, dmarc, bimi)
            
            table = f"""<table>
                            <tr>
                                <td colspan="2">
                                    <div class="progress-bar-container">
                                        <div class="progress" style="width: {percentage}%;">{percentage}%</div>
                                    </div>
                                </td>
                            </tr>
                            <tr>
                                <td colspan="2" style="text-align: left;"><h3>Mail Security Checklist</h3></td>
                            </tr>
                            <tr>
                                <td style="text-align: left;">SPF</td>
                                <td>{"✅ Enabled" if spf == "Enabled" else "❌ Not Enabled"}</td>
                            </tr>
                            <tr>
                                <td style="text-align: left;">DKIM</td>
                                <td>{"✅ Enabled" if dkim  == "Enabled" else "❌ Not Enabled"}</td>
                            </tr>
                            <tr>
                                <td style="text-align: left;">DMARC</td>
                                <td>{"✅ Enabled" if dmarc == "Enabled" else "❌ Not Enabled"}</td>
                            </tr>
                            <tr>
                                <td style="text-align: left;">BIMI</td>
                                <td>{"✅ Enabled" if bimi == "Enabled" else "❌ Not Enabled"}</td>
                            </tr>"""

            # Show actual record values if enabled
            if spf == "Enabled":
                table += f"""<tr>
                                <td colspan="2" style="text-align: left; padding-left: 20px;">
                                    <small style="color: #a8aab7;">{security_info['spf_record'][:100]}...</small>
                                </td>
                            </tr>"""
            
            if dkim == "Enabled":
                table += f"""<tr>
                                <td colspan="2" style="text-align: left; padding-left: 20px;">
                                    <small style="color: #a8aab7;">{security_info['dkim_record'][:100]}...</small>
                                </td>
                            </tr>"""
            
            if dmarc == "Enabled":
                table += f"""<tr>
                                <td colspan="2" style="text-align: left; padding-left: 20px;">
                                    <small style="color: #a8aab7;">{security_info['dmarc_record'][:100]}...</small>
                                </td>
                            </tr>"""
            
            if bimi == "Enabled":
                table += f"""<tr>
                                <td colspan="2" style="text-align: left; padding-left: 20px;">
                                    <small style="color: #a8aab7;">{security_info['bimi_record'][:100]}...</small>
                                </td>
                            </tr>"""

            table += """<tr><td colspan="2" style="text-align: left;"><h3>MX Records</h3></td></tr>"""
            
            # Add MX Records
            if mx_records:
                for mx in mx_records:
                    table += f"""<tr><td style="text-align: left;">{mx[0]}</td><td>Priority: {mx[1]}</td></tr>"""
            else:
                table += """<tr><td colspan="2" style="text-align: left;">No MX records found.</td></tr>"""

            # Add External Mail Services
            table += """<tr><td colspan="2" style="text-align: left;"><h3>External Mail Services</h3></td></tr>"""
            if external_services:
                for service in external_services:
                    table += f"""<tr><td style="text-align: left;">{service}</td><td>Detected</td></tr>"""
            else:
                table += """<tr><td colspan="2" style="text-align: left;">No external mail services detected.</td></tr>"""

            # Add Mail-related TXT Records
            table += """<tr><td colspan="2" style="text-align: left;"><h3>Other TXT Records</h3></td></tr>"""
            if txt_records:
                # Filter out SPF record since we already showed it
                other_txt = [txt for txt in txt_records if not txt.startswith('v=spf1')]
                if other_txt:
                    for txt in other_txt:
                        # Truncate long records
                        display_txt = txt[:150] + "..." if len(txt) > 150 else txt
                        table += f"""<tr><td colspan="2" style="text-align: left;"><small>{display_txt}</small></td></tr>"""
                else:
                    table += """<tr><td colspan="2" style="text-align: left;">No additional TXT records found.</td></tr>"""
            else:
                table += """<tr><td colspan="2" style="text-align: left;">No TXT records found.</td></tr>"""

            table += "</table>"

        rep_data.append(table)
        rep_data.append(html)
        return rep_data

    async def __security_score(self, spf, dkim, dmarc, bimi):
        """Calculates security score and generates issue/suggestion report."""
        score = 0
        max_score = 4  # SPF, DKIM, DMARC, BIMI
        issues = []
        suggestions = []

        # Security checks
        if spf == "Enabled": 
            score += 1
        else: 
            issues.append(Issue_Config.ISSUE_EMAIL_CONFIG_SPF)
            suggestions.append(Issue_Config.SUGGESTION_EMAIL_CONFIG_SPF)

        if dkim == "Enabled": 
            score += 1
        else: 
            issues.append(Issue_Config.ISSUE_EMAIL_CONFIG_DKIM)
            suggestions.append(Issue_Config.SUGGESTION_EMAIL_CONFIG_DKIM)

        if dmarc == "Enabled": 
            score += 1
        else: 
            issues.append(Issue_Config.ISSUE_EMAIL_CONFIG_DMARC)
            suggestions.append(Issue_Config.SUGGESTION_EMAIL_CONFIG_DMARC)

        if bimi == "Enabled": 
            score += 1
        else: 
            issues.append(Issue_Config.ISSUE_EMAIL_CONFIG_BIMI)
            suggestions.append(Issue_Config.SUGGESTION_EMAIL_CONFIG_BIMI)

        percentage_score = (score / max_score) * 100

        # Generate analysis report
        report_util = Report_Utility()
        html_tags = await report_util.analysis_table(Configuration.ICON_EMAIL_CONFIGURATION, Configuration.MODULE_EMAIL_CONFIGURATION, issues, suggestions, int(percentage_score))

        return int(percentage_score), html_tags
    
    async def __empty_output(self, error):
        report_util = Report_Utility()
        table = await report_util.Empty_Table(f"Error: {error}", 100)
        
        return [table, ""]