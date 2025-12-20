import asyncio
import dns.asyncresolver
from colorama import Fore, Style
from time import perf_counter
import traceback
from util.config_uti import Configuration
from util.issue_config import Issue_Config
from util.report_util import Report_Utility


class DNS_Records():
    Error_Title = None

    def __init__(self, url, domain):
        self.url=url
        self.domain = domain

    async def Get_DNS_Records(self):
        config = Configuration()
        self.Error_Title = config.DNS_RECORDS
        DNS_Records = []
        TXT_Records = []
        output = []
        try:
            # start_time = perf_counter()
            result = await self.__final_result(self.domain)
            # email_result = await self.__fetch_email_result(result[2], result[5])
            
            DNS_Records = await self.__html_DNS_table(result[0], result[1], result[2], result[3], result[4])
            TXT_Records = await self.__html_TXT_table(self.domain, result[5])
            # Email_Records = await self.__html_email_table(email_result)

            output = DNS_Records + TXT_Records #+ Email_Records
            # print(f"✅ {config.MODULE_DNS_RECORDS} has been successfully completed in {round(perf_counter() - start_time, 2)} seconds.")
            print(f"✅ {config.MODULE_DNS_RECORDS} has been successfully completed")
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
        record_types = ["A", "AAAA", "MX", "NS", "CNAME", "TXT"]
        tasks = [self.__get_record(domain, record_type) for record_type in record_types]
        results = await asyncio.gather(*tasks)
        return results

    async def __get_record(self, domain, record_type):
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = ["8.8.8.8", "1.1.1.1"]  # Google & Cloudflare DNS
            resolver.lifetime = 40  # Increase timeout

            answers = await resolver.resolve(domain, record_type)
            return f"{record_type} Records: " + ", ".join([rdata.to_text() for rdata in answers])

        except Exception as ex:
            # print(ex)
            return None

    # THIS IS FINAL RESULT FUNCTION TO GET RESULT OF ALL FUNCTIONS
    async def __fetch_email_result(self, mx_records, txt_records):
        # mx_records = dns.resolver.resolve(domain, "MX")
        # # Get TXT records
        # txt_records = dns.resolver.resolve(domain, "TXT")
        # Filter for only email related TXT records (SPF, DKIM, DMARC, and certain provider verifications)
        email_txt_records = [
                    record.strip('"')  # Remove quotes from TXT record
                    for record in txt_records
                    if record.startswith("v=spf1")
                    or record.startswith("v=DKIM1")
                    or record.startswith("v=DMARC1")
                    or record.startswith("protonmail-verification=")
                    or record.startswith("google-site-verification=")
                    or record.startswith("MS=")
                    or record.startswith("zoho-verification=")
                    or record.startswith("titan-verification=")
                    or "bluehost.com" in record
                ]

        # Identify specific mail services
        mail_services = []
        for record in email_txt_records:
            if record.startswith("protonmail-verification="):
                mail_services.append(
                    {"provider": "ProtonMail", "value": record.split("=")[1]}
                )
            elif record.startswith("google-site-verification="):
                mail_services.append(
                    {"provider": "Google Workspace", "value": record.split("=")[1]}
                )
            elif record.startswith("MS="):
                mail_services.append(
                    {"provider": "Microsoft 365", "value": record.split("=")[1]}
                )
            elif record.startswith("zoho-verification="):
                mail_services.append(
                    {"provider": "Zoho", "value": record.split("=")[1]}
                )
            elif record.startswith("titan-verification="):
                mail_services.append(
                    {"provider": "Titan", "value": record.split("=")[1]}
                )
            elif "bluehost.com" in record:
                mail_services.append({"provider": "BlueHost", "value": record})

        # Check MX records for Yahoo
        yahoo_mx = [record for record in mx_records if "yahoodns.net" in record]
        if yahoo_mx:
            mail_services.append({"provider": "Yahoo", "value": yahoo_mx[0]})

        # Check MX records for Mimecast
        mimecast_mx = [record for record in mx_records if "mimecast.com" in record]
        if mimecast_mx:
            mail_services.append({"provider": "Mimecast", "value": mimecast_mx[0]})

        return {
            "mxRecords": [record for record in mx_records],
            "txtRecords": email_txt_records,
            "mailServices": mail_services,
        }

    async def __html_DNS_table(self, A_record, AAAA_record, mx_record, NS_record, CNAME_record):
        rep_data = []
        html = ""

        percentage, html = await self.__dns_records_score(A_record, AAAA_record, mx_record, NS_record, CNAME_record)
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
                        <td>A RECORD</td>
                        <td>""" + str(A_record) + """</td>
                    </tr>
                    <tr>
                        <td>AAAA RECORD</td>
                        <td>""" + str(AAAA_record) + """</td>
                    </tr>
                    <tr>
                        <td>MX RECORD</td>
                        <td>""" + str(mx_record) + """</td>
                    </tr>
                    <tr>
                        <td>NS RECORD</td>
                        <td>""" + str(NS_record) + """</td>
                    </tr>
                    <tr>
                        <td>CNAME RECORD</td>
                        <td>""" + str(CNAME_record) + """</td>
                    </tr>
                </table>"""
        )
        rep_data.append(table)
        rep_data.append(html)
        return rep_data

    async def __html_TXT_table(self, domain, txt_record):
        rep_data = []
        html = ""

        if txt_record == "":
            report_util = Report_Utility()
            table = await report_util.Empty_Table()
        else:
            percentage, html = await self.__txt_records_score(txt_record)
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
                            <td>Domain Name</td>
                            <td>""" + str(domain) + """</td>
                        </tr>
                        <tr>
                            <td>TXT RECORD</td>
                            <td>""" + str(txt_record) + """</td>
                        </tr>
                    </table>"""
            )
        rep_data.append(table)
        rep_data.append(html)
        return rep_data

    async def __html_email_table(self, records):
        html = ""
        try:
            if not records:
                report_util = Report_Utility()
                table = await report_util.Empty_Table()
            else:
                percentage = 70  # Example percentage
                
                # Ensure all lists are properly initialized
                mx_records = records.get("mxRecords", []) or []
                mail_services = records.get("mailServices", []) or []
                txt_records = records.get("txtRecords", []) or []

                table = """<table>
                                <tr>
                                    <td colspan="2">
                                        <div class="progress-bar-container">
                                            <div class="progress" style="width:{0}%;">{0}%</div>
                                        </div>
                                    </td>
                                </tr>
                                <tr>
                                    <td colspan="2">
                                        <h3>Mail Security Checklist</h3>
                                    </td>
                                </tr>
                                <tr>
                                    <td>SPF:</td>
                                    <td>{1}</td>
                                </tr>
                                <tr>
                                    <td>DKIM:</td>
                                    <td>{2}</td>
                                </tr>
                                <tr>
                                    <td>DMARC:</td>
                                    <td>{3}</td>
                                </tr>
                                <tr>
                                    <td>BIMI:</td>
                                    <td>{4}</td>
                                </tr>
                                <tr>
                                    <td colspan="2">
                                        <h3>MX Records</h3>
                                    </td>
                                </tr>
                                <tr>
                                    <td colspan="2">
                                        <ul>
                                            {5}
                                        </ul>
                                    </td>
                                </tr>
                                <tr>
                                    <td colspan="2">
                                        <h3>External Mail Services</h3>
                                    </td>
                                </tr>
                                <tr>
                                    <td colspan="2">
                                        <ul>
                                            {6}
                                        </ul>
                                    </td>
                                </tr>
                                <tr>
                                    <td colspan="2">
                                        <h3>Mail-related TXT Records</h3>
                                    </td>
                                </tr>
                                <tr>
                                    <td colspan="2">
                                        <ul>
                                            {7}
                                        </ul>
                                    </td>
                                </tr>
                            </table>
                """.format(
                    percentage,
                    "✅" if any("v=spf1" in record for record in txt_records) else "❌",
                    "✅" if any("v=DKIM1" in record for record in txt_records) else "❌",
                    "✅" if any("v=DMARC1" in record for record in txt_records) else "❌",
                    "❌",  # BIMI is assumed to be not enabled
                    "".join(
                        f"<li>{mx.split()[1]} Priority: {mx.split()[0]}</li>"
                        for mx in mx_records
                    ),
                    "".join(
                        f"<li>{service['provider']}: {service['value']}</li>"
                        for service in mail_services
                    ),
                    "".join(f"<li>{record}</li>" for record in txt_records),
                )
            return table
        except Exception as ex:
            print("Error:", ex)


        
    async def __dns_records_score(self, A_record, AAAA_record, mx_record, NS_record, CNAME_record):
        score = 0
        max_score = 5
        issues = []
        suggestions = []

        if not A_record:  # A Record
            issues.append(Issue_Config.ISSUE_DNS_RECORDS_A)
            suggestions.append(Issue_Config.SUGGESTION_DNS_RECORDS_A)
        else:
            score += 1

        if not AAAA_record:  # AAAA Record
            issues.append(Issue_Config.ISSUE_DNS_RECORDS_AAAA)
            suggestions.append(Issue_Config.SUGGESTION_DNS_RECORDS_AAAA)
        else:
            score += 1

        if not mx_record:  # MX Record
            issues.append(Issue_Config.ISSUE_DNS_RECORDS_MX)
            suggestions.append(Issue_Config.SUGGESTION_DNS_RECORDS_MX)
        else:
            score += 1

        if not NS_record:  # NS Record
            issues.append(Issue_Config.ISSUE_DNS_RECORDS_NS)
            suggestions.append(Issue_Config.SUGGESTION_DNS_RECORDS_NS)
        else:
            score += 1

        if not CNAME_record:  # CNAME Record
            issues.append(Issue_Config.ISSUE_DNS_RECORDS_CNAME)
            suggestions.append(Issue_Config.SUGGESTION_DNS_RECORDS_CNAME)
        else:
            score += 1

        percentage_score = (score / max_score) * 100
        report_util = Report_Utility()
        html_tags = await report_util.analysis_table(Configuration.ICON_DNS_RECORDS, Configuration.MODULE_DNS_RECORDS, issues, suggestions, int(percentage_score))

        return int(percentage_score), html_tags

    async def __txt_records_score(self, txt_record):
        score = 0
        max_score = 1
        issues = []
        suggestions = []

        if not txt_record:  # TXT Record
            issues.append(Issue_Config.ISSUE_DNS_RECORDS_TXT)
            suggestions.append(Issue_Config.SUGGESTION_DNS_RECORDS_TXT)
        else:
            score += 1

        percentage_score = (score / max_score) * 100
        report_util = Report_Utility()
        html_tags = await report_util.analysis_table(Configuration.ICON_TXT_RECORDS, Configuration.MODULE_TXT_RECORDS, issues, suggestions, int(percentage_score))

        return int(percentage_score), html_tags
    
    async def __email_records_score(self, mx_record, txt_record):
        score = 0
        max_score = 2
        issues = []
        suggestions = []

        if not mx_record:  # MX Record
            issues.append(Issue_Config.ISSUE_DNS_RECORDS_MX)
            suggestions.append(Issue_Config.SUGGESTION_DNS_RECORDS_MX)
        else:
            score += 1

        if not txt_record:  # TXT Record
            issues.append(Issue_Config.ISSUE_DNS_RECORDS_NS)
            suggestions.append(Issue_Config.SUGGESTION_DNS_RECORDS_NS)
        else:
            score += 1

        percentage_score = (score / max_score) * 100
        report_util = Report_Utility()
        html_tags = await report_util.analysis_table(Configuration.ICON_EMAIL_CONFIGURATION, Configuration.MODULE_EMAIL_CONFIGURATION, issues, suggestions, int(percentage_score))

        return int(percentage_score), html_tags
    
    async def __empty_output(self, error):
        report_util = Report_Utility()
        table = await report_util.Empty_Table(f"Error : {error}", 100)
        
        return [table, "", table, ""]
