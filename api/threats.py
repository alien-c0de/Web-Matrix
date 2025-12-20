import aiohttp
import asyncio
import base64
from colorama import Fore, Style
from time import perf_counter
import traceback
from util.config_uti import Configuration
from util.report_util import Report_Utility
from util.issue_config import Issue_Config

class Threats:
    Error_Title = None

    def __init__(self, ip_address, url, domain):
        self.ip_address = ip_address
        self.url = url
        self.domain = domain

    async def Get_Threats(self):
        config = Configuration()
        self.Error_Title = config.THREATS
        tasks = []
        decodedResponse = []
        output = []

        headers = {"Accept": "application/json", "x-apikey": config.VIRUS_TOTAL_API_KEY}
        try:
            # start_time = perf_counter()
            encoded_url = await self.__url_to_base64(self.url)
            async with aiohttp.ClientSession(headers = headers) as session:
                url = config.VIRUS_TOTAL_ENDPOINT_URL + encoded_url

                tasks.append(asyncio.create_task(session.request(method="GET", url=url)))

                responses = await asyncio.gather(*tasks)
                for response in responses:
                    decodedResponse.append(await response.json())

            output = await self.__html_table(decodedResponse)
            # print(f"✅ {config.MODULE_THREATS} has been successfully completed in {round(perf_counter() - start_time, 2)} seconds.")
            print(f"✅ {config.MODULE_THREATS} has been successfully completed.")
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

    async def __url_to_base64(self, url):
        """Encode URL to a format suitable for VirusTotal API."""
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    async def __html_table(self, decodedResponse):
        rep_data = []
        html = ""

        if decodedResponse is None:
            report_util = Report_Utility()
            table = await report_util.Empty_Table()
        else:
            if not 'error' in decodedResponse[0]:
                phishing = int(decodedResponse[0]["data"]["attributes"]["last_analysis_stats"]["suspicious"])
                malware = int(decodedResponse[0]["data"]["attributes"]["last_analysis_stats"]["malicious"])

                percentage, html = await self.__threat_score(phishing, malware)
                table = f"""<table>
                            <tr>
                                <td colspan="2">
                                    <div class="progress-bar-container">
                                        <div class="progress" style="width: {str(percentage)}%;">{str(percentage)}%</div>
                                    </div>
                                </td>
                            </tr>
                            <tr>
                                <td>Phishing Status</td>
                                <td>{'✅ No Phishing Found' if phishing == 0 else '❌ Phishing'}</td>
                            </tr>
                            <tr>
                                <td>Malware Status</td>
                                <td>{'✅ No Malwares Found' if malware == 0 else '❌ Malware Found'}</td>
                            </tr>
                        </table>"""
        rep_data.append(table)
        rep_data.append(html)
        return rep_data

    async def __threat_score(self, phishing_status, malware_status):
        score = 0
        max_score = 2  # 2 parameters to evaluate
        issues = []
        suggestions = []
        html_tags = ""

        # Check Phishing Status
        if phishing_status == 0:
            score += 1  # No deduction for no phishing found
        else:
            issues.append(Issue_Config.ISSUE_THREATS_PHISHING)
            suggestions.append(Issue_Config.SUGGESTION_THREATS_PHISHING)

        # Check Malware Status
        if malware_status == 0:
            score += 1  # No deduction for no malware found
        else:
            issues.append(Issue_Config.ISSUE_THREATS_MALWARE)
            suggestions.append(Issue_Config.SUGGESTION_THREATS_MALWARE)


        percentage_score = (score / max_score) * 100
        report_util = Report_Utility()
        html_tags = await report_util.analysis_table(Configuration.ICON_THREATS, Configuration.MODULE_THREATS, issues, suggestions, int(percentage_score))

        return int(percentage_score), html_tags
    
    async def __empty_output(self, error):
        report_util = Report_Utility()
        table = await report_util.Empty_Table(f"Error: {error}", 100)
        
        return [table, ""]