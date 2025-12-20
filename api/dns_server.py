import aiohttp
import asyncio
from colorama import Fore, Style
from time import perf_counter
import traceback
from util.config_uti import Configuration
from util.report_util import Report_Utility
from util.issue_config import Issue_Config

class DNS_Server():
    Error_Title = None

    def __init__(self, ip_address, url, domain):
        self.ip_address = ip_address
        self.url = url
        self.domain = domain

    async def Get_DNS_Server(self):

        config = Configuration()
        self.Error_Title = config.DNS_SERVER
        DoH = "No"
        output = []

        try:
            doh_url = f"https://{self.ip_address}/dns-query"
            
            # Set a timeout to prevent hanging on both Linux and Windows
            timeout = aiohttp.ClientTimeout(total=5)

            async with aiohttp.ClientSession(timeout=timeout) as session:
                try:
                    async with session.get(doh_url) as response:
                        if response.status == 200:
                            DoH = "Yes"
                
                except (aiohttp.ClientError, asyncio.TimeoutError, ConnectionResetError, OSError):
                    # Silently handle the failure (common in scanning) and return the "No" table
                    output = await self.__html_table(DoH)
                    print(f"✅ {config.MODULE_DNS_SERVER} has been successfully completed.")
                    return output

            return await self.__html_table(DoH)

        except Exception as ex:
            # This is your generic crash handler for unexpected logic errors
            error_type = ex.__class__.__name__
            error_message = str(ex)
            tb = traceback.extract_tb(ex.__traceback__)
            error_details = tb[-1]
            
            file_name = error_details.filename
            method_name = error_details.name
            line_number = error_details.lineno

            error_msg = f"❌ {self.Error_Title} => ERROR in method '{method_name}' at line {line_number} : {error_type}: {error_message}"
            print(Fore.RED + Style.BRIGHT + error_msg + Fore.RESET + Style.RESET_ALL)
            output = await self.__empty_output(error_message)
            return output

    async def __html_table(self, DoH):
        rep_data = []
        html = ""
        if not DoH:
            report_util = Report_Utility()
            table = await report_util.Empty_Table()
        else:
            percentage, html = await self.__DNS_Server_score(DoH)
            table = (
                f"""<table>
                        <tr>
                            <td colspan="2">
                                <div class="progress-bar-container">
                                    <div class="progress" style="width: {str(percentage)}%;">{str(percentage) }%</div>
                                </div>
                            </td>
                        </tr>
                        <tr>
                            <td>IP Address</td>
                            <td>{str(self.ip_address)}</td>
                        </tr>
                        <tr>
                            <td>Hostname</td>
                            <td>{str(self.domain)}</td>
                        </tr>
                        <tr>
                            <td>DoH Support</td>
                            <td>{'✅ Yes' if str(DoH) == 'Yes'  else '❌ No'}</td>
                        </tr>
                    </table>"""
            )
        rep_data.append(table)
        rep_data.append(html)
        return rep_data
    
    async def __DNS_Server_score(self, DoH):
        issues = []
        suggestions = []
        html_tags = ""
        percentage = 0

        if DoH:
            # Session Name - Should not be empty or generic
            if DoH.upper() == 'NO':
                issues.append(Issue_Config.ISSUE_DNS_SERVER)
                suggestions.append(Issue_Config.SUGGESTION_DNS_SERVER)
                percentage = 50
            else:
                percentage = 100
    
        report_util = Report_Utility()
        html_tags = await report_util.analysis_table(Configuration.ICON_DNS_SERVER, Configuration.MODULE_DNS_SERVER, issues, suggestions, int(percentage))

        return int(percentage), html_tags
    
    async def __empty_output(self, error):
        report_util = Report_Utility()
        table = await report_util.Empty_Table(f"Error: {error}", 100)
        
        return [table, ""]