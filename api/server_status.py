import aiohttp
from time import perf_counter
from colorama import Fore, Style
import traceback
from util.config_uti import Configuration
from util.report_util import Report_Utility
from util.issue_config import Issue_Config

class Server_Status():
    Error_Title = None

    def __init__(self, url, response, domain):
        self.url = url
        self.response = response
        self.domain = domain

    async def Get_Server_Status(self):
        config = Configuration()
        self.Error_Title = config.SERVER_STATUS
        output = []
        IsUp  = False
        try:
            async with aiohttp.ClientSession() as session:
                start_time = perf_counter()
                async with session.get(self.url) as response:
                    end_time = perf_counter()
                    response_time = round(end_time - start_time, 2)  # Convert to ms
                    IsUp = True

            output = await self.__html_table(IsUp, response.status, response_time)
            # print(f"✅ {config.MODULE_SERVER_STATUS} has been successfully completed in {round(perf_counter() - start_time, 2)} seconds.")
            print(f"✅ {config.MODULE_SERVER_STATUS} has been successfully completed.")
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

    async def __html_table(self, IsUp, status, response_time):
        rep_data = []
        html = ""

        if IsUp:
            percentage, html = await self.__server_status_score(IsUp, status, response_time)

            table = (
                f"""<table>
                        <tr>
                            <td colspan="2">
                                <div class="progress-bar-container">
                                    <div class="progress" style="width:{str(percentage)}%;">{str(percentage)}%</div>
                                </div>
                            </td>
                        </tr>
                        <tr>
                            <td>Is Up?</td>
                            <td>{'✅ Online' if IsUp else '❌ Offline'} </td>
                        </tr>
                        <tr>
                        <td>Status Code</td>
                            <td >{str(status)}</td>
                        </tr>
                        <tr>
                        <td>Response Time</td>
                            <td >{str(response_time)} ms</td>
                        </tr>
                </table>"""
            )
        else:
            report_util = Report_Utility()
            table = await report_util.Empty_Table()

        rep_data.append(table)
        rep_data.append(html)
        return rep_data


    async def __server_status_score(self, is_up, status_code, response_time):
        score = 0  # Start with a full score
        max_score = 3
        issues = []
        suggestions = []
        
        # Check if website is online
        if is_up:
            score += 1
        else:
            issues.append(Issue_Config.ISSUE_SERVER_STATUS_IS_UP)
            suggestions.append(Issue_Config.SUGGESTION_SERVER_STATUS_IS_UP)
            
        # Check status code issues
        if status_code != 200:
            if status_code in [301, 302]:
                issues.append(f"{Issue_Config.ISSUE_SERVER_STATUS_300} {status_code}")
                suggestions.append(Issue_Config.SUGGESTION_SERVER_STATUS_300)
            elif status_code in [400, 403, 404]:
                issues.append(f"{Issue_Config.ISSUE_SERVER_STATUS_400} {status_code}")
                suggestions.append(Issue_Config.SUGGESTION_SERVER_STATUS_400)
            elif status_code in [500, 502, 503, 504]:
                issues.append(f"{Issue_Config.ISSUE_SERVER_STATUS_500} {status_code}: ")
                suggestions.append(Issue_Config.SUGGESTION_SERVER_STATUS_500)
            else:
                score += 1
        else:
            score += 1
        
        # Check response time (in milliseconds)
        if response_time > 200:
            issues.append(f"{Issue_Config.ISSUE_SERVER_STATUS_TIME_200} {response_time} ms.")
            suggestions.append(Issue_Config.SUGGESTION_SERVER_STATUS_TIME_200)
        elif response_time > 100:
            issues.append(f"{Issue_Config.ISSUE_SERVER_STATUS_TIME_100} {response_time} ms.")
            suggestions.append(Issue_Config.SUGGESTION_SERVER_STATUS_TIME_100)
        else:
            score += 1
        
        percentage_score = (score / max_score) * 100
        report_util = Report_Utility()
        html_tags = await report_util.analysis_table(Configuration.ICON_SERVER_STATUS, Configuration.MODULE_SERVER_STATUS, issues, suggestions, int(percentage_score))

        return int(percentage_score), html_tags
    
    async def __empty_output(self, error):
        report_util = Report_Utility()
        table = await report_util.Empty_Table(f"Error : {error}", 100)
        
        return [table, ""]
