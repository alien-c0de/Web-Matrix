from colorama import Fore, Style
from datetime import datetime, timezone
from datetime import datetime
import re
from time import perf_counter
import traceback
from util.config_uti import Configuration
from util.issue_config import Issue_Config
from util.report_util import Report_Utility

class Cookies():
    Error_Title = None

    def __init__(self, url, response, domain):
        self.url = url
        self.response = response
        self.domain = domain

    async def Get_Cookies(self):
        config = Configuration()
        self.Error_Title = config.COOKIES
        output = []
        try:
            # start_time = perf_counter()
            self.response.raise_for_status()  # Raise an error for non-200 status codes

            cookies = self.response.cookies
            cookie_info = {}
            for cookie in cookies:
                cookie_info = []
                for cookie in cookies:
                    cookie_info.append((cookie.name, cookie.value, cookie.domain, cookie.path, cookie.expires, cookie.secure))

            output = await self.__html_cookies_table(cookie_info)
            # print(f"✅ {config.MODULE_COOKIES} has been successfully completed in {round(perf_counter() - start_time, 2)} seconds.")
            print(f"✅ {config.MODULE_COOKIES} has been successfully completed.")
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

    async def __html_cookies_table(self, cookie_info):
        rep_data = []
        html = ""
        if not cookie_info:
            report_util = Report_Utility()
            table = await report_util.Empty_Table("This website does not use cookies.", 100)
        else:
            percentage, html = await self.__cookies_score(cookie_info)
            for cookie in cookie_info:
                name  = cookie[0] 
                value = cookie[1]
                domain = cookie[2]
                path = cookie[3]
                secure = cookie[5]
                if cookie[4]:
                    expires = datetime.fromtimestamp(cookie[4], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                else:
                    expires = ""

                table = f"""<table>
                                    <tr>
                                        <td colspan="2">
                                            <div class="progress-bar-container">
                                                <div class="progress" style="width: {percentage}%;">{percentage}%</div>
                                            </div>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td>Name</td>
                                        <td>{name}</td>
                                    </tr>
                                    <tr>
                                        <td>Session ID</td>
                                        <td>{value}</td>
                                    </tr>
                                    <tr>
                                        <td>Expires </td>
                                        <td>{expires}</td>
                                    </tr>
                                    <tr>
                                        <td>Path</td>
                                        <td>{path}</td>
                                    </tr>
                                    <tr>
                                        <td>Domain</td>
                                        <td>{domain}</td>
                                    </tr>
                                    <tr>
                                        <td>Secure</td>
                                        <td>{secure}</td>
                                    </tr>
                                </table>"""
        rep_data.append(table)
        rep_data.append(html)
        return rep_data

    async def __cookies_score(self, cookie):
        score = 0
        max_score = 6  # 6 parameters to evaluate
        issues = []
        suggestions = []
        html_tags = ""
        
        if cookie:
            session_name  = cookie[0][0] 
            session_value = cookie[0][1]
            domain = cookie[0][2]
            path = cookie[0][3]
            expires = cookie[0][4]
            secure = cookie[0][5]
            
            # Session Name - Should not be empty or generic
            if not session_name or session_name == 'session':
                issues.append(Issue_Config.ISSUE_COOKIES_SESSION_NAME)
                suggestions.append(Issue_Config.SUGGESTION_COOKIES_SESSION_NAME)
            else:
                score += 1
            
            # Session ID - Should not be simple (For simplicity, we will use regex)
            if not session_value or re.match(r'^[a-zA-Z0-9]{8,}$', session_value) is None:
                issues.append(Issue_Config.ISSUE_COOKIES_SESSION_VALUE)
                suggestions.append(Issue_Config.SUGGESTION_COOKIES_SESSION_VALUE)
            else:
                score += 1
            
            # Expires - Should not be far-off date or missing
            if not expires:
                issues.append(Issue_Config.ISSUE_COOKIES_EXPIRES)
                suggestions.append(Issue_Config.SUGGESTION_COOKIES_EXPIRES)
            else:
                try:
                    # Parse the expiration date
                    expire_date = datetime.strptime(expires, "%a, %d-%b-%Y %H:%M:%S GMT")
                    # Check if expired
                    if expire_date < datetime.now():
                        issues.append(Issue_Config.ISSUE_COOKIES_EXPIRES)
                        suggestions.append(Issue_Config.SUGGESTION_COOKIES_EXPIRES)
                    else:
                        score += 1
                except (ValueError, TypeError):
                    # Invalid date format
                    issues.append(Issue_Config.ISSUE_COOKIES_EXPIRES)
                    suggestions.append(Issue_Config.SUGGESTION_COOKIES_EXPIRES)
            
            # Path - Should not be overly broad (must be specific like `/app` or `/secure`)
            if path == '/' or not path:
                issues.append(Issue_Config.ISSUE_COOKIES_PATH)
                suggestions.append(Issue_Config.SUGGESTION_COOKIES_PATH)
            else:
                score += 1
            
            # Domain - Should be a specific domain, not localhost or too general
            if not domain or domain in ['localhost', '127.0.0.1', '']:
                issues.append(Issue_Config.ISSUE_COOKIES_DOMAIN)
                suggestions.append(Issue_Config.SUGGESTION_COOKIES_DOMAIN)
            else:
                score += 1
            
            # Secure - Should be True
            if secure != True:
                issues.append(Issue_Config.ISSUE_COOKIES_SECURE)
                suggestions.append(Issue_Config.SUGGESTION_COOKIES_SECURE)
            else:
                score += 1
        
        percentage_score = (score / max_score) * 100
        report_util = Report_Utility()
        html_tags = await report_util.analysis_table(
            Configuration.ICON_COOKIES, 
            Configuration.MODULE_COOKIES, 
            issues, 
            suggestions, 
            int(percentage_score)
        )
        
        return int(percentage_score), html_tags
    
    async def __empty_output(self, error):
        report_util = Report_Utility()
        table = await report_util.Empty_Table(f"Error: {error}", 100)
        
        return [table, ""]