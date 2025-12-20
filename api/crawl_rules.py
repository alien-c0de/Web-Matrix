import aiohttp
from colorama import Fore, Style
from time import perf_counter
import traceback
from urllib.parse import urljoin
from util.config_uti import Configuration
from util.report_util import Report_Utility
from util.issue_config import Issue_Config

class Crawl_Rules:
    Error_Title = None

    def __init__(self, url, domain):
        self.url = url
        self.domain = domain

    SENSITIVE_KEYWORDS = ['admin', 'login', 'config', 'backup', 'private', 'secret', 'data', 'password', 'upload']

    async def Get_Crawl_Rules(self):
        config = Configuration()
        self.Error_Title = config.CRAWL_RULES
        output = []
        robot_url = urljoin(self.url, config.CRAWL_FILE)
        try:
            # start_time = perf_counter()
            async with aiohttp.ClientSession() as session:
                async with session.get(robot_url) as response:
                    crawl_rules = []
                    user_agent = ""
                    if response.status == 200:
                        # Parse robots.txt and extract rules
                        lines = (await response.text()).splitlines()
                        
                        for line in lines:
                            if line.lower().startswith("user-agent:"):
                                user_agent = line.split(":")[1].strip()
                            elif line.lower().startswith(("allow:", "disallow:")):
                                rule = line.split(":")[1].strip()
                                crawl_rules.append((user_agent, rule))

            output = await self.__html_table(user_agent, crawl_rules, lines)
            # print(f"✅ {config.MODULE_CRAWL_RULES} has been successfully completed in {round(perf_counter() - start_time, 2)} seconds.")
            print(f"✅ {config.MODULE_CRAWL_RULES} has been successfully completed.")
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

    async def __html_table(self, user_agent, data, raw_rules):
        rep_data = []
        html = ""
        if data:
            percentage, html = await self.__crawl_rules_score(raw_rules)
            table = (
                    """<table>
                            <tr>
                                <td colspan="2">
                                    <div class="progress-bar-container">
                                        <div class="progress" style="width: """+ str(percentage) +"""%;">"""+ str(percentage) +"""%</div>
                                    </div>
                                </td>
                            </tr>"""
                    + "".join(
                        f"""<tr>
                                <td>User Agent : {user_agent}</td>
                                <td>{rule}</td>
                        </tr>"""
                        for user_agent, rule in data
                    )
                    + """</table>"""
                )
        else:
            report_util = Report_Utility()
            table = await report_util.Empty_Table()

        rep_data.append(table)
        rep_data.append(html)
        return rep_data

    async def __crawl_rules_score(self, crawl_rules):
        score = 0
        max_score = len(crawl_rules) * len(self.SENSITIVE_KEYWORDS)
        issues = []
        suggestions = []
        html_tags = ""

        for rule in crawl_rules:
            for keyword in self.SENSITIVE_KEYWORDS:
                if keyword in rule.lower():
                    issues.append(f"{Issue_Config.ISSUE_CRAWL_RULES} {rule}")
                    suggestions.append(f"{Issue_Config.SUGGESTION__CRAWL_RULES} {keyword}.")
                else:
                    score += 1

        percentage_score = (score / max_score) * 100
        report_util = Report_Utility()
        html_tags = await report_util.analysis_table(Configuration.ICON_CRAWL_RULES, Configuration.MODULE_CRAWL_RULES, issues, suggestions, int(percentage_score))

        return int(percentage_score), html_tags
    
    async def __empty_output(self, error):
        report_util = Report_Utility()
        table = await report_util.Empty_Table(f"Error: {error}", 100)
        
        return [table, ""]
