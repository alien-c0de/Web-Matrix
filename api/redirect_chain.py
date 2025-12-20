import aiohttp
from colorama import Fore, Style
from time import perf_counter
import traceback
from util.config_uti import Configuration
from util.report_util import Report_Utility
from util.issue_config import Issue_Config

class Redirect_Chain():
    def __init__(self, url, domain):
        self.url = url
        self.domain = domain

    async def Get_Redirect_Chain(self):
        config = Configuration()
        self.Error_Title = config.REDIRECT_FETCH
        output = []
        try:
            # start_time = perf_counter()
            result = await self.__final_result()
            output = await self.__html_table(result)
            # print(f"✅ {config.MODULE_REDIRECT_CHAIN} has been successfully completed in {round(perf_counter() - start_time, 2)} seconds.")
            print(f"✅ {config.MODULE_REDIRECT_CHAIN} has been successfully completed.")
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

    # THIS IS FINAL RESULT FUNCTION TO GET RESULT OF ALL FUNCTION
    async def __final_result(self):
        error_ans = [0,None,None]
        respond = []
        count = 0
        ans = ""
        try:
            # response = requests.get(self.url, allow_redirects=True)
            async with aiohttp.ClientSession() as session:
                async with session.get(self.url, allow_redirects = True) as response:
                    final_url = str(response.url)
                    # final_url = response.url

                    if response.history:
                        for resp in response.history:
                            count += 1
                            ans += str(resp.url)
                            ans += ',\n'
                        count += 1
                        ans += str(final_url)
                        ans += ',\n'
                        respond.append(count)
                        respond.append(ans)
                        respond.append(final_url)
                        return respond
                    else:
                        respond.append(count + 1)
                        respond.append(final_url)
                        respond.append(final_url)
                        return respond

        except Exception as e:
            #print(e)
            return error_ans

    async def __html_table(self, result):
        rep_data = []
        html = ""
        if not result:
            report_util = Report_Utility()
            table = await report_util.Empty_Table()
        else:
            percentage, html = await self.__redirect_score(result[0], str(result[1]), str(result[2]))
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
                            <td>""" + str(self.domain) + """</td>
                        </tr>
                        <tr>
                            <td>Number of Redirects</td>
                            <td>""" + str(result[0]) + """</td>
                        </tr>
                        <tr>
                            <td>Redirect Link</td>
                            <td>""" + str(result[1]) + """</td>
                        </tr>
                        <tr>
                            <td>Final Page</td>
                            <td>""" + str(result[2]) + """</td>
                        </tr>
                    </table>"""
            )
        rep_data.append(table)
        rep_data.append(html)
        return rep_data

    async def __rating(self, doman, no_of_redirect, redirect_link, final_page):
        condition1 = doman != None
        condition2 = no_of_redirect != None
        condition3 = redirect_link != None
        condition4 = final_page != None

        # Count the number of satisfied conditions
        satisfied_conditions = sum([condition1, condition2, condition3, condition4])
        
        # Determine the percentage based on the number of satisfied conditions
        if satisfied_conditions == 4:
            percentage = 100
        elif satisfied_conditions == 3:
            percentage = 75
        elif satisfied_conditions == 2:
            percentage = 50
        elif satisfied_conditions == 1:
            percentage = 25
        else:
            percentage = 0  # In case no conditions are satisfied
    
        return percentage
    
    async def __redirect_score(self, no_of_redirect, redirect_link, final_page):
        score = 0
        max_score = 2  # 6 parameters to evaluate
        issues = []
        suggestions = []
        html_tags = ""

        # More redirects = More Risk
        if no_of_redirect > 3:
            issues.append(f"{no_of_redirect} {Issue_Config.ISSUE_REDIRECT_TOTAL_REDIRECT}")
            suggestions.append(Issue_Config.SUGGESTION_REDIRECT_TOTAL_REDIRECT)
        else:
            score += 1
            

        # Check for HTTPS Usage
        if redirect_link.startswith("http://") and final_page.startswith("https://"):
            issues.append(Issue_Config.ISSUE_REDIRECT_HTTP_TO_HTTPS)
            suggestions.append(Issue_Config.SUGGESTION_REDIRECT_HTTP_TO_HTTPS)
        elif redirect_link.startswith("http://") and final_page.startswith("http://"):
            issues.append(Issue_Config.ISSUE_REDIRECT_HTTP_TO_HTTP)
            suggestions.append(Issue_Config.SUGGESTION_REDIRECT_HTTP_TO_HTTP)
        elif redirect_link.startswith("https://") and final_page.startswith("http://"):
            issues.append(Issue_Config.ISSUE_REDIRECT_HTTPS_TO_HTTP)
            suggestions.append(Issue_Config.SUGGESTION_REDIRECT_HTTPS_TO_HTTP)
        else:
            score += 1

        # Limit score to 100% max
        percentage_score = (score / max_score) * 100
        report_util = Report_Utility()
        html_tags = await report_util.analysis_table(Configuration.ICON_REDIRECT_CHAIN, Configuration.MODULE_REDIRECT_CHAIN, issues, suggestions, int(percentage_score))

        return int(percentage_score), html_tags
    
    async def __empty_output(self, error):
        report_util = Report_Utility()
        table = await report_util.Empty_Table(f"Error: {error}", 100)
        
        return [table, ""]