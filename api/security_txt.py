import aiohttp
from colorama import Fore, Style
from time import perf_counter
import traceback
from util.config_uti import Configuration
from util.report_util import Report_Utility
from util.issue_config import Issue_Config

class Security_TXT:
    Error_Title = None

    def __init__(self, url, domain):
        self.url = url
        self.domain = domain
        self.dict = {}

    SECURITY_TXT_PATHS = [
        "/security.txt",
        "/.well-known/security.txt",]

    async def Get_Security_TXT(self):
        config = Configuration()
        self.Error_Title = config.SECURITY_TXT
        output = []
        present = ""
        location = ""
        PGP = ""

        try:
            # start_time = perf_counter()
            for path in self.SECURITY_TXT_PATHS:
                url = f"{self.url}{path}"
                async with aiohttp.ClientSession() as session:
                    async with session.get(url) as response:
                        if response.status == 200:
                            result = await response.text()
                            if result and '<html' in result:
                                self.dict = {"isPresent": False}
                            if result:
                                self.dict = {
                                    "isPresent": True,
                                    "foundIn": path,
                                    "content": result,
                                    "isPgpSigned": await self.__is_pgp_signed(result),
                                    "fields": await self.__parse_result(result),
                                }
            if self.dict:
                present = self.dict["isPresent"]
                location = self.dict["foundIn"]
                PGP = self.dict["isPgpSigned"]

            output = await self.__html_table(present, location, PGP)
            # print(f"✅ {config.MODULE_SECURITY_TXT} has been successfully completed in {round(perf_counter() - start_time, 2)} seconds.")
            print(f"✅ {config.MODULE_SECURITY_TXT} has been successfully completed.")
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

    async def __is_pgp_signed(self, result):
        return '-----BEGIN PGP SIGNED MESSAGE-----' in result

    async def __parse_result(self, result):
        output = {}
        counts = {}
        lines = result.split('\n')
        for line in lines:
            if not line.startswith("#") and not line.startswith("-----") and line.strip() != '':
                key_value = line.split(':', 1)
                if len(key_value) == 2:
                    key = key_value[0].strip()
                    value = key_value[1].strip()
                    if key in output:
                        counts[key] = counts.get(key, 0) + 1
                        key += str(counts[key])
                    output[key] = value
        return output

    async def __html_table(self, present, location, PGP):
        rep_data = []
        html = ""

        percentage, html = await self.__security_TXT_score(present, location, PGP)

        # Build the HTML table
        table = (f"""<table>
                    <tr>
                        <td colspan="2">
                            <div class="progress-bar-container">
                                <div class="progress" style="width: {str(percentage)}%;">{str(percentage)}%</div>
                            </div>
                        </td>
                    </tr>
                    <tr>
                        <td> Present </td>
                        <td> {'✅ Yes' if present else '❌ No'} </td>
                    </tr>
                    <tr>
                        <td> File Location </td>
                        <td> {location} </td>
                    </tr>
                    <tr>
                        <td> PGP Signed </td>
                        <td> {'✅ Yes' if PGP else '❌ No'} </td>
                    </tr> </table>""")
        
        rep_data.append(table)
        rep_data.append(html)
        return rep_data

    async def __security_TXT_score(self, present, file_location, pgp_signed):
        score = 0
        max_score = 3
        issues = []
        suggestions = []

        # Check if security.txt is present
        if present:
            score += 1  # No risk if present
        else:
            issues.append(Issue_Config.ISSUE_SECURITY_TXT_MISSING)
            suggestions.append(Issue_Config.SUGGESTION_SECURITY_TXT_MISSING)

        # Validate file location
        if file_location == "/.well-known/security.txt":
            score += 1  # No risk
        else:
            issues.append(f"{Issue_Config.ISSUE_SECURITY_TXT_LOCATION} {file_location}")
            suggestions.append(Issue_Config.SUGGESTION_SECURITY_TXT_LOCATION)

        # Check if PGP Signed
        if pgp_signed:
            score += 1  # No risk if signed
        else:
            issues.append(Issue_Config.ISSUE_SECURITY_TXT_PGP)
            suggestions.append(Issue_Config.SUGGESTION_SECURITY_TXT_PGP)
        
        percentage_score = (score / max_score) * 100
        report_util = Report_Utility()
        html_tags = await report_util.analysis_table(Configuration.ICON_SECURITY_TXT, Configuration.MODULE_SECURITY_TXT, issues, suggestions, int(percentage_score))

        return int(percentage_score), html_tags
    
    async def __empty_output(self, error):
        report_util = Report_Utility()
        table = await report_util.Empty_Table(f"Error: {error}", 100)
        
        return [table, ""]