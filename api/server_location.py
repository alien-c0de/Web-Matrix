import pandas as pd
import aiohttp
import asyncio
from colorama import Fore, Style
from time import perf_counter
import traceback
from util.config_uti import Configuration
from util.issue_config import Issue_Config
from util.report_util import Report_Utility


class Server_Location():
    Error_Title = None

    def __init__(self, ip_address, domain):
        self.ip_address = ip_address
        self.domain = domain

    async def Get_Server_Location(self):
        config = Configuration()
        self.Error_Title = config.SERVER_LOCATION
        tasks = []
        decodedResponse = []
        location = []
        info = [] 
        output = []

        headers = {'Accept': 'application/json',}

        try:
            # start_time = perf_counter()
            async with aiohttp.ClientSession(headers=headers) as session:
                url = config.IPAPI_IO_ENDPOINT_URL + self.ip_address + "/json/"
                tasks.append(asyncio.create_task(session.request(method="GET", url=url)))

                responses = await asyncio.gather(*tasks)
                for response in responses:
                    decodedResponse.append(await response.json())

            dataframe = pd.DataFrame.from_dict(decodedResponse[0], orient='index')
            location = await self.__html_server_loc_table(dataframe)
            info = await self.__html_server_info_table(dataframe)
            output = location + info
            # print(f"✅ {config.MODULE_SERVER_LOCATION} has been successfully completed in {round(perf_counter() - start_time, 2)} seconds.")
            print(f"✅ {config.MODULE_SERVER_LOCATION} has been successfully completed.")
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

    async def __html_server_info_table(self, dataframe):
        rep_data = []
        html = ""
        if dataframe.empty:
            percentage = 0
            report_util = Report_Utility()
            table = report_util.Empty_Table()
        else:
            org = str(dataframe[0]["org"])
            asn = str(dataframe[0]["asn"])
            ip = str(dataframe[0]["ip"])
            location =  str(dataframe[0]["region"]) + ",\n " + str(dataframe[0]["country_name"])

            percentage, html = await self.__server_info_score(org, asn, ip, location)

            table = """<table>
                            <tr>
                                <td colspan="2">
                                    <div class="progress-bar-container">
                                        <div class="progress" style="width:""" + str(percentage) + """%;">""" + str(percentage) + """%</div>
                                    </div>
                                </td>
                            </tr>
                            <tr>
                                <td>Organization</td>
                                <td>""" + org +  """</td>
                            </tr>
                            <tr>
                                <td>ASN Code</td>
                                <td>""" + asn +  """</td>
                            </tr>
                            <tr>
                                <td>IP</td>
                                <td>""" + ip +  """</td>
                            </tr>
                            <tr>
                                <td>Location</td>
                                <td>""" + location +  """</td>
                            </tr>
                    </table>"""

        rep_data.append(table)
        rep_data.append(html)
        return rep_data

    async def __html_server_loc_table(self, dataframe):
        rep_data = []
        html = ""
        if dataframe.empty:
            report_util = Report_Utility()
            table = await report_util.Empty_Table()
        else:
            city =  str(dataframe[0]["city"])
            postal = str(dataframe[0]["postal"])
            region = str(dataframe[0]["region"])
            country = str(dataframe[0]["country_name"])
            country_code = str(dataframe[0]["country_code"]).lower()
            timezone = str(dataframe[0]["timezone"])
            languages =  str(dataframe[0]["languages"])
            currency_name = str(dataframe[0]["currency_name"])
            currency = str(dataframe[0]["currency"])

            percentage, html = await self.__server_Location_score(city, country, timezone, languages, currency)

            table = """<table>
                            <tr>
                                <td colspan="2">
                                    <div class="progress-bar-container">
                                        <div class="progress" style="width:""" + str(percentage) + """%;">""" + str(percentage) + """%</div>
                                    </div>
                                </td>
                            </tr>
                            <tr>
                                <td>City</td>
                                <td>""" + postal + ", " + city + ", " + region + """</td>
                            </tr>
                            <tr>
                                <td>Country</td>
                                <td> """ + country + """ <span id="country-icon" class="flag-icon"></span></td>
                            </tr>
                            <tr>
                                <td>Timezone</td>
                                <td>""" + timezone +  """</td>
                            </tr>
                            <tr>
                                <td>Languages</td>
                                <td>""" + languages +  """</td>
                            </tr>
                            <tr>
                                <td>Currency</td>
                                <td>""" + currency_name  + "  (" + currency + ")" """</td>
                            </tr>
                    </table>
                    <script>
                        function displayCountryIcon() {
                            const countryIconElement = document.getElementById('country-icon');
                            countryIconElement.className = 'flag-icon flag-icon-$ """ + country_code + """';
                        }
                        displayCountryIcon();
                    </script>"""
        rep_data.append(table)
        rep_data.append(html)
        return rep_data

    async def __server_Location_score(self, city, country, timezone, languages, currency):
        score = 0
        max_score = 5 # Max total score

        issues = []
        suggestions = []

        # Check City
        if city != "Unknown" and city != "":
            score += 1
        else:
            issues.append(Issue_Config.ISSUE_LOCATION_CITY)
            suggestions.append(Issue_Config.SUGGESTION_LOCATION_CITY)

        # Check Country
        if country != "Unknown" and country != "":
            score += 1
        else:
            issues.append(Issue_Config.ISSUE_LOCATION_COUNTRY)
            suggestions.append(Issue_Config.SUGGESTION_LOCATION_COUNTRY)

        # Check Timezone
        if timezone != "Unknown" and timezone != "":
            score += 1
        else:
            issues.append(Issue_Config.ISSUE_LOCATION_TIMEZONE)
            suggestions.append(Issue_Config.SUGGESTION_LOCATION_TIMEZONE)

        # Check Languages
        if languages != "Unknown" and languages != "":
            score += 1
        else:
            issues.append(Issue_Config.ISSUE_LOCATION_LANGUAGES)
            suggestions.append(Issue_Config.SUGGESTION_LOCATION_LANGUAGES)

        # Check Currency
        if currency != "Unknown" and currency != "":
            score += 1
        else:
            issues.append(Issue_Config.ISSUE_LOCATION_CURRENCY)
            suggestions.append(Issue_Config.SUGGESTION_LOCATION_CURRENCY)

        # Calculate percentage score
        percentage_score = (score / max_score) * 100
        report_util = Report_Utility()
        html_tags = await report_util.analysis_table(Configuration.ICON_SERVER_LOCATION, Configuration.MODULE_SERVER_LOCATION, issues, suggestions, int(percentage_score))

        return int(percentage_score), html_tags

    async def __server_info_score(self, organization, asn_code, ip, location):
        score = 0
        max_score = 4 # Max total score

        issues = []
        suggestions = []

        # Check Organization
        if organization != "Unknown" and organization != "":
            score += 1
        else:
            issues.append(Issue_Config.ISSUE_SERVER_INFO_ORGANIZATION)
            suggestions.append(Issue_Config.SUGGESTION_SERVER_INFO_ORGANIZATION)

        # Check ASN Code
        if asn_code != "Unknown" and asn_code != "":
            score += 1
        else:
            issues.append(Issue_Config.ISSUE_SERVER_INFO_ASN)
            suggestions.append(Issue_Config.SUGGESTION_SERVER_INFO_ASN)

        # Check IP
        if ip != "Unknown" and ip != "":
            score += 1
        else:
            issues.append(Issue_Config.ISSUE_IP)
            suggestions.append(Issue_Config.SUGGESTION_SERVER_INFO_IP)

        # Check Location
        if location != "Unknown" and location != "":
            score += 1
        else:
            issues.append(Issue_Config.ISSUE_SERVER_INFO_LOCATION)
            suggestions.append(Issue_Config.SUGGESTION_SERVER_INFO_LOCATION)

        # Calculate percentage score
        percentage_score = (score / max_score) * 100
        report_util = Report_Utility()
        html_tags = await report_util.analysis_table(Configuration.ICON_SERVER_INFO, Configuration.MODULE_SERVER_INFO, issues, suggestions, int(percentage_score))

        return int(percentage_score), html_tags
    
    async def __empty_output(self, error):
        report_util = Report_Utility()
        table = await report_util.Empty_Table(f"Error : {error}", 100)
        
        return [table, "", table, ""]