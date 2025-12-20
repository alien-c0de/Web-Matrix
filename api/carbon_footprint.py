import aiohttp
from colorama import Fore, Style
from time import perf_counter
import traceback
from util.config_uti import Configuration
from util.issue_config import Issue_Config
from util.report_util import Report_Utility

class Carbon_Footprint:
    Error_Title = None

    def __init__(self, url, domain):
        self.url = url
        self.domain  = domain

    async def Get_Carbon_Footprint(self):
        config = Configuration()
        self.Error_Title = config.CARBON_FOOTPRINT
        output = []

        try:
            # start_time = perf_counter()
            async with aiohttp.ClientSession() as session:
                size_in_bytes = await self.__get_html_size(self.url)
                api_url = config.CARBON_API_ENDPOINT_URL.replace("{size_in_bytes}", str(size_in_bytes))
                async with session.get(api_url) as response:
                    response.raise_for_status()
                    decodedResponse = await response.json()

            output = await self.__html_table(decodedResponse)
            # print(f"✅ {config.MODULE_CARBON_FOOTPRINT} has been successfully completed in {round(perf_counter() - start_time, 2)} seconds.")
            print(f"✅ {config.MODULE_CARBON_FOOTPRINT} has been successfully completed.")
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

    async def __get_html_size(self, url):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    response.raise_for_status()
                    html_content = await response.text()
                    size_in_bytes = len(html_content.encode('utf-8'))
                    return size_in_bytes
        except aiohttp.ClientResponseError as e:
            if e.status == 403:
                msg = "[-] " + self.Error_Title + " => get_html_size : Forbidden: You don't have permission to access this resource."
                raise ValueError(msg)
            else:
                msg = "[-] " + self.Error_Title + " => get_html_size : Error fetching HTML size: {e}"
                raise ValueError(msg)

    async def __html_table(self, data):
        rep_data = []
        html = ""
        if not data:
            report_util = Report_Utility()
            table = await report_util.Empty_Table()
        else:
            HTML_Initial_Size = data['statistics']['adjustedBytes']
            CO2_Load = data['statistics']['co2']['grid']['grams']
            Energy_Usage = data['statistics']['energy']
            CO2_Emitted =  data['statistics']['co2']['renewable']['grams']
            percentage, html = await self.__carbon_footprint_score(HTML_Initial_Size, CO2_Load, Energy_Usage, CO2_Emitted)

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
                            <td>HTML Initial Size</td>
                            <td>""" + str(HTML_Initial_Size) +  """ bytes</td>
                        </tr>
                        <tr>
                            <td>CO2 for Initial Load:</td>
                            <td>""" + str(CO2_Load) + """ grams</td>
                        </tr>
                        <tr>
                            <td>Energy Usage for Load:</td>
                            <td>""" f"{data['statistics']['energy']:.4f}" """ KWg</td>
                        </tr>
                        <tr>
                            <td>CO2 Emitted:</td>
                            <td>""" + str(CO2_Emitted)  + """ grams</td>
                        </tr>
                    </table>"""
            )
        rep_data.append(table)
        rep_data.append(html)
        return rep_data

    async def __carbon_footprint_score(self, html_size, co2_initial_load, energy_usage, co2_emitted):
        score = 0
        max_score = 4  # 6 parameters to evaluate
        issues = []
        suggestions = []
        html_tags = ""
        # Define thresholds for scoring
        thresholds = {
            'html_size': 100000.0,  # in bytes
            'co2_initial_load': 0.05,  # in grams
            'energy_usage': 0.00015,  # in KWg
            'co2_emitted': 0.04  # in grams
        }

        # Initialize score, issues, and suggestions
        score = 0
        issues = []
        suggestions = []

        # Evaluate HTML initial size
        if html_size > thresholds['html_size']:
            issues.append(f"{Issue_Config.ISSUE_CO2_INITIAL_SIZE} {html_size} bytes")
            suggestions.append(Issue_Config.SUGGESTION_CO2_INITIAL_SIZE)
        else:
            score += 1

        # Evaluate CO2 for initial load
        if co2_initial_load > thresholds['co2_initial_load']:
            issues.append(f"{Issue_Config.ISSUE_CO2_INITIAL_LOAD} {co2_initial_load} grams")
            suggestions.append(Issue_Config.SUGGESTION_CO2_INITIAL_LOAD)
        else:
            score += 1

        # Evaluate energy usage for load
        if energy_usage > thresholds['energy_usage']:
            issues.append(f"{Issue_Config.ISSUE_CO2_ENERGY_USE} {energy_usage} KWg")
            suggestions.append(Issue_Config.SUGGESTION_CO2_ENERGY_USE)
        else:
            score += 1

        # Evaluate CO2 emitted
        if co2_emitted > thresholds['co2_emitted']:
            issues.append(f"{Issue_Config.ISSUE_CO2_EMITTED} {co2_emitted} grams")
            suggestions.append(Issue_Config.SUGGESTION_CO2_EMITTED)
        else:
            score += 1

        percentage = (score / max_score) * 100
        report_util = Report_Utility()
        html_tags = await report_util.analysis_table(Configuration.ICON_CARBON_FOOTPRINT, Configuration.MODULE_CARBON_FOOTPRINT, issues, suggestions, int(percentage))

        return int(percentage), html_tags

    async def __empty_output(self, error):
        report_util = Report_Utility()
        table = await report_util.Empty_Table(f"Error: {error}", 100)
        
        return [table, ""]