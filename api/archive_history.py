import aiohttp
import asyncio
from colorama import Fore, Style
from datetime import datetime
from time import perf_counter
import traceback
from statistics import mean
from util.config_uti import Configuration
from util.issue_config import Issue_Config
from util.report_util import Report_Utility

class Archive_History:
    Error_Title = None

    def __init__(self, url, domain):
        self.url = url
        self.domain = domain

    async def Get_Archive_History(self):
        config = Configuration()
        self.Error_Title = config.ARCHIVE_HISTORY
        tasks = []
        decodedResponse = []
        output = []
        url = ""

        headers = {"Accept": "application/json",}

        try:
            # print("archive_history.py: start ")
            # start_time = perf_counter()
            async with aiohttp.ClientSession(headers=headers) as session:
                url = config.ARCHIVE_ENDPOINT_URL.replace("{url}", self.url)

                tasks.append(
                    asyncio.create_task(session.request(method="GET", url = url))
                    )

                responses = await asyncio.gather(*tasks)
                for response in responses:
                    decodedResponse.append(await response.json())

            output = await self.__html_table(decodedResponse)
            # print(f"✅ {config.MODULE_ARCHIVE_HISTORY} has been successfully completed in {round(perf_counter() - start_time, 2)} seconds.")
            print(f"✅ {config.MODULE_ARCHIVE_HISTORY} has been successfully completed.")
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
        
    async def __convert_timestamp_to_date(self, timestamp):
        year = int(timestamp[0:4])
        month = int(timestamp[4:6])
        day = int(timestamp[6:8])
        hour = int(timestamp[8:10])
        minute = int(timestamp[10:12])
        second = int(timestamp[12:14])
        return datetime(year, month, day, hour, minute, second)

    async def __count_page_changes(self, results):
        prev_digest = None
        change_count = 0
        for result in results:
            if result[2] != prev_digest:
                change_count += 1
                prev_digest = result[2]
        return change_count

    async def __get_average_page_size(self, scans):
        sizes = [int(scan[3]) for scan in scans]
        return round(mean(sizes))

    async def __get_scan_frequency(self, first_scan, last_scan, total_scans, change_count):
        days_between_scans = (last_scan - first_scan).days / total_scans
        days_between_changes = (last_scan - first_scan).days / change_count
        if (last_scan - first_scan).days > 0:
            scans_per_day = (total_scans - 1) / (last_scan - first_scan).days
            changes_per_day = change_count / (last_scan - first_scan).days
        else:
            scans_per_day = 0
            changes_per_day = 0
        return {
            'Days Between Scans': round(days_between_scans, 2),
            'Days Between Changes': round(days_between_changes, 2),
            'Scans Per Day': round(scans_per_day, 2),
            'Changes Per Day': round(changes_per_day, 2)
        }

    async def __html_table(self, data):
        html = ""
        if data and not any(data):
            report_util = Report_Utility()
            table = await report_util.Empty_Table()
        else:
            data[0].pop(0)
            first_scan = await self.__convert_timestamp_to_date(data[0][0][0])
            last_scan = await self.__convert_timestamp_to_date(data[-1][-1][0])
            total_scans = len(data[0])
            change_count = await self.__count_page_changes(data[0])
            average_page_size = await self.__get_average_page_size(data[0])
            scan_frequency = await self.__get_scan_frequency(first_scan, last_scan, total_scans, change_count)

            rep_data = []
            percentage, html = await self.__archive_history_score(first_scan, last_scan, total_scans, change_count, average_page_size, scan_frequency)

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
                            <td>First Scan</td>
                            <td>""" + first_scan.strftime("%d %B %Y") + """</td>
                        </tr>
                        <tr>
                            <td>Last Scan</td>
                            <td>""" + last_scan.strftime("%d %B %Y") + """</td>
                        </tr>
                        <tr>
                            <td>Total Scans</td>
                        <td>""" + str(total_scans) + """</td>
                        </tr>
                        <tr>
                            <td>Change Count</td>
                            <td>""" + str(change_count) + """</td>
                        </tr>
                        <tr>
                            <td>Avg Size</td>
                        <td>""" + str(average_page_size) + """</td>
                        </tr>
                        <tr>
                            <td>Avg Days between Scans</td>
                            <td>""" + str(scan_frequency['Days Between Scans']) + """</td>
                        </tr>
                    </table>"""
            )
        
        rep_data.append(table)
        rep_data.append(html)
        return rep_data          

    async def __archive_history_score(self, first_scan, last_scan, total_scans, change_count, average_page_size, scan_frequency):
        score = 0
        max_score = 6  
        issues = []
        suggestions = []

        # Evaluate each parameter with security conditions

        # First Scan
        if first_scan and await self.__is_valid_date(str(first_scan)):
            score += 1
        else:
            issues.append(Issue_Config.ISSUE_ARCHIVE_HISTORY_FIRST_SCAN)
            suggestions.append(Issue_Config.SUGGESTION_ARCHIVE_HISTORY_FIRST_SCAN)

        # Last Scan
        if last_scan and await self.__is_valid_date(str(last_scan)):
            score += 1
        else:
            issues.append(Issue_Config.ISSUE_ARCHIVE_HISTORY_LAST_SCAN)
            suggestions.append(Issue_Config.SUGGESTION_ARCHIVE_HISTORY_LAST_SCAN)

        # Total Scans
        if total_scans > 0:
            score += 1
        else:
            issues.append(Issue_Config.ISSUE_ARCHIVE_HISTORY_TOTAL_SCANS)
            suggestions.append(Issue_Config.SUGGESTION_ARCHIVE_HISTORY_TOTAL_SCANS)

        # Change Count
        if change_count > 0:
            score += 1
        else:
            issues.append(Issue_Config.ISSUE_ARCHIVE_HISTORY_CHANGE_COUNTS)
            suggestions.append(Issue_Config.SUGGESTION_ARCHIVE_HISTORY_CHANGE_COUNTS)

        # Avg Size
        if int(average_page_size) <= 20000:  # Set a threshold for Avg Size
            score += 1
        else:
            issues.append(Issue_Config.ISSUE_ARCHIVE_HISTORY_AVG_SIZE)
            suggestions.append(Issue_Config.SUGGESTION_ARCHIVE_HISTORY_AVG_SIZE)

        # Avg Days between Scans
        if int(scan_frequency['Days Between Scans']) <= 7:  # Set a threshold for Avg Days between Scans
            score += 1
        else:
            issues.append(Issue_Config.ISSUE_ARCHIVE_HISTORY_AVG_DAYS)
            suggestions.append(Issue_Config.SUGGESTION_ARCHIVE_HISTORY_AVG_DAYS)

        
        percentage_score = (score / max_score) * 100
        # html_tags = await self.__analysis_table(issues, suggestions, int(percentage_score))
        report_util = Report_Utility()
        html_tags = await report_util.analysis_table(Configuration.ICON_ARCHIVE_HISTORY, Configuration.MODULE_ARCHIVE_HISTORY, issues, suggestions, int(percentage_score))

        return int(percentage_score), html_tags

    async def __is_valid_date(self, date_str, date_format="%Y-%m-%d %H:%M:%S"):
        try:
            datetime.strptime(date_str, date_format)
            return True
        except ValueError:
            return False
        
    async def __empty_output(self, error):
        report_util = Report_Utility()
        table = await report_util.Empty_Table(f"Error: {error}", 100)
        
        return [table, ""]