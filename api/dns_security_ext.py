import aiohttp
import asyncio
from colorama import Fore, Style
from time import perf_counter
import traceback
from util.config_uti import Configuration
from util.report_util import Report_Utility
from util.issue_config import Issue_Config

class DNS_Security_Ext:
    Error_Title = None

    def __init__(self, url, domain):
        self.url = url
        self.domain = domain

    dns_parameters = {
        'DNSKEY': {
            'present': True,
            'flags': {
                'RD': True,
                'RA': True,
                'TC': False,
                'AD': True,
                'CD': False
            }
        },
        'DS': {
            'present': True,
            'flags': {
                'RD': True,
                'RA': True,
                'TC': False,
                'AD': True,
                'CD': False
            }
        },
        'RRSIG': {
            'present': True,
            'flags': {
                'RD': True,
                'RA': True,
                'TC': False,
                'AD': True,
                'CD': False
            }
        }
    }

    async def Get_DNS_Security_Ext(self):
        config = Configuration()
        self.Error_Title = config.DNS_SECURITY_EXT
        output = []

        try:
            # start_time = perf_counter()
            dns_types = ['DNSKEY', 'DS', 'RRSIG']
            records = {}

            async with aiohttp.ClientSession() as session:
                tasks = [self.__fetch_dns_record(session, self.url, dns_type, config.DNS_SECURITY_API) for dns_type in dns_types]
                results = await asyncio.gather(*tasks)

            for dns_type, result in zip(dns_types, results):
                records[dns_type] = result

            output = await self.__html_table(records)
            # print(f"✅ {config.MODULE_DNS_SECURITY} has been successfully completed in {round(perf_counter() - start_time, 2)} seconds.")
            print(f"✅ {config.MODULE_DNS_SECURITY} has been successfully completed.")
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

    async def __fetch_dns_record(self, session, domain, dns_type, url):
        new_url = url.replace("{domain}", domain).replace("{dns_type}", dns_type)
        headers = {'Accept': 'application/dns-json'}

        try:
            async with session.get(new_url, headers=headers) as response:
                response.raise_for_status()
                dns_response = await response.json()

                return {
                        'isFound': bool(dns_response.get('Answer')),
                        'answer': dns_response.get('Answer', []),
                        'flags': dns_response.get('AD'),
                        }
        except Exception as error:
            raise Exception(f"Error fetching {dns_type} record: {error}")


    async def __html_table(self, data):
        rep_data = []
        html = ""
        
        if not data:
            report_util = Report_Utility()
            table = await report_util.Empty_Table()
        else:
            percentage, html = await self.__DNS_Sec_score()
            dns_flags = [
                ('Recursion Desired (RD)', True),
                ('Recursion Available (RA)', True),
                ('TrunCation (TC)', False),
                ('Authentic Data (AD)', lambda record: '✅' if record['flags'] else '❌'),
                ('Checking Disabled (CD)', False)
            ]

            rows = []

            for dns_type, record in data.items():
                rows.append(f"""
                <tr>
                    <td><h3>{dns_type}</h3></td>
                    <td></td>
                </tr>
                <tr>
                    <td>{dns_type} - Present?</td>
                    <td>{'✅ Yes' if record['isFound'] else '❌ No'}</td>
                </tr>
                """)

                for description, status in dns_flags:
                    status_output = status(record) if callable(status) else ('✅' if status else '❌')
                    rows.append(f"""
                    <tr>
                        <td style="padding-left: 20px;">{description}</td>
                        <td>{status_output}</td>
                    </tr>
                    """)

            rows = ''.join(rows)

            table = f"""
            <table>
                <tr>
                    <td colspan="2">
                        <div class="progress-bar-container">
                            <div class="progress" style="width: {str(percentage)}%;">{str(percentage)}%</div>
                        </div>
                    </td>
                </tr>
                {rows}
            </table>"""

        rep_data.append(table)
        rep_data.append(html)
        return rep_data

    async def __DNS_Sec_score(self):
        score = 100
        issues = []
        suggestions = []
        html_tags = ""

        for dns_type, params in self.dns_parameters.items():
            if not params['present']:
                score -= 20
                issues.append(f"{dns_type} {Issue_Config.ISSUE_DNS_SECURITY_DNS_TYPE}")
                suggestions.append(f"{Issue_Config.SUGGESTION_DNS_SECURITY_DNS_TYPE} {dns_type}.")

            flags_issues = []
            if not params['flags']['RD']:
                flags_issues.append(Issue_Config.ISSUE_DNS_SECURITY_RD)
            if not params['flags']['RA']:
                flags_issues.append(Issue_Config.ISSUE_DNS_SECURITY_RA)
            if params['flags']['TC']:
                flags_issues.append(Issue_Config.ISSUE_DNS_SECURITY_TC)
            if not params['flags']['AD']:
                flags_issues.append(Issue_Config.ISSUE_DNS_SECURITY_AD)
            if params['flags']['CD']:
                flags_issues.append(Issue_Config.ISSUE_DNS_SECURITY_CD)

            if flags_issues:
                score -= len(flags_issues) * 2
                issues.append(f"{dns_type} flags issues: {', '.join(flags_issues)}.")
                suggestions.append(f"{Issue_Config.SUGGESTION_DNS_SECURITY_DNS_FLAG} {dns_type}: {', '.join(flags_issues)}.")

        percentage_score = max(score, 0)
        
        report_util = Report_Utility()
        html_tags = await report_util.analysis_table(Configuration.ICON_DNS_SECURITY, Configuration.MODULE_DNS_SECURITY, issues, suggestions, int(percentage_score))

        return int(percentage_score), html_tags
    
    async def __empty_output(self, error):
        report_util = Report_Utility()
        table = await report_util.Empty_Table(f"Error: {error}", 100)
        
        return [table, ""]

