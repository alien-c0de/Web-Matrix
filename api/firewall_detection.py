import requests
from colorama import Fore, Style
from time import perf_counter
import traceback
from util.config_uti import Configuration
from util.report_util import Report_Utility
from util.issue_config import Issue_Config

class Firewall_Detection():
    Error_Title = None

    def __init__(self, url, domain):
        self.url = url
        self.domain = domain

    async def Get_Firewall_Detection(self):
        config = Configuration()
        self.Error_Title = config.FIREWALL
        output = []
        waf_identifiers = {'cloudflare': 'Cloudflare', 'aws lambda': 'AWS WAF', 'akamaighost': 'Akamai',    
                           'sucuri': 'Sucuri', 'barracudawaf': 'Barracuda WAF', 'f5 big-ip': 'F5 BIG-IP',
                            'big-ip': 'F5 BIG-IP', 'fortiweb': 'Fortinet FortiWeb WAF', 'imperva': 'Imperva SecureSphere WAF',
                            'sqreen': 'Sqreen', 'reblaze': 'Reblaze WAF', 'citrix netscaler': 'Citrix NetScaler',
                            'wangzhanbao': 'WangZhanBao WAF', 'webcoment': 'Webcoment Firewall', 'yundun': 'Yundun WAF',
                            'safe3waf': 'Safe3 Web Application Firewall', 'naxsi': 'NAXSI WAF','ibm websphere datapower': 'IBM WebSphere DataPower',
                        }
        try:
            # start_time = perf_counter()
            response = requests.get(self.url, timeout=10)
            headers = response.headers

            header_checks = {
                'server': lambda val: any(keyword in val.lower() for keyword in waf_identifiers.keys()),
                'x-powered-by': lambda val: 'aws lambda' in val.lower(),
                'x-sucuri-id': lambda _: True,
                'x-sucuri-cache': lambda _: True,
                'x-protected-by': lambda val: 'sqreen' in val.lower(),
                'x-waf-event-info': lambda _: True,
                'set-cookie': lambda val: '_citrix_ns_id' in val,
                'x-denied-reason': lambda _: True,
                'x-wzws-requested-method': lambda _: True,
                'x-webcoment': lambda _: True,
                'x-yd-waf-info': lambda _: True,
                'x-yd-info': lambda _: True,
                'x-datapower-transactionid': lambda _: True,
            }

            for header, check in header_checks.items():
                if header in headers and check(headers[header]):
                    for key, waf in waf_identifiers.items():
                        if key in headers.get('server', '').lower():
                            decode = {'Firewall': True, 'WAF': waf}
                            output = await self.__html_table(decode)
                            return output
                    decode = {'Firewall': True, 'WAF': waf_identifiers.get(header.lower(), 'Unknown WAF')}
                    output = await self.__html_table(decode)
                    return output

            decode = {'hasWaf': False, 'wafName': '*The domain may be protected with a proprietary or custom WAF which we were unable to identify automatically'}
            output = await self.__html_table(decode)
            # print(f"✅ {config.MODULE_FIREWALL_DETECTION} has been successfully completed in {round(perf_counter() - start_time, 2)} seconds.")
            print(f"✅ {config.MODULE_FIREWALL_DETECTION} has been successfully completed.")
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

    async def __html_table(self, data):
        rep_data = []
        html = ""
        if not data:
            report_util = Report_Utility()
            table = await report_util.Empty_Table()
        else:
            percentage, html = await self.__firewall_score(data)
            rows = [
                f"""
                <tr>
                    <td>{key}</td>
                    <td>{value}</td>
                </tr>"""
                for key, value in data.items()
            ]

            table = f"""
            <table>
                <tr>
                    <td colspan="2">
                        <div class="progress-bar-container">
                            <div class="progress" style="width: {str(percentage) }%;">{str(percentage)}%</div>
                        </div>
                    </td>
                </tr>
                    {''.join(rows)}
            </table>"""

        rep_data.append(table)
        rep_data.append(html)
        return rep_data

    async def __firewall_score(self, data):
        score = 0
        max_score = 2  
        issues = []
        suggestions = []
        html_tags = ""

        # Extracting the values, considering case insensitivity
        has_waf_key = next((key for key in data if key.lower() == 'haswaf'), None)
        waf_name_key = next((key for key in data if key.lower() == 'wafname'), None)

        hasWaf = data.get(has_waf_key, 'False')
        wafName = data.get(waf_name_key, '*The domain may be protected with a proprietary or custom WAF which we were unable to identify automatically*')

        # Session Name - Should not be empty or generic
        if hasWaf:
            score += 1
        else:
            issues.append(Issue_Config.ISSUE_FIREWALL_HAS_WAF)
            suggestions.append(Issue_Config.SUGGESTION_FIREWALL_HAS_WAF)

        # Session ID - Should not be simple (For simplicity, we will use regex)
        if wafName.lower() == "*the domain may be protected with a proprietary or custom waf which we were unable to identify automatically":
            issues.append(Issue_Config.ISSUE_FIREWALL_WAF_NAME)
            suggestions.append(Issue_Config.SUGGESTION_FIREWALL_WAF_NAME)
        else:
            score += 1

        percentage_score = (score / max_score) * 100
        report_util = Report_Utility()
        html_tags = await report_util.analysis_table(Configuration.ICON_FIREWALL_DETECTION, Configuration.MODULE_FIREWALL_DETECTION, issues, suggestions, int(percentage_score))

        return int(percentage_score), html_tags
    
    async def __empty_output(self, error):
        report_util = Report_Utility()
        table = await report_util.Empty_Table(f"Error: {error}", 100)
        
        return [table, ""]
