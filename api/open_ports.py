import socket
import asyncio
from colorama import Fore, Style
from time import perf_counter
import traceback
from util.config_uti import Configuration
from util.report_util import Report_Utility
from util.issue_config import Issue_Config

class Open_Ports():
    Error_Title = None

    def __init__(self, url, ip_address, domain):
        self.url = url
        self.ip_address = ip_address
        self.domain = domain

    ports_to_scan = [80, 443, 8080, 20, 21, 22, 23, 25, 53, 67, 68, 69, 110, 119, 123, 143, 156, 161, 162, 179, 194, 389, 587, 993, 995, 3000, 3306, 3389, 5060, 5900, 8000, 8888]

    PORT_RISK = {
        21: {"issue": Issue_Config.ISSUE_OPEN_PORT_FTP, "suggestion": Issue_Config.SUGGESTION_OPEN_PORT_FTP},
        22: {"issue": Issue_Config.ISSUE_OPEN_PORT_SSH, "suggestion": Issue_Config.SUGGESTION_OPEN_PORT_SSH},
        23: {"issue": Issue_Config.ISSUE_OPEN_PORT_TELNET, "suggestion": Issue_Config.SUGGESTION_OPEN_PORT_TELNET},
        25: {"issue": Issue_Config.ISSUE_OPEN_PORT_SMTP, "suggestion": Issue_Config.SUGGESTION_OPEN_PORT_SMTP},
        53: {"issue": Issue_Config.SUGGESTION_OPEN_PORT_DNS, "suggestion": Issue_Config.SUGGESTION_OPEN_PORT_DNS},
        110: {"issue": Issue_Config.ISSUE_OPEN_PORT_POP3, "suggestion": Issue_Config.SUGGESTION_OPEN_PORT_POP3},
        143: {"issue": Issue_Config.ISSUE_OPEN_PORT_IMAP, "suggestion": Issue_Config.SUGGESTION_OPEN_PORT_IMAP},
        3306: {"issue": Issue_Config.ISSUE_OPEN_PORT_MYSQL, "suggestion": Issue_Config.SUGGESTION_OPEN_PORT_MYSQL},
        3389: {"issue": Issue_Config.ISSUE_OPEN_PORT_RDP, "suggestion": Issue_Config.SUGGESTION_OPEN_PORT_RDP},
    }


    EXCLUDED_PORTS = {80, 443}

    async def Get_Open_Ports(self):
        config = Configuration()
        self.Error_Title = config.PORT_SCANNING
        output = []
        try:
            # start_time = perf_counter()
            open_ports = []
            closed_ports = []

            tasks = [self.check_port(self.domain, port) for port in self.ports_to_scan]
            results = await asyncio.gather(*tasks)

            for port, is_open in results:
                if is_open:
                    open_ports.append(port)
                else:
                    closed_ports.append(port)

            output = await self.__html_table(open_ports, closed_ports)
            # print(f"✅ {config.MODULE_OPEN_PORTS} has been successfully completed in {round(perf_counter() - start_time, 2)} seconds.")
            print(f"✅ {config.MODULE_OPEN_PORTS} has been successfully completed.")
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

    async def check_port(self, domain, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((domain, port))
            sock.close()
            return port, result == 0
        except Exception:
            return port, False

    async def __html_table(self, open_ports, closed_ports):
        rep_data = []
        html = ""

        if len(open_ports) == 0:
            report_util = Report_Utility()
            table = await report_util.Empty_Table()
        else:
            percentage, html = await self.__ports_score(open_ports)
            table = f"""<table>
                        <tr>
                            <td colspan="1">
                                <div class="progress-bar-container">
                                    <div class="progress" style="width:{str(percentage)}%;">{str(percentage)}%</div>
                                </div>
                            </td>
                        </tr>
                        <tr>
                            <td align="left">{'<br>'.join(map(str, open_ports)) if open_ports else 'None'}</td>
                        </tr>
                        <tr>
                            <td>
                            <h4 align="left">Unable to establish connections to:</h4>
                            <p align="left">{', '.join(map(str, closed_ports)) if closed_ports else 'None'}</p>
                            </td>
                        </tr>
                    </table>"""
        rep_data.append(table)
        rep_data.append(html)
        return rep_data

    async def __ports_score(self, open_ports):
        score = 0
        max_score = len(open_ports)
        issues = []
        suggestions = []

        for port in open_ports:
            if port in self.PORT_RISK and port not in self.EXCLUDED_PORTS:
                issues.append(self.PORT_RISK[port]["issue"])
                suggestions.append(self.PORT_RISK[port]["suggestion"])
            elif port not in self.PORT_RISK and port not in self.EXCLUDED_PORTS:
                issues.append(f"{port} {Issue_Config.ISSUE_OPEN_PORT_UNKNOW}")
                suggestions.append(Issue_Config.SUGGESTION_OPEN_PORT_UNKNOW)
            else:
                score += 1

        percentage_score = (score / max_score) * 100
        report_util = Report_Utility()
        html_tags = await report_util.analysis_table(Configuration.ICON_OPEN_PORTS, Configuration.MODULE_OPEN_PORTS, issues, suggestions, int(percentage_score))

        return int(percentage_score), html_tags
    
    async def __empty_output(self, error):
        report_util = Report_Utility()
        table = await report_util.Empty_Table(f"Error: {error}", 100)
        
        return [table, ""]
