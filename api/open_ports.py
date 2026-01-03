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

    # Updated PORT_RISK dictionary with severity levels
    PORT_RISK = {
        # High Risk Ports (Security concerns)
        21: {"issue": Issue_Config.ISSUE_OPEN_PORT_FTP, "suggestion": Issue_Config.SUGGESTION_OPEN_PORT_FTP, "severity": "high"},
        22: {"issue": Issue_Config.ISSUE_OPEN_PORT_SSH, "suggestion": Issue_Config.SUGGESTION_OPEN_PORT_SSH, "severity": "medium"},
        23: {"issue": Issue_Config.ISSUE_OPEN_PORT_TELNET, "suggestion": Issue_Config.SUGGESTION_OPEN_PORT_TELNET, "severity": "high"},
        25: {"issue": Issue_Config.ISSUE_OPEN_PORT_SMTP, "suggestion": Issue_Config.SUGGESTION_OPEN_PORT_SMTP, "severity": "medium"},
        53: {"issue": Issue_Config.ISSUE_OPEN_PORT_DNS, "suggestion": Issue_Config.SUGGESTION_OPEN_PORT_DNS, "severity": "low"},
        110: {"issue": Issue_Config.ISSUE_OPEN_PORT_POP3, "suggestion": Issue_Config.SUGGESTION_OPEN_PORT_POP3, "severity": "medium"},
        143: {"issue": Issue_Config.ISSUE_OPEN_PORT_IMAP, "suggestion": Issue_Config.SUGGESTION_OPEN_PORT_IMAP, "severity": "medium"},
        3306: {"issue": Issue_Config.ISSUE_OPEN_PORT_MYSQL, "suggestion": Issue_Config.SUGGESTION_OPEN_PORT_MYSQL, "severity": "high"},
        3389: {"issue": Issue_Config.ISSUE_OPEN_PORT_RDP, "suggestion": Issue_Config.SUGGESTION_OPEN_PORT_RDP, "severity": "high"},
    }

    # Ports that are commonly used for legitimate web services (not threats)
    SAFE_PORTS = {
        80,    # HTTP - Standard web traffic
        443,   # HTTPS - Secure web traffic
        8080,  # HTTP Alternate - Common for web apps, proxies, app servers
        8000,  # HTTP Alternate - Development/alternate web server
        8888,  # HTTP Alternate - Alternate web server
    }

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
            # Categorize ports
            safe_ports = [p for p in open_ports if p in self.SAFE_PORTS]
            risky_ports = [p for p in open_ports if p not in self.SAFE_PORTS]
            
            percentage, html = await self.__ports_score(open_ports)
            
            # Enhanced table with categorization
            table = f"""<table>
                        <tr>
                            <td colspan="2">
                                <div class="progress-bar-container">
                                    <div class="progress" style="width:{str(percentage)}%;">{str(percentage)}%</div>
                                </div>
                            </td>
                        </tr>"""
            
            # Show safe/standard ports
            if safe_ports:
                table += f"""
                        <tr>
                            <td><strong>Standard Web Ports (Safe):</strong></td>
                            <td align="right">{', '.join(map(str, sorted(safe_ports)))}</td>
                        </tr>"""
            
            # Show risky ports
            if risky_ports:
                table += f"""
                        <tr>
                            <td><strong>Ports Requiring Review:</strong></td>
                            <td align="right" style="color: #f59e0b;">{', '.join(map(str, sorted(risky_ports)))}</td>
                        </tr>"""
            
            # Show all open ports
            table += f"""
                        <tr>
                            <td><strong>All Open Ports:</strong></td>
                            <td align="right">{', '.join(map(str, sorted(open_ports)))}</td>
                        </tr>"""
            
            # Show closed ports summary
            if closed_ports:
                table += f"""
                        <tr>
                            <td colspan="2">
                                <details style="margin-top: 10px;">
                                    <summary style="cursor: pointer; color: #64748b;">
                                        <strong>Closed/Filtered Ports ({len(closed_ports)})</strong>
                                    </summary>
                                    <p style="margin-top: 8px; color: #64748b; font-size: 0.9em;">
                                        {', '.join(map(str, sorted(closed_ports)))}
                                    </p>
                                </details>
                            </td>
                        </tr>"""
            
            table += """</table>"""
            
        rep_data.append(table)
        rep_data.append(html)
        return rep_data

    async def __ports_score(self, open_ports):
        """
        Enhanced scoring system that treats standard web ports as safe
        Only flags genuinely risky ports as issues
        """
        score = 0
        max_score = len(open_ports)
        issues = []
        suggestions = []

        for port in open_ports:
            # Safe ports get full points
            if port in self.SAFE_PORTS:
                score += 1
            # Known risky ports
            elif port in self.PORT_RISK:
                severity = self.PORT_RISK[port].get("severity", "medium")
                issues.append(f"Port {port}: {self.PORT_RISK[port]['issue']}")
                suggestions.append(self.PORT_RISK[port]["suggestion"])
                
                # Partial scoring based on severity
                if severity == "low":
                    score += 0.5  # Low risk gets half point
                # High/medium risk gets 0 points
            # Unknown ports (not in safe list, not in risk list)
            else:
                issues.append(f"Port {port}: {Issue_Config.ISSUE_OPEN_PORT_UNKNOW}")
                suggestions.append(Issue_Config.SUGGESTION_OPEN_PORT_UNKNOW)
                score += 0.3  # Unknown ports get minimal points

        # Calculate percentage
        percentage_score = (score / max_score) * 100 if max_score > 0 else 100
        
        # Add informational note if only safe ports are open
        safe_ports_only = all(port in self.SAFE_PORTS for port in open_ports)
        if safe_ports_only and not issues:
            issues.append("All open ports are standard web service ports (80, 443, 8080, 8000, 8888)")
            suggestions.append("Standard web ports are open. Ensure these services are properly secured with firewalls, authentication, and up-to-date software.")
        
        report_util = Report_Utility()
        html_tags = await report_util.analysis_table(
            Configuration.ICON_OPEN_PORTS, 
            Configuration.MODULE_OPEN_PORTS, 
            issues, 
            suggestions, 
            int(percentage_score)
        )

        return int(percentage_score), html_tags
    
    async def __empty_output(self, error):
        report_util = Report_Utility()
        table = await report_util.Empty_Table(f"Error: {error}", 100)
        
        return [table, ""]