import asyncio
import xml.etree.ElementTree as ET
import subprocess
import os
import re
import traceback
from time import perf_counter
from colorama import Fore, Style
from util.config_uti import Configuration
from util.issue_config import Issue_Config
from util.report_util import Report_Utility

class Nmap_Ops:
    Error_Title = None

    def __init__(self, ip_address, url, domain):
        self.url = url
        self.ip_address = ip_address
        self.domain = domain
        os.makedirs(self.xml_folder, exist_ok=True)  # Ensure folder exists

    nmap_scripts = {
        'general_vulnerabilities': 'http-vuln*',
        'sql_injection': 'http-sql-injection',
        'xss': 'http-stored-xss,http-dombased-xss',
        'shellshock': 'http-shellshock',
        'rce_exploits': 'http-vuln-cve2017-5638',
        'web_server_checks': 'http-enum,http-headers,http-methods',
    }

    # target_ip = "192.168.0.178"
    ports_to_scan = "21,22,25,53,80,110,143,443,465,587,993,995,8080,8443"
    xml_folder = "nmap_xml"

    @property
    def target_ip(self):
        # return "192.168.0.178"
        return self.ip_address 
    
    async def Get_Nmap_Ops(self):
        config = Configuration()
        self.Error_Title = config.NMAP_OPERATION
        output = []
        try:
            # start_time = perf_counter()
            tasks = [self.__os_detection(self.target_ip), self.__port_scan(self.target_ip)]
            for category, script in self.nmap_scripts.items():
                tasks.append(self.__run_nmap(self.target_ip, category, script))

            await asyncio.gather(*tasks)

            scan_data = {}
            scan_data["os_detection"] = await self.__parse_nmap_xml(f"{self.xml_folder}/nmap_output_os_detection.xml", "os_detection")

            scan_data["port_scan"] = await self.__parse_nmap_xml(f"{self.xml_folder}/nmap_output_port_scan.xml", "port_scan")

            for category in self.nmap_scripts.keys():
                scan_data[category] = await self.__parse_nmap_xml(f"{self.xml_folder}/nmap_output_{category}.xml", category)

            output = await asyncio.gather(*(self.__html_table(category, data) for category, data in scan_data.items()))
            # print(f"✅ {config.MODULE_NMAP_OPERATION} has been successfully completed in {round(perf_counter() - start_time, 2)} seconds.")
            print(f"✅ {config.MODULE_NMAP_OPERATION} has been successfully completed.")
            return [table for sublist in output for table in sublist]  # Flatten list
            # return output

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

    async def __html_table(self, category, scan_data):
        rep_data = []
        html = ""
        table_parts = []

        if not scan_data:
            report_util = Report_Utility()
            table = await report_util.Empty_Table(f"Couldn't find any {category} vulnerabilities.", 100)
        else:
            percentage, html = await self.__nmap_score(category, scan_data)
            table_parts = [
                        '<table>',
                        '<tr>',
                        f'<td colspan="2"><div class="progress-bar-container">'
                        f'<div class="progress" style="width: {percentage}%;">{percentage}%</div></div></td>',
                        '</tr>'
                    ]
            
            if category == "port_scan":
                table_parts.append(
                    f'<tr><td colspan="2" style="text-align: left;"><h3>Open Ports</h3></td></tr>'
                    )

            for data in scan_data:
                if category == "os_detection":
                    table_parts.append(
                        f'<tr><td>OS Details</td><td>{data["os"]}</td></tr>'
                    )
                elif category == "port_scan":
                    if data["state"].lower() == "open":
                        table_parts.append(
                            f'<tr><td>{data["port"]}</td><td>{data["service"]}</td></tr>'
                        )
                else:
                    table_parts.append(
                        f'<tr><td colspan="3" style="text-align: left;"><h3>{data["script_id"]}</h3></td></tr>'
                        f'<tr><td colspan="3" style="text-align: left;">{data["output"]}</td></tr>'
                    )

            table_parts.append("</table>")
            table = "".join(table_parts)  # Combine all parts into a single string

        rep_data.append(table.replace("\n", ""))  # Remove all newline characters
        rep_data.append(html.replace("\n", ""))   # Ensure the report does not contain newlines
        return rep_data

    async def __nmap_score(self, category, scan_data):
        issues = []
        suggestions = []
        score = 0
        icon = ""
        module  = ""
        
        for data in scan_data:
            # score = 0  # Reset score for each entry
            if category == "os_detection":
                if "os" in data and data["os"] != "Unknown":
                    issues.append(Issue_Config.ISSUE_NMAP_OS_DETECT.format(data['os']))
                    suggestions.append(Issue_Config.SUGGESTION_NMAP_OS_DETECT)
                else:
                    score += 1  # If OS is not detected, it’s more secure.
                icon = Configuration.ICON_NMAP_OS_DETECT
                module = Configuration.MODULE_NMAP_OS_DETECT
            elif category == "port_scan":
                if "port" in data and "state" in data and data["state"].lower() == "open":
                    port_number = int(data["port"])  # Convert to integer for comparison
                    if port_number not in [80, 443]:  # Skip ports 80 and 443
                        issues.append(Issue_Config.ISSUE_NMAP_PORT_SCAN.format(port_number, data.get('service', 'unknown service')))
                        suggestions.append(Issue_Config.SUGGESTION_NMAP_PORT_SCAN.format(port_number))
                    else:
                        score += 1  # If it's port 80 or 443, increase score (indicating it's not a critical issue)
                else:
                    score += 1

                icon = Configuration.ICON_NMAP_PORT_SCAN
                module = Configuration.MODULE_NMAP_PORT_SCAN
            else:  # Check for vulnerabilities in script output
                script_id = data.get('script_id', 'unknown script')
                output = data.get('output', '').lower()

            if category == "sql_injection":
                if "sql injection" in output or "sql-injection" in script_id:
                    issues.append(Issue_Config.ISSUE_NMAP_SQL_INJECTION.format(script_id))
                    suggestions.append(Issue_Config.SUGGESTION_NMAP_SQL_INJECTION)
                else:
                    score += 1

                icon = Configuration.ICON_NMAP_SQL_INJECTION
                module = Configuration.MODULE_NMAP_SQL_INJECTION

            if category == "xss":
                if (
                    script_id in ["http-stored-xss", "http-dombased-xss"]
                    and (
                        "couldn't find any stored xss vulnerabilities." in output
                        or "couldn't find any dom based xss." in output
                    )
                ):
                    # No XSS vulnerabilities found; skip adding issues
                    score += 1
                
                elif "xss" in output or "cross-site scripting" in output:
                    issues.append(Issue_Config.ISSUE_NMAP_XSS.format(script_id))
                    suggestions.append(Issue_Config.SUGGESTION_NMAP_XSS)
                else:
                    score += 1

                icon = Configuration.ICON_NMAP_XSS
                module = Configuration.MODULE_NMAP_XSS
                
            if category == "shellshock":
                if "shellshock" in output:
                    issues.append(Issue_Config.ISSUE_NMAP_SHELLSHOCK.format(script_id))
                    suggestions.append(Issue_Config.SUGGESTION_NMAP_SHELLSHOCK)
                else:
                    score += 1

                icon = Configuration.ICON_NMAP_SHELLSHOCK
                module = Configuration.MODULE_NMAP_SHELLSHOCK
            
            if category == "rce_exploits":
                if "remote code execution" in output or "rce" in output:
                    issues.append(Issue_Config.ISSUE_NMAP_RCE_EXPLOITS.format(script_id))
                    suggestions.append(Issue_Config.SUGGESTION_NMAP_RCE_EXPLOITS)
                else:
                    score += 1

                icon = Configuration.ICON_NMAP_RCE_EXPLOITS
                module = Configuration.MODULE_NMAP_RCE_EXPLOITS

            if category == "web_server_checks":
                if "server misconfiguration" in output or "http-headers" in script_id or "http-methods" in script_id:
                    issues.append(Issue_Config.ISSUE_NMAP_WEB_CHECK_MISCONFIG.format(script_id))
                    suggestions.append(Issue_Config.SUGGESTION_NMAP_WEB_CHECK_MISCONFIG)

                elif "enumeration" in output or "http-enum" in script_id:
                    issues.append(Issue_Config.ISSUE_NMAP_WEB_CHECK_ENUM.format(script_id))
                    suggestions.append(Issue_Config.SUGGESTION_NMAP_WEB_CHECK_ENUM)

                else:
                    score += 1
                
                icon = Configuration.ICON_NMAP_WEB_SERVER_CHECK
                module = Configuration.MODULE_NMAP_WEB_SERVER_CHECK

            # Handling general vulnerabilities (http-vuln*)
            if category == "general_vulnerabilities*":
                if "http-vuln" in script_id:
                    issues.append(Issue_Config.ISSUE_NMAP_HTTP_VULN.format(script_id))
                    suggestions.append(Issue_Config.SUGGESTION_NMAP_HTTP_VULN)

                elif "csrf" in output or "cross-site request forgery" in output:
                    issues.append(Issue_Config.ISSUE_NMAP_CSRF.format(script_id))
                    suggestions.append(Issue_Config.SUGGESTION_NMAP_CSRF)

                elif "open redirect" in output:
                    issues.append(Issue_Config.ISSUE_NMAP_OPEN_REDIRECT.format(script_id))
                    suggestions.append(Issue_Config.SUGGESTION_NMAP_OPEN_REDIRECT)
                
                else:
                    score += 1

                icon = Configuration.ICON_NMAP_HTTP_VULN
                module = Configuration.MODULE_NMAP_HTTP_VULN

        percentage_score = (score / len(scan_data)) * 100
        report_util = Report_Utility()
        html_tags = await report_util.analysis_table(icon, module, issues, suggestions, int(percentage_score))
        return int(percentage_score), html_tags

    async def __run_nmap(self, target_ip, script_category, nmap_script):
        output_file = f"{self.xml_folder}/nmap_output_{script_category}.xml"
        # command = ["sudo", "nmap", "-sT", "-T2", "-p", self.ports_to_scan, "--script", nmap_script, "-oX", output_file, target_ip]
        command = ["sudo", "nmap", "-sS", "-T3", "-p", self.ports_to_scan, "--script", nmap_script, "--min-parallelism 10", "-oX", output_file, target_ip]
        # command = ["sudo", "nmap", "-sS", "-T1", "-p", self.ports_to_scan, "--script", nmap_script, 
        #            "-f", "--spoof-mac", "00:11:22:33:44:55", "-D", "RND:2", "-oX", output_file, target_ip]
        # print(f"    ⚙️  Running NMAP script : {nmap_script}")
        process = await asyncio.create_subprocess_exec(*command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        await process.communicate()

    async def __os_detection(self, target_ip):
        output_file = f"{self.xml_folder}/nmap_output_os_detection.xml"
        command = ["sudo", "nmap", "-O", "-oX", output_file, target_ip]
        # command = ["sudo", "nmap", "-sS", "-O", "--osscan-guess", "-oX", output_file, target_ip]
        # command = ["sudo", "nmap", "-sS", "-O", "-T2", "--scan-delay", "1s", "-D", "RND:2", "-oX", output_file, target_ip]
        # print(f"    ⚙️  Running NMAP OS Detection.")
        process = await asyncio.create_subprocess_exec(*command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        await process.communicate()

    async def __port_scan(self, target_ip):
        output_file = f"{self.xml_folder}/nmap_output_port_scan.xml"
        # command = ["sudo", "nmap", "-p-", "-oX", output_file, target_ip]
        command = ["sudo", "nmap", "-sS", "--top-ports", "1000", "-T2", "-oX", output_file, target_ip]
        # command = ["sudo", "nmap", "-sS", "--top-ports", "1000", "-T2", "--scan-delay", "1s", "-D", "RND:2", "-oX", output_file, target_ip]
        # print(f"    ⚙️  Running NMAP Port Scan.")
        process = await asyncio.create_subprocess_exec(*command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        await process.communicate()

    async def __parse_nmap_xml(self, xml_file, category):
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            scan_data = []
            for host in root.findall('host'):

                if category == "os_detection":
                    os_info = host.find(".//osmatch")
                    os_name = os_info.get('name') if os_info is not None else "Unknown"
                    scan_data.append({'os': os_name})

                elif category == "port_scan":
                    for port in host.findall(".//port"):
                        port_id = port.get('portid')
                        state = port.find(".//state")
                        state = state.get('state')
                        service = port.find(".//service")
                        service_name = service.get('name') if service is not None else "Unknown"
                        scan_data.append({'port': port_id, 'state': state, 'service': service_name})

                else:
                    for script in host.findall(".//script"):
                        script_id = script.get('id')
                        script_output = script.get('output', 'No output')

                        # Remove HTML tags from script output
                        clean_output = re.sub(r'<[^>]+>', '', script_output)
                        scan_data.append({'script_id': script_id, 'output': clean_output})
            return scan_data
        except Exception as e:
            print(f"Error parsing XML {xml_file}: {e}")
            return []

    async def __empty_output(self, error):
        report_util = Report_Utility()
        table = await report_util.Empty_Table(f"Error: {error}", 100)
        
        return [table, "", table, "", table, "", table, "", table, "", table, "", table, "", table, ""]