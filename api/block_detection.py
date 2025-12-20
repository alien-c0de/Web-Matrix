import dns.asyncresolver
import dns.resolver
import asyncio
from colorama import Fore, Style
from time import perf_counter
import traceback
from util.config_uti import Configuration
from util.report_util import Report_Utility
from util.issue_config import Issue_Config


class Block_Detection:
    Error_Title = None

    def __init__(self, url, ip_address, domain):
        self.url = url
        self.ip_address = ip_address
        self.domain = domain

    DNS_SERVERS = [
    {'name': 'AdGuard', 'ip': '176.103.130.130'},
    {'name': 'AdGuard Family', 'ip': '176.103.130.132'},
    {'name': 'CleanBrowsing Adult', 'ip': '185.228.168.10'},
    {'name': 'CleanBrowsing Family', 'ip': '185.228.168.168'},
    {'name': 'CleanBrowsing Security', 'ip': '185.228.168.9'},
    {'name': 'CloudFlare', 'ip': '1.1.1.1'},
    {'name': 'CloudFlare Family', 'ip': '1.1.1.3'},
    {'name': 'Comodo Secure', 'ip': '8.26.56.26'},
    {'name': 'Google DNS', 'ip': '8.8.8.8'},
    {'name': 'Neustar Family', 'ip': '156.154.70.3'},
    {'name': 'Neustar Protection', 'ip': '156.154.70.2'},
    {'name': 'Norton Family', 'ip': '199.85.126.20'},
    {'name': 'OpenDNS', 'ip': '208.67.222.222'},
    {'name': 'OpenDNS Family', 'ip': '208.67.222.123'},
    {'name': 'Quad9', 'ip': '9.9.9.9'},
    {'name': 'Yandex Family', 'ip': '77.88.8.7'},
    {'name': 'Yandex Safe', 'ip': '77.88.8.88'}]

    KNOWN_BLOCK_IPS = [
        '146.112.61.106',  # OpenDNS
        '185.228.168.10',  # CleanBrowsing
        '8.26.56.26',      # Comodo
        '9.9.9.9',         # Quad9
        '208.69.38.170',   # Some OpenDNS IPs
        '208.69.39.170',   # Some OpenDNS IPs
        '208.67.222.222',  # OpenDNS
        '208.67.222.123',  # OpenDNS FamilyShield
        '199.85.126.10',   # Norton
        '199.85.126.20',   # Norton Family
        '156.154.70.22',   # Neustar
        '77.88.8.7',       # Yandex
        '77.88.8.8',       # Yandex
        '::1',             # Localhost IPv6
        '2a02:6b8::feed:0ff',  # Yandex DNS
        '2a02:6b8::feed:bad',  # Yandex Safe
        '2a02:6b8::feed:a11',  # Yandex Family
        '2620:119:35::35',     # OpenDNS
        '2620:119:53::53',     # OpenDNS FamilyShield
        '2606:4700:4700::1111',  # Cloudflare
        '2606:4700:4700::1001',  # Cloudflare
        '2001:4860:4860::8888',  # Google DNS
        '2a0d:2a00:1::',         # AdGuard
        '2a0d:2a00:2::'          # AdGuard Family
    ]

    async def Get_Block_Detection(self):
        """Optimized function to detect domain blocking."""
        config = Configuration()
        self.Error_Title = config.BLOCK_DETECTION
        output = []
        try:
            # start_time = perf_counter()
            results = await self.__check_domain_against_dns_servers()
            output = await self.__html_table(results)  # Assuming __html_table is async
            # print(f"✅ {config.MODULE_BLOCK_DETECTION} has been successfully completed in {round(perf_counter() - start_time, 2)} seconds.")
            print(f"✅ {config.MODULE_BLOCK_DETECTION} has been successfully completed.")
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
        
    async def __check_domain_against_dns_servers(self):
        """Runs DNS checks concurrently for all servers."""
        tasks = [self.__check_domain_against_dns_server(server) for server in self.DNS_SERVERS]
        return await asyncio.gather(*tasks)

    async def __check_domain_against_dns_server(self, server):
        """Checks if a domain is blocked on a given DNS server."""
        is_blocked = await self.__is_domain_blocked(server['ip'])
        return {'server': server['name'], 'server_ip': server['ip'], 'is_blocked': is_blocked}

    async def __is_domain_blocked(self, server_ip):
        """Optimized DNS resolver using async queries."""
        resolver = dns.asyncresolver.Resolver()
        resolver.nameservers = [server_ip]

        # Run A and AAAA queries in parallel
        tasks = [self.__resolve_dns(resolver, 'A'), self.__resolve_dns(resolver, 'AAAA')]
        results = await asyncio.gather(*tasks)

        return any(results)  # If any result is True, domain is blocked

    async def __resolve_dns(self, resolver, record_type):
        """Helper function to resolve DNS asynchronously."""
        try:
            answers = await resolver.resolve(self.domain, record_type)
            return any(rdata.to_text() in self.KNOWN_BLOCK_IPS for rdata in answers)
        except (dns.resolver.NoAnswer, dns.resolver.Timeout):
            return False
        except dns.resolver.NXDOMAIN:
            return True  # Domain blocked

    async def __html_table(self, data):
        rep_data = []
        html = ""
        if data and not any(data):
            report_util = Report_Utility()
            table = await report_util.Empty_Table()
        else:
            percentage, html = await self.__block_score(data)
            table = (
            """<table>
                <tr>
                    <td colspan="2">
                        <div class="progress-bar-container">
                            <div class="progress" style="width: """+ str(percentage) +"""%;">"""+ str(percentage) +"""%</div>
                        </div>
                    </td>
                </tr>"""
            + "".join(
                f"""<tr>
                    <td> {block['server']} </td>
                    <td> {'❌ Blocked' if block['is_blocked']  else '✅  Not Blocked'}  </td>
                </tr>"""
                for block in data
            )
            + """</table>"""
        )
        rep_data.append(table)
        rep_data.append(html)
        return rep_data

    async def __block_score(self, data):
        count = 0
        percentage = 0
        issues = []
        suggestions = []
        html_tags = ""

        for block in data:
            if block['is_blocked']:
                count += 1

        ser = len(self.DNS_SERVERS)
        if ser > 0:
            percentage = (100 * count) / ser

        if count > 1:
            issues.append(Issue_Config.ISSUE_COOKIES_SESSION_NAME)
            suggestions.append(Issue_Config.SUGGESTION_COOKIES_SESSION_NAME)
        else:
            percentage = 100  # Ensure percentage is 100 if no issues are found

        report_util = Report_Utility()
        html_tags = await report_util.analysis_table(Configuration.ICON_BLOCK_DETECTION, Configuration.MODULE_BLOCK_DETECTION, issues, suggestions, int(percentage))

        return int(percentage), html_tags
    
    async def __empty_output(self, error):
        report_util = Report_Utility()
        table = await report_util.Empty_Table(f"Error: {error}", 100)
        
        return [table, ""]


    
