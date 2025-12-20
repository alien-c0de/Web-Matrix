import os
import time
from bs4 import BeautifulSoup
from colorama import Back, Fore, Style
from util.config_uti import Configuration

class Summary_Report:
    def __init__(self, domain, timestamp):
        self.domain = domain
        self.timestamp = timestamp

    async def __ranking_percentage(self, Server_Location, SSL_Cert, Whois, ser_info, HTTP_sec, headers, cookies, dns_server_info, 
                             tls_cipher_suite, dns_info, txt_info, server_status_info, mail_configuration_info, redirect_Record, 
                             ports, archive_info, associated_info, block_info, carbon_info, crawl_info, site_info, dns_sec_info,
                             tech_stack_info, firewall_info, social_tag_info, threats_info, global_ranking_info, security_txt_info, nmap_ops):

        # List of parameters
        params = {
            'Server_Location': Server_Location,
            'SSL_Cert': SSL_Cert,
            'Whois': Whois,
            'ser_info': ser_info,
            'HTTP_sec': HTTP_sec,
            'headers': headers,
            'cookies': cookies,
            'DNS_Server': dns_server_info,
            'tls_cipher_suite': tls_cipher_suite,
            'dns_info': dns_info,
            'txt_info': txt_info,
            'server_status_info': server_status_info,
            'mail_configuration_info': mail_configuration_info,
            'redirect_Record': redirect_Record,
            'ports': ports,
            'archive_info': archive_info,
            'associated_info': associated_info,
            'block_info': block_info,
            'carbon_info': carbon_info,
            'crawl_info': crawl_info,
            'site_info': site_info,
            'dns_sec_info': dns_sec_info,
            'tech_stack_info': tech_stack_info,
            'firewall_info': firewall_info,
            'social_tag_info': social_tag_info,
            'threats_info': threats_info,
            'global_ranking_info': global_ranking_info,
            'security_txt_info': security_txt_info
        }

        percent = 0
        total_items = len(params)

        # Process regular params
        for name, value in params.items():
            if isinstance(value, str):
                progress = await self._extract_progress_from_html(value)
                if progress:
                    percent += int(progress.rstrip('%'))

        # Process nmap_ops if it's not None
        if nmap_ops:
            selected_indices = {0, 2, 4, 6, 8, 10, 12, 14}
            filtered_nmap_ops = [nmap_ops[i] for i in selected_indices if i < len(nmap_ops)]

            for item in filtered_nmap_ops:
                if isinstance(item, str):
                    progress = await self._extract_progress_from_html(item)
                    if progress:
                        percent += int(progress.rstrip('%'))

            total_items += len(filtered_nmap_ops)  # Adjust total count for averaging

        # Calculate final percentage
        final = percent / total_items if total_items else 0
        return round(final, 2)

    async def _extract_progress_from_html(self, html_content):
        """Extract the progress percentage from HTML content."""
        # Simulate an asynchronous operation if needed
        # await asyncio.sleep(0)  # No actual async operation here, but for demonstration

        soup = BeautifulSoup(html_content, 'html.parser')
        progress_div = soup.find('div', class_='progress')
        if progress_div:
            return progress_div.get_text(strip=True)
        return None

    async def Generate_Summary_Report(self, website, Server_Location, SSL_Cert, Whois, ser_info, HTTP_sec, headers, cookies, dns_server_info, 
                         tls_cipher_suite, dns_info, txt_info, server_status_info, mail_configuration_info, redirect_Record, 
                         ports, archive_info, associated_info, block_info, carbon_info, crawl_info, site_info, dns_sec_info,
                         tech_stack_info, firewall_info, social_tag_info, threats_info, global_ranking_info, security_txt_info, 
                         nmap_ops, mode = 1):

        config = Configuration()
        # report_timestamp = str(time.strftime("%A %d-%b-%Y %H:%M:%S", self.timestamp))
        report_timestamp = self.timestamp.strftime("%A %d-%b-%Y %H:%M:%S")
        if nmap_ops:
            Analysis_report = "%s_%s_%s_%s.html" % (config.ANALYSIS_REPORT_FILE_NAME, self.domain, config.REPORT_NMAP_FILE_NAME, self.timestamp.strftime("%d%b%Y_%H-%M-%S"))
        else:    
            Analysis_report = "%s_%s_%s.html" % (config.ANALYSIS_REPORT_FILE_NAME, self.domain, self.timestamp.strftime("%d%b%Y_%H-%M-%S"))

        percent = await self.__ranking_percentage(Server_Location, SSL_Cert, Whois, ser_info, HTTP_sec, headers, cookies, dns_server_info, 
                         tls_cipher_suite, dns_info, txt_info, server_status_info, mail_configuration_info, redirect_Record, 
                         ports, archive_info, associated_info, block_info, carbon_info, crawl_info, site_info, dns_sec_info,
                         tech_stack_info, firewall_info, social_tag_info, threats_info, global_ranking_info, security_txt_info, nmap_ops)
        header = (
            """<!DOCTYPE html>
            <html lang="en">
            <head>
            <meta charset="UTF-8">
            <meta http-equiv="X-UA-Compatible" content="IE=edge">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title> """
            + config.TOOL_NAME
            + """ </title>
            <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css" rel="stylesheet"/>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/flag-icon-css/3.5.0/css/flag-icon.min.css">""")
        body = (
            f"""</head>
                <body>
                <div class="header">
                    <h1> <i class="fas fa-user-secret icon"></i> {config.REPORT_HEADER} </h1>
                    <h2 align="right"; margin-right: 40px; style="color:#00FF00;"> <a href= "{website}" target="_blank"> {website} </a></h2>
                </div>
                <div class="date">
                    <h3 align="right"; margin-right: 20px; style="color:blue;"><i class="far fa-clock"></i> Report Generated: {report_timestamp}</h3>
                </div>
                <div class="ranking-container">
                    <h1> {config.REPORT_RANK_PANAL} <i class="fas fa-heartbeat"></i></h1>
                    <div class="progress-bar-container">
                        <div class="progress-bar" style="width: {str(percent)}%;">{str(percent)}%</div>
                    </div>
                    <h2> <a href="{Analysis_report}?report={str(percent)}" target="_blank"> {config.ANALYSIS_REPORT_HEADER} </a></h2>
                </div>
                <div class="content">
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_SERVER_LOCATION + """ </h2>
                            <i class= """ + config.ICON_SERVER_LOCATION + """ > </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + Server_Location + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_SSL_CERTIFICATE + """ </h2>
                            <i class=  """ + config.ICON_SSL_CERTIFICATE + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + SSL_Cert + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_DOMAIN_WHOIS + """ </h2>
                            <i class=""" + config.ICON_DOMAIN_WHOIS + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + Whois + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_SERVER_INFO + """ </h2>
                            <i class=""" + config.ICON_SERVER_INFO + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + ser_info + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_HEADERS + """ </h2>
                            <i class=""" + config.ICON_HEADERS + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + headers + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_COOKIES + """ </h2>
                            <i class=""" + config.ICON_COOKIES + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + cookies + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_HTTP_SECURITY + """ </h2>
                            <i class=""" + config.ICON_HTTP_SECURITY + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + HTTP_sec + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_DNS_SERVER + """ </h2>
                            <i class=""" + config.ICON_DNS_SERVER + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + dns_server_info + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_TLS_CIPHER_SUITES + """ </h2>
                            <i class=""" + config.ICON_TLS_CIPHER_SUITES + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + tls_cipher_suite + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_DNS_RECORDS + """ </h2>
                            <i class=""" + config.ICON_DNS_RECORDS + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + dns_info + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_TXT_RECORDS + """ </h2>
                            <i class=""" + config.ICON_TXT_RECORDS + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + txt_info + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_SERVER_STATUS + """ </h2>
                            <i class=""" + config.ICON_SERVER_STATUS + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + server_status_info + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_EMAIL_CONFIGURATION + """ </h2>
                            <i class=""" + config.ICON_EMAIL_CONFIGURATION + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + mail_configuration_info + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_REDIRECT_CHAIN + """ </h2>
                            <i class=""" + config.ICON_REDIRECT_CHAIN + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + redirect_Record + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_OPEN_PORTS + """ </h2>
                            <i class=""" + config.ICON_OPEN_PORTS + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + ports + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_ARCHIVE_HISTORY + """ </h2>
                            <i class=""" + config.ICON_ARCHIVE_HISTORY + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + archive_info + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_ASSOCIATED_HOSTS + """ </h2>
                            <i class=""" + config.ICON_ASSOCIATED_HOSTS + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + associated_info + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_BLOCK_DETECTION + """ </h2>
                            <i class=""" + config.ICON_BLOCK_DETECTION + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + block_info + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_CARBON_FOOTPRINT + """ </h2>
                            <i class=""" + config.ICON_CARBON_FOOTPRINT + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + carbon_info + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_CRAWL_RULES + """ </h2>
                            <i class=""" + config.ICON_CRAWL_RULES + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + crawl_info + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_SITE_FEATURES + """ </h2>
                            <i class=""" + config.ICON_SITE_FEATURES + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + site_info + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_DNS_SECURITY + """ </h2>
                            <i class=""" + config.ICON_DNS_SECURITY + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + dns_sec_info + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_TECH_STACK + """ </h2>
                            <i class=""" + config.ICON_TECH_STACK + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + tech_stack_info + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_FIREWALL_DETECTION + """ </h2>
                            <i class=""" + config.ICON_FIREWALL_DETECTION + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + firewall_info + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_SOCIAL_TAGS + """ </h2>
                            <i class=""" + config.ICON_SOCIAL_TAGS + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + social_tag_info + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_THREATS + """ </h2>
                            <i class=""" + config.ICON_THREATS + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + threats_info + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_GLOBAL_RANK + """ </h2>
                            <i class=""" + config.ICON_GLOBAL_RANK + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + global_ranking_info + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_SECURITY_TXT + """ </h2>
                            <i class=""" + config.ICON_SECURITY_TXT + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + security_txt_info + """</h4> 
                        </div>
                    </div>
                    """ )
        # Conditionally add NMAP section
        if nmap_ops:
            body += (
                """<div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_NMAP_OS_DETECT + """ </h2>
                            <i class=""" + config.ICON_NMAP_OS_DETECT + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + nmap_ops[0] + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_NMAP_PORT_SCAN + """ </h2>
                            <i class=""" + config.ICON_NMAP_PORT_SCAN + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + nmap_ops[2] + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_NMAP_HTTP_VULN + """ </h2>
                            <i class=""" + config.ICON_NMAP_HTTP_VULN + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + nmap_ops[4] + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_NMAP_SQL_INJECTION + """ </h2>
                            <i class=""" + config.ICON_NMAP_SQL_INJECTION + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + nmap_ops[6] + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_NMAP_XSS + """ </h2>
                            <i class=""" + config.ICON_NMAP_XSS + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + nmap_ops[8] + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_NMAP_SHELLSHOCK + """ </h2>
                            <i class=""" + config.ICON_NMAP_SHELLSHOCK + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + nmap_ops[10] + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_NMAP_RCE_EXPLOITS + """ </h2>
                            <i class=""" + config.ICON_NMAP_RCE_EXPLOITS + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + nmap_ops[12] + """</h4> 
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h2> """ + config.MODULE_NMAP_WEB_SERVER_CHECK + """ </h2>
                            <i class=""" + config.ICON_NMAP_WEB_SERVER_CHECK + """> </i> 
                        </div>
                        <div class="card-content">    
                            <h4>""" + nmap_ops[14] + """</h4> 
                        </div>
                    </div>"""
            )

        # Close the main content div
        body += """</div>"""
        footer = (f"""<footer class="footer">
                            <p>&copy; {config.YEAR} {config.SUMMARY_REPORT_FOTTER} </p>
                            <p>Generated by: <strong>{config.TOOL_NAME}</strong> | {config.SUMMARY_REPORT_TAG_LINE}</p>
                            <p>For more details, visit <a href={config.EMAIL} target="_blank" style="color: #007bff; text-decoration: none;">{config.EMAIL}</a></p>
                    </footer>
                  </body>
                </html>""")
                 
        # Close the Body & Main if Footer is not selected
        No_footer = ("""
                    </body>
                </html>""")

        # create and open the new WebKundli.html file
        if nmap_ops:
            html_report = "%s_%s_%s_%s.html" % (config.REPORT_FILE_NAME, self.domain, config.REPORT_NMAP_FILE_NAME, self.timestamp.strftime("%d%b%Y_%H-%M-%S"))
        else:    
            html_report = "%s_%s_%s.html" % (config.REPORT_FILE_NAME, self.domain, self.timestamp.strftime("%d%b%Y_%H-%M-%S"))

        html_report = os.path.join("./output", html_report)

        with open(html_report, "a", encoding="UTF-8") as f:
            f.write(header)
            f.write(body)

            if mode == 1:
                CSS = await self.dark_mode()
            else:
                CSS = await self.light_mode()
            f.write(CSS)
            
            if config.REPORT_FOOTER.upper() == "YES":
                f.write(footer)
            else:
                f.write(No_footer)

        if os.name == "nt":
            filenameH = html_report.partition("./output\\")[-1]
            os.system(f'start "" "{html_report}"')
        else:
            filenameH = html_report.partition("output/")[-1]
            os.system(f'xdg-open "{html_report}"')

        print(
            Fore.GREEN + Style.BRIGHT + f"\n📂 HTML Report" + Fore.WHITE + Style.BRIGHT,
            filenameH,
            Fore.GREEN + Style.BRIGHT + f"File Is Ready",
            Fore.RESET,
        )

    async def dark_mode(self):
        CSS = """<style>
                        body {
                            background-color: #1e1e1e;
                            color: #d4d4d4;
                            font-family: 'Cascadia Mono', 'Liberation Mono', 'Courier New', Courier, monospace;
                            margin: 0;
                            padding: 0;
                        }
                        .header {
                            background-color: #333;
                            padding: 10px;
                            display: flex;
                            align-items: center;
                            justify-content: space-between;
                            margin-right: 20px;
                            margin-left: 20px;
                            border-radius: 10px;
                        }
                        .header h1 {
                            color: #FFA500;
                            margin: 0;
                            font-size: 2.5em;
                        }
                        .header h2 {
                            color: #FFA500;
                            margin: 0;
                            font-size: 1.5em;
                        }
                        .header h3 {
                            color: #FFA500;
                            margin: 0;
                            font-size: 1em;
                        }
                        .header .icon {
                            color: #ffffff;
                            font-size: 60px;
                        }
                        .ranking-container {
                            background-color: #333;
                            display: flex;
                            align-items: center; /* Vertically align items */
                            justify-content: space-between; /* Space between header and progress bar */
                            margin-right: 20px;
                            margin-left: 20px;
                            border-radius: 10px;
                        }
                        .ranking-container h1 {
                            margin: 20px;
                            padding: 5px;
                            color: #ff00fb;
                        }
                        .ranking-container h2 {
                            font-size: 1.5em;
                            margin: 20px;
                            padding: 5px;
                        }
                        .progress-bar-container {
                            flex: 1; /* Allow progress bar to take available space */
                            background-color: #A9A9A9;
                            border-radius: 4px;
                            margin-left: 20px; /* Space between header and progress bar */
                            margin-right: 20px;
                            overflow: hidden;
                            border-radius: 5px;
                        }
                        .progress-bar {
                            height: 30px;
                            color: #FFFF00;
                            text-align: center;
                            line-height: 30px;
                            border-radius: 3px;
                            background-color: #8F00FF;  /* #76c7c0 Default color, adjust as needed */
                            transition: width 0.5s, background-color 0.5s;
                            font-size: 20px; /* Adjust font size as needed */
                            font-weight: bold; /* Makes the percentage text bold */
                        }
                        .progress {
                            height: 20px;
                            color: red;
                            text-align: center;
                            line-height: 20px;
                            border-radius: 4px;
                            background-color: #FFFF00; /* #76c7c0 Default color, adjust as needed */
                            transition: width 0.5s, background-color 0.5s;
                            font-size: 16px; /* Adjust font size as needed */
                            font-weight: bold; /* Makes the percentage text bold */
                            border-radius: 5px;
                        }
                        .date {
                            padding: 5px;
                            margin-right: 30px;
                        }
                        .date h3 {
                            color: #FFA500;
                            margin: 0;
                            font-size: 1em;
                        }
                        .content h4 {
                            margin: 0;
                            font-size: 0.9em;
                        }
                        .content {
                            display: flex;
                            flex-wrap: wrap;
                            padding: 10px;
                            border-radius: 10px;
                        }
                        .card {
                            background-color: #2d2d2d;
                            margin: 10px;
                            padding: 10px;
                            flex: 1;
                            min-width: 400px;
                            max-width: 200%;
                            border-radius: 5px;
                            position: relative;
                            overflow: hidden;
                            height: 450px; 
                            word-wrap: break-word;
                            border-radius: 10px;
                        }
                        .card-header {
                            position: sticky;
                            background-color: #333;
                            border-radius: 5px;
                            height: 50px;
                            text-align: center; 
                            border-top: 1px solid #333;
                            border-bottom: 0.5px solid #333;
                        }
                        .card-content {
                            max-height: 400px;
                            overflow-y: auto;
                        }
                        .card h2 {
                            color: #FFA500;
                            margin-top: 0;
                        }
                        .card h3 {
                            color: #FFA500;
                            margin-top: 0;
                            font-size: 1em;
                        }
                        .card flag-icon {
                            font-size: 10px; /* Size the flag */
                        }
                        .card .refresh {
                            position: absolute;
                            top: 10px;
                            right: 10px;
                            color: #00FF00;
                            font-size: 30px;
                        }
                        .card table {
                            width: 100%;
                            border-collapse: collapse;
                            table-layout: fixed;
                        }
                        .card table td {
                            padding: 5px;
                            border-bottom: 1px solid #444;
                            text-overflow: ellipsis; 
                            overflow: hidden;
                            word-wrap: break-word;
                        }
                        .card table td:last-child {
                            text-align: right;
                        }
                        .card .map {
                            width: 100%;
                            height: 100px;
                            background: url('https://placehold.co/300x200') no-repeat center center;
                            background-size: cover;
                        }
                        .footer{
                            background-color: #333; 
                            text-align: center; 
                            font-size: 14px; 
                            color: #ddd; 
                            border-top: 1px solid #383434;
                            border-bottom: 1px solid #383434;
                            margin-right: 20px;
                            margin-left: 20px;
                            border-radius: 10px;
                        }
                        .footer h3{
                            display: flex; 
                            flex-end; 
                            align-items: center;
                            color: black;
                        }
                        a {
                            color: #00FF00;
                            text-decoration: none; /* Remove underline */
                        }
                        /* Change color when hovering over the link */
                        a:hover {
                            color: red; /* Change color to red when hovered */
                        }
                </style> """
        return CSS

    async def light_mode(self):
        CSS = """<style>
                body {
                    background-color: #f9f9f9;
                    color: #1a1a1a;
                    font-family: 'Cascadia Mono', 'Liberation Mono', 'Courier New', Courier, monospace;
                    margin: 0;
                    padding: 0;
                }
                .header {
                    background-color: #ffffff;
                    padding: 10px;
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    margin-right: 20px;
                    margin-left: 20px;
                    border-radius: 10px;
                    border: 1px solid #ddd;
                }
                .header h1, .header h2, .header h3 {
                    color: #2c3e50;
                    margin: 0;
                }
                .header h1 { font-size: 2.5em; }
                .header h2 { font-size: 1.5em; }
                .header h3 { font-size: 1em; }
                .header .icon {
                    color: #06334c;
                    font-size: 60px;
                }
                .ranking-container {
                    background-color: #ffffff;
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    margin: 20px;
                    border-radius: 10px;
                    border: 1px solid #ddd;
                }
                .ranking-container h1 {
                    margin: 20px;
                    padding: 5px;
                    color: #0f0f10;
                }
                .ranking-container h2 {
                    font-size: 1.5em;
                    margin: 20px;
                    padding: 5px;
                }
                .progress-bar-container {
                    flex: 1;
                    background-color: #e0e0e0;
                    border-radius: 5px;
                    margin-left: 20px;
                    margin-right: 20px;
                    overflow: hidden;
                }
                .progress-bar {
                    height: 30px;
                    color: #fff;
                    text-align: center;
                    line-height: 30px;
                    border-radius: 3px;
                    background-color: #4caf50;
                    transition: width 0.5s, background-color 0.5s;
                    font-size: 20px;
                    font-weight: bold;
                }
                .progress {
                    height: 20px;
                    color: #fff;
                    text-align: center;
                    line-height: 20px;
                    border-radius: 5px;
                    background-color: #515153;
                    transition: width 0.5s, background-color 0.5s;
                    font-size: 16px;
                    font-weight: bold;
                }
                .date {
                    padding: 5px;
                    margin-right: 30px;
                }
                .date h3 {
                    color: #333;
                    margin: 0;
                    font-size: 1em;
                }
                .content h4 {
                    margin: 0;
                    font-size: 0.9em;
                }
                .content {
                    display: flex;
                    flex-wrap: wrap;
                    padding: 10px;
                    border-radius: 10px;
                }
                .card {
                    background-color: #fdfcfc;
                    margin: 10px;
                    padding: 10px;
                    flex: 1;
                    min-width: 400px;
                    max-width: 200%;
                    border-radius: 10px;
                    position: relative;
                    overflow: hidden;
                    height: 450px;
                    word-wrap: break-word;
                    border: 1px solid #ccc;
                }
                .card-header {
                    position: sticky;
                    background-color: #e9e1e1;
                    border-radius: 5px;
                    height: 50px;
                    text-align: center; 
                    border-top: 1px solid #ccc;
                    border-bottom: 0.5px solid #ccc;
                }
                .card-content {
                    max-height: 400px;
                    overflow-y: auto;
                }
                .card h2, .card h3 {
                    color: #0e0e12;
                    margin-bottom: 10px;
                    margin-top: 10px;
                }
                .card h3 {
                    font-size: 1em;
                }
                .card flag-icon {
                    font-size: 10px;
                }
                .card .refresh {
                    position: absolute;
                    top: 10px;
                    right: 10px;
                    color: #388e3c;
                    font-size: 30px;
                }
                .card table {
                    width: 100%;
                    border-collapse: collapse;
                    table-layout: fixed;
                }
                .card table td {
                    padding: 5px;
                    border-bottom: 1px solid #e0e0e0;
                    text-overflow: ellipsis;
                    overflow: hidden;
                    word-wrap: break-word;
                }
                .card table td:last-child {
                    text-align: right;
                }
                .card .map {
                    width: 100%;
                    height: 100px;
                    background: url('https://placehold.co/300x200?text=Map') no-repeat center center;
                    background-size: cover;
                }
                .footer {
                    background-color: #f0f0f0;
                        text-align: center;
                        font-size: 14px;
                        color: #666;
                        border-top: 1px solid #ccc;
                        border-bottom: 1px solid #ccc;
                    margin-right: 20px;
                    margin-left: 20px;
                    border-radius: 10px;
                }
                .footer h3 {
                    display: flex;
                    align-items: center;
                    color: #555;
                }
                a {
                    color: #1e88e5;
                    text-decoration: none;
                }
                a:hover {
                    color: #1565c0;
                }
            </style>"""
        return CSS
