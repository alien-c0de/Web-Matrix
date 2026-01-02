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
                    <h2 align="right"; margin-right: 40px; style="color:rgb(214, 214, 238);"> <a href= "{website}" target="_blank"> {website} </a></h2>
                </div>
                <div class="date">
                    <h3 align="right"; margin-right: 20px; style="color:whitesmoke;"><i class="far fa-clock"></i> Report Generated: {report_timestamp}</h3>
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
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
            @import url('https://fonts.googleapis.com/css2?family=Cascadia+Mono:wght@400;600;700&display=swap');
            
            :root {
                --primary-color: #00ff88;
                --secondary-color: #ff00ff;
                --accent-color: #00d4ff;
                --bg-dark: #0a0e1a;
                --bg-card: #1a1f35;
                --bg-header: #0f1420;
                --text-primary: #e4e6eb;
                --text-secondary: #a8aab7;
                --border-color: #2d3548;
                --success: #00ff88;
                --warning: #ffaa00;
                --danger: #ff4757;
                --shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
            }
            
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                background: linear-gradient(135deg, var(--bg-dark) 0%, #0f1828 100%);
                color: var(--text-primary);
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                line-height: 1.6;
                min-height: 100vh;
                padding: 20px;
            }
            
            /* Header Styling */
            .header {
                background: linear-gradient(135deg, #1a1f35 0%, #0f1420 100%);
                border: 1px solid var(--border-color);
                border-radius: 16px;
                padding: 10px 20px;
                margin: 0 10px 20px;
                box-shadow: var(--shadow);
                position: relative;
                overflow: hidden;
            }
            
            .header::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 4px;
                background: linear-gradient(90deg, var(--primary-color), var(--secondary-color), var(--accent-color));
            }
            
            .header h1 {
                color: var(--primary-color);
                font-size: 2.5em;
                font-weight: 800;
                margin-bottom: 15px;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 15px;
            }
            
            .header h2 {
                color: var(--accent-color);
                font-size: 1.5em;
                font-weight: 600;
                text-align: right;
                margin-top: 10px;
            }
            
            .header h2 a {
                color: var(--accent-color);
                text-decoration: none;
                transition: all 0.3s ease;
                padding: 8px 16px;
                border-radius: 8px;
                background: rgba(0, 212, 255, 0.1);
            }
            
            .header h2 a:hover {
                background: rgba(0, 212, 255, 0.2);
                transform: translateY(-2px);
            }
            
            .header .icon {
                color: var(--primary-color);
                font-size: 48px;
                filter: drop-shadow(0 0 10px rgba(0, 255, 136, 0.5));
            }
            
            /* Date Section */
            .date {
                margin: 0 40px 20px;
            }
            
            .date h3 {
                color: var(--text-secondary);
                font-size: 0.95em;
                font-weight: 500;
                display: flex;
                align-items: center;
                gap: 8px;
                justify-content: flex-end;
            }
            
            /* Ranking Container */
            .ranking-container {
                background: linear-gradient(135deg, #1a1f35 0%, #0f1420 100%);
                border: 1px solid var(--border-color);
                border-radius: 16px;
                padding: 20px 30px;
                margin: 0 20px 30px;
                box-shadow: var(--shadow);
                display: flex;
                align-items: center;
                gap: 30px;
            }
            
            .ranking-container h1 {
                color: var(--secondary-color);
                font-size: 1.5em;
                font-weight: 700;
                white-space: nowrap;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            
            .ranking-container h2 {
                font-size: 1.1em;
                font-weight: 600;
                white-space: nowrap;
            }
            
            .ranking-container h2 a {
                color: var(--primary-color);
                text-decoration: none;
                padding: 10px 20px;
                border-radius: 8px;
                background: rgba(0, 255, 136, 0.1);
                border: 1px solid rgba(0, 255, 136, 0.3);
                transition: all 0.3s ease;
            }
            
            .ranking-container h2 a:hover {
                background: rgba(0, 255, 136, 0.2);
                transform: translateY(-2px);
                box-shadow: 0 4px 12px rgba(0, 255, 136, 0.3);
            }
            
            .progress-bar-container {
                flex: 1;
                background: rgba(255, 255, 255, 0.05);
                border-radius: 12px;
                overflow: hidden;
                height: 30px;
                border: 1px solid var(--border-color);
                position: relative;
            }
            
            .progress-bar {
                height: 100%;
                background: linear-gradient(90deg, #00ff88, #00ffff);
                color: #000000;
                text-align: center;
                line-height: 30px;
                font-size: 18px;
                font-weight: 700;
                transition: width 1s cubic-bezier(0.4, 0, 0.2, 1);
                position: relative;
                overflow: hidden;
                text-shadow: 1px 1px 2px rgba(255, 255, 255, 0.5);
            }
            
            .progress-bar::after {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: linear-gradient(90deg, 
                    transparent, 
                    rgba(255, 255, 255, 0.4), 
                    transparent
                );
                animation: shimmer 2s infinite;
            }
            
            @keyframes shimmer {
                0% { transform: translateX(-100%); }
                100% { transform: translateX(100%); }
            }
            
            /* Content Grid */
            .content {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(450px, 1fr));
                gap: 24px;
                padding: 0 20px;
            }
            
            /* Card Styling */
            .card {
                background: linear-gradient(135deg, var(--bg-card) 0%, #14182c 100%);
                border: 1px solid var(--border-color);
                border-radius: 16px;
                padding: 0;
                height: 480px;
                display: flex;
                flex-direction: column;
                box-shadow: var(--shadow);
                transition: all 0.3s ease;
                position: relative;
                overflow: hidden;
            }
            
            .card::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 3px;
                background: linear-gradient(90deg, var(--primary-color), var(--accent-color));
                opacity: 0;
                transition: opacity 0.3s ease;
            }
            
            .card:hover {
                transform: translateY(-4px);
                box-shadow: 0 12px 40px rgba(0, 0, 0, 0.5);
                border-color: var(--primary-color);
            }
            
            .card:hover::before {
                opacity: 1;
            }
            
            .card-header {
                background: rgba(0, 0, 0, 0.3);
                padding: 20px 24px;
                border-bottom: 1px solid var(--border-color);
                display: flex;
                align-items: center;
                justify-content: space-between;
                min-height: 70px;
            }
            
            .card-header h2 {
                color: var(--primary-color);
                font-size: 1.2em;
                font-weight: 600;
                flex: 1;
                font-family: 'Cascadia Mono', 'Courier New', monospace;
                letter-spacing: 0.5px;
            }
            
            .card-header i {
                color: var(--accent-color);
                font-size: 28px;
                opacity: 0.8;
            }
            
            .card-content {
                padding: 24px;
                overflow-y: auto;
                overflow-x: hidden;
                flex: 1;
                font-size: 0.95em;
                word-wrap: break-word;
                overflow-wrap: break-word;
            }
            
            .card-content::-webkit-scrollbar {
                width: 8px;
            }
            
            .card-content::-webkit-scrollbar-track {
                background: rgba(255, 255, 255, 0.05);
                border-radius: 4px;
            }
            
            .card-content::-webkit-scrollbar-thumb {
                background: var(--primary-color);
                border-radius: 4px;
            }
            
            .card-content::-webkit-scrollbar-thumb:hover {
                background: var(--accent-color);
            }
            
            .card h4 {
                color: var(--text-primary);
                line-height: 1.7;
                font-weight: 400;
                word-wrap: break-word;
                overflow-wrap: break-word;
                white-space: normal;
            }
            
            /* Progress bars inside cards */
            .progress {
                background: linear-gradient(90deg, #e2bf7d, #e08f24);
                height: 100%;
                color: #000000;
                text-align: center;
                line-height: 30px;
                font-size: 15px;
                font-weight: 700;
                transition: width 1s cubic-bezier(0.4, 0, 0.2, 1);
                position: relative;
                overflow: hidden;
                text-shadow: 1px 1px 2px rgba(255, 255, 255, 0.5);
            }

            /* Tables */
            .card table {
                width: 100%;
                border-collapse: collapse;
                table-layout: fixed;
            }
            
            .card table td {
                padding: 12px 8px;
                border-bottom: 1px solid rgba(255, 255, 255, 0.05);
                font-size: 0.9em;
                word-wrap: break-word;
                overflow-wrap: break-word;
                white-space: normal;
            }
            
            .card table td:first-child {
                color: var(--text-secondary);
                font-weight: 500;
                width: 35%;
            }
            
            .card table td:last-child {
                color: var(--text-primary);
                text-align: right;
                font-weight: 400;
                width: 65%;
            }
            
            /* Footer */
            .footer {
                background: linear-gradient(135deg, #1a1f35 0%, #0f1420 100%);
                border: 1px solid var(--border-color);
                border-radius: 16px;
                padding: 5px;
                margin: 15px 10px 10px;
                text-align: center;
                box-shadow: var(--shadow);
            }
            
            .footer p {
                color: var(--text-secondary);
                margin: 4px 0;
                font-size: 0.95em;
            }
            
            .footer strong {
                color: var(--primary-color);
                font-weight: 600;
            }
            
            .footer a {
                color: var(--accent-color);
                text-decoration: none;
                transition: color 0.3s ease;
            }
            
            .footer a:hover {
                color: var(--primary-color);
            }
            
            /* Links */
            a {
                color: var(--primary-color);
                text-decoration: none;
                transition: all 0.3s ease;
                word-wrap: break-word;
            }
            
            a:hover {
                color: var(--accent-color);
            }
            
            /* Responsive Design */
            @media (max-width: 1200px) {
                .content {
                    grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
                }
            }
            
            @media (max-width: 768px) {
                body {
                    padding: 10px;
                }
                
                .header, .ranking-container, .footer {
                    margin: 0 10px 20px;
                    padding: 20px;
                }
                
                .header h1 {
                    font-size: 1.8em;
                }
                
                .ranking-container {
                    flex-direction: column;
                    gap: 15px;
                }
                
                .content {
                    grid-template-columns: 1fr;
                    padding: 0 10px;
                }
                
                .card {
                    height: auto;
                    min-height: 400px;
                }
            }
            
            /* Loading Animation */
            @keyframes fadeIn {
                from {
                    opacity: 0;
                    transform: translateY(20px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            
            .card {
                animation: fadeIn 0.5s ease-out backwards;
            }
            
            .card:nth-child(1) { animation-delay: 0.05s; }
            .card:nth-child(2) { animation-delay: 0.1s; }
            .card:nth-child(3) { animation-delay: 0.15s; }
            .card:nth-child(4) { animation-delay: 0.2s; }
            .card:nth-child(5) { animation-delay: 0.25s; }
            .card:nth-child(6) { animation-delay: 0.3s; }
        </style>"""
        return CSS

    async def light_mode(self):
        CSS = """<style>
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
            @import url('https://fonts.googleapis.com/css2?family=Cascadia+Mono:wght@400;600;700&display=swap');
            
            :root {
                --primary-color: #0066ff;
                --secondary-color: #7c3aed;
                --accent-color: #0891b2;
                --bg-light: #f8fafc;
                --bg-card: #ffffff;
                --bg-header: #ffffff;
                --text-primary: #1e293b;
                --text-secondary: #64748b;
                --border-color: #e2e8f0;
                --success: #10b981;
                --warning: #f59e0b;
                --danger: #ef4444;
                --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            }
            
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                background: linear-gradient(135deg, #f8fafc 0%, #e0e7ff 100%);
                color: var(--text-primary);
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                line-height: 1.6;
                min-height: 100vh;
                padding: 20px;
            }
            
            /* Header Styling */
            .header {
                background: var(--bg-header);
                border: 1px solid var(--border-color);
                border-radius: 16px;
                padding: 30px 40px;
                margin: 0 20px 30px;
                box-shadow: var(--shadow);
                position: relative;
                overflow: hidden;
            }
            
            .header::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 4px;
                background: linear-gradient(90deg, var(--primary-color), var(--secondary-color), var(--accent-color));
            }
            
            .header h1 {
                color: var(--primary-color);
                font-size: 2.5em;
                font-weight: 800;
                margin-bottom: 15px;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 15px;
            }
            
            .header h2 {
                color: var(--secondary-color);
                font-size: 1.5em;
                font-weight: 600;
                text-align: right;
                margin-top: 10px;
            }
            
            .header h2 a {
                color: var(--secondary-color);
                text-decoration: none;
                transition: all 0.3s ease;
                padding: 8px 16px;
                border-radius: 8px;
                background: rgba(124, 58, 237, 0.1);
            }
            
            .header h2 a:hover {
                background: rgba(124, 58, 237, 0.2);
                transform: translateY(-2px);
            }
            
            .header .icon {
                color: var(--primary-color);
                font-size: 48px;
            }
            
            /* Date Section */
            .date {
                margin: 0 40px 20px;
            }
            
            .date h3 {
                color: var(--text-secondary);
                font-size: 0.95em;
                font-weight: 500;
                display: flex;
                align-items: center;
                gap: 8px;
                justify-content: flex-end;
            }
            
            /* Ranking Container */
            .ranking-container {
                background: var(--bg-card);
                border: 1px solid var(--border-color);
                border-radius: 16px;
                padding: 20px 30px;
                margin: 0 20px 30px;
                box-shadow: var(--shadow);
                display: flex;
                align-items: center;
                gap: 30px;
            }
            
            .ranking-container h1 {
                color: var(--secondary-color);
                font-size: 1.5em;
                font-weight: 700;
                white-space: nowrap;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            
            .ranking-container h2 {
                font-size: 1.1em;
                font-weight: 600;
                white-space: nowrap;
            }
            
            .ranking-container h2 a {
                color: var(--primary-color);
                text-decoration: none;
                padding: 10px 20px;
                border-radius: 8px;
                background: rgba(0, 102, 255, 0.1);
                border: 1px solid rgba(0, 102, 255, 0.2);
                transition: all 0.3s ease;
            }
            
            .ranking-container h2 a:hover {
                background: rgba(0, 102, 255, 0.2);
                transform: translateY(-2px);
                box-shadow: 0 4px 12px rgba(0, 102, 255, 0.2);
            }
            
            .progress-bar-container {
                flex: 1;
                background: #f1f5f9;
                border-radius: 12px;
                overflow: hidden;
                height: 30px;
                border: 1px solid var(--border-color);
                position: relative;
            }
            
            .progress-bar {
                height: 100%;
                background: linear-gradient(90deg, #0066ff, #00bcd4);
                color: white;
                text-align: center;
                line-height: 30px;
                font-size: 18px;
                font-weight: 700;
                transition: width 1s cubic-bezier(0.4, 0, 0.2, 1);
                position: relative;
                overflow: hidden;
                text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.3);
            }
            
            .progress-bar::after {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: linear-gradient(90deg, 
                    transparent, 
                    rgba(255, 255, 255, 0.3), 
                    transparent
                );
                animation: shimmer 2s infinite;
            }
            
            @keyframes shimmer {
                0% { transform: translateX(-100%); }
                100% { transform: translateX(100%); }
            }
            
            /* Content Grid */
            .content {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(450px, 1fr));
                gap: 24px;
                padding: 0 20px;
            }
            
            /* Card Styling */
            .card {
                background: var(--bg-card);
                border: 1px solid var(--border-color);
                border-radius: 16px;
                padding: 0;
                height: 480px;
                display: flex;
                flex-direction: column;
                box-shadow: var(--shadow);
                transition: all 0.3s ease;
                position: relative;
                overflow: hidden;
            }
            
            .card::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 3px;
                background: linear-gradient(90deg, var(--primary-color), var(--accent-color));
                opacity: 0;
                transition: opacity 0.3s ease;
            }
            
            .card:hover {
                transform: translateY(-4px);
                box-shadow: 0 12px 24px -4px rgba(0, 0, 0, 0.12), 0 8px 16px -4px rgba(0, 0, 0, 0.08);
                border-color: var(--primary-color);
            }
            
            .card:hover::before {
                opacity: 1;
            }
            
            .card-header {
                background: #f8fafc;
                padding: 20px 24px;
                border-bottom: 1px solid var(--border-color);
                display: flex;
                align-items: center;
                justify-content: space-between;
                min-height: 70px;
            }
            
            .card-header h2 {
                color: var(--primary-color);
                font-size: 1.2em;
                font-weight: 600;
                flex: 1;
                font-family: 'Cascadia Mono', 'Courier New', monospace;
                letter-spacing: 0.5px;
            }
            
            .card-header i {
                color: var(--accent-color);
                font-size: 28px;
                opacity: 0.8;
            }
            
            .card-content {
                padding: 24px;
                overflow-y: auto;
                overflow-x: hidden;
                flex: 1;
                font-size: 0.95em;
                word-wrap: break-word;
                overflow-wrap: break-word;
            }
            
            .card-content::-webkit-scrollbar {
                width: 8px;
            }
            
            .card-content::-webkit-scrollbar-track {
                background: #f1f5f9;
                border-radius: 4px;
            }
            
            .card-content::-webkit-scrollbar-thumb {
                background: var(--primary-color);
                border-radius: 4px;
            }
            
            .card-content::-webkit-scrollbar-thumb:hover {
                background: var(--accent-color);
            }
            
            .card h4 {
                color: var(--text-primary);
                line-height: 1.7;
                font-weight: 400;
                word-wrap: break-word;
                overflow-wrap: break-word;
                white-space: normal;
            }
            
            /* Progress bars inside cards */
            .progress {
                height: 24px;
                background: linear-gradient(90deg, #00ff88, #00d4ff);
                border-radius: 6px;
                margin: 1px 0;
                border: 1px solid var(--border-color);
                color: #000;
                text-align: center;
                line-height: 24px;
                font-size: 15px;
                font-weight: 700;
                transition: width 0.8s ease;
                box-shadow: inset 0 0 6px rgba(0, 0, 0, 0.4);
            }
            
            # .progress > div {
            #     height: 100%;
            #     background: linear-gradient(90deg, #0066ff, #00bcd4);
            #     color: white;
            #     text-align: center;
            #     line-height: 24px;
            #     font-size: 13px;
            #     font-weight: 700;
            #     transition: width 0.8s ease;
            #     text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.3);
            # }
            
            /* Tables */
            .card table {
                width: 100%;
                border-collapse: collapse;
                table-layout: fixed;
            }
            
            .card table td {
                padding: 12px 8px;
                border-bottom: 1px solid #f1f5f9;
                font-size: 0.9em;
                word-wrap: break-word;
                overflow-wrap: break-word;
                white-space: normal;
            }
            
            .card table td:first-child {
                color: var(--text-secondary);
                font-weight: 500;
                width: 35%;
            }
            
            .card table td:last-child {
                color: var(--text-primary);
                text-align: right;
                font-weight: 400;
                width: 65%;
            }
            
            /* Footer */
            .footer {
                background: var(--bg-card);
                border: 1px solid var(--border-color);
                border-radius: 16px;
                padding: 30px;
                margin: 30px 20px 20px;
                text-align: center;
                box-shadow: var(--shadow);
            }
            
            .footer p {
                color: var(--text-secondary);
                margin: 8px 0;
                font-size: 0.95em;
            }
            
            .footer strong {
                color: var(--primary-color);
                font-weight: 600;
            }
            
            .footer a {
                color: var(--accent-color);
                text-decoration: none;
                transition: color 0.3s ease;
            }
            
            .footer a:hover {
                color: var(--primary-color);
            }
            
            /* Links */
            a {
                color: var(--primary-color);
                text-decoration: none;
                transition: all 0.3s ease;
                word-wrap: break-word;
            }
            
            a:hover {
                color: var(--accent-color);
            }
            
            /* Responsive Design */
            @media (max-width: 1200px) {
                .content {
                    grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
                }
            }
            
            @media (max-width: 768px) {
                body {
                    padding: 10px;
                }
                
                .header, .ranking-container, .footer {
                    margin: 0 10px 20px;
                    padding: 20px;
                }
                
                .header h1 {
                    font-size: 1.8em;
                }
                
                .ranking-container {
                    flex-direction: column;
                    gap: 15px;
                }
                
                .content {
                    grid-template-columns: 1fr;
                    padding: 0 10px;
                }
                
                .card {
                    height: auto;
                    min-height: 400px;
                }
            }
            
            /* Loading Animation */
            @keyframes fadeIn {
                from {
                    opacity: 0;
                    transform: translateY(20px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            
            .card {
                animation: fadeIn 0.5s ease-out backwards;
            }
            
            .card:nth-child(1) { animation-delay: 0.05s; }
            .card:nth-child(2) { animation-delay: 0.1s; }
            .card:nth-child(3) { animation-delay: 0.15s; }
            .card:nth-child(4) { animation-delay: 0.2s; }
            .card:nth-child(5) { animation-delay: 0.25s; }
            .card:nth-child(6) { animation-delay: 0.3s; }
        </style>"""
        return CSS