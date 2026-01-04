import os
from colorama import Back, Fore, Style
from util.config_uti import Configuration

class Analysis_Report:
    def __init__(self, domain, timestamp):
        self.domain = domain
        self.timestamp = timestamp

    async def Generate_Analysis_Report(self, website, cookies, server_location, server_info, SSL_Cert, Archive, Asso_Host, Block_Detect,
                            CO2_print, crawl_rule, DNS_Security, DNS_Server, whois, http_security, web_header, firewall, global_rank,
                            open_ports, redirect_chain, security_TXT, server_status, site_feature, social_tags, tech_stack, threats,
                            dns_records, txt_records, tls_cipher_suit, email_config, nmap_ops):

        config = Configuration()
        report_timestamp = self.timestamp.strftime("%A %d-%b-%Y %H:%M:%S")

        header = ("""<!DOCTYPE html>
                        <html lang="en">
                        <head>
                            <meta charset="UTF-8">
                            <meta name="viewport" content="width=device-width, initial-scale=1.0">
                            <title>Web Security Analysis Report - """ + self.domain + """</title>
                            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
                            <style>
                                * {
                                    margin: 0;
                                    padding: 0;
                                    box-sizing: border-box;
                                }
                                
                                body {
                                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                                    color: #2d3748;
                                    padding: 40px 20px;
                                    line-height: 1.6;
                                    min-height: 100vh;
                                }
                                
                                .container {
                                    max-width: 1400px;
                                    margin: 0 auto;
                                    background: #ffffff;
                                    border-radius: 16px;
                                    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
                                    overflow: hidden;
                                }
                                
                                .header {
                                    background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
                                    color: #ffffff;
                                    padding: 20px;
                                    position: relative;
                                    overflow: hidden;
                                }
                                
                                .header::before {
                                    content: '';
                                    position: absolute;
                                    top: -50%;
                                    right: -50%;
                                    width: 200%;
                                    height: 200%;
                                    background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
                                    animation: pulse 15s ease-in-out infinite;
                                }
                                
                                @keyframes pulse {
                                    0%, 100% { transform: scale(1); opacity: 0.5; }
                                    50% { transform: scale(1.1); opacity: 0.8; }
                                }
                                
                                .header-content {
                                    position: relative;
                                    z-index: 1;
                                }
                                
                                .header-top {
                                    display: flex;
                                    align-items: center;
                                    justify-content: center;
                                    gap: 20px;
                                    margin-bottom: 20px;
                                }
                                
                                .header-icon {
                                    font-size: 48px;
                                    color: #fbbf24;
                                    filter: drop-shadow(0 4px 6px rgba(0,0,0,0.3));
                                }
                                
                                .header h1 {
                                    font-size: 36px;
                                    font-weight: 700;
                                    letter-spacing: -0.5px;
                                    margin: 0;
                                }
                                
                                .header h2 {
                                    font-size: 20px;
                                    font-weight: 400;
                                    opacity: 0.9;
                                    margin: 8px 0;
                                    text-align: center;
                                }
                                
                                .website-link-container {
                                    text-align: right;
                                    margin-top: 15px;
                                }
                                
                                .header h3 a {
                                    color: #fbbf24;
                                    text-decoration: none;
                                    font-size: 18px;
                                    font-weight: 500;
                                    display: inline-flex;
                                    align-items: center;
                                    gap: 8px;
                                    transition: all 0.3s ease;
                                    padding: 8px 16px;
                                    background: rgba(251, 191, 36, 0.1);
                                    border-radius: 8px;
                                    border: 1px solid rgba(251, 191, 36, 0.3);
                                }
                                
                                .header h3 a:hover {
                                    background: rgba(251, 191, 36, 0.2);
                                    transform: translateX(4px);
                                }
                                
                                .timestamp {
                                    display: flex;
                                    align-items: center;
                                    justify-content: flex-end;
                                    gap: 10px;
                                    padding: 20px 40px;
                                    background: #f7fafc;
                                    border-bottom: 2px solid #e2e8f0;
                                    font-size: 14px;
                                    color: #4a5568;
                                }
                                
                                .timestamp i {
                                    color: #667eea;
                                    font-size: 16px;
                                }
                                
                                .content-wrapper {
                                    padding: 40px;
                                }
                                
                                .score-section {
                                    background: linear-gradient(135deg, #f7fafc 0%, #edf2f7 100%);
                                    border-radius: 12px;
                                    padding: 20px;
                                    margin-bottom: 20px;
                                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
                                }
                                
                                .score-header {
                                    display: flex;
                                    align-items: center;
                                    gap: 15px;
                                    margin-bottom: 25px;
                                }
                                
                                .score-header i {
                                    font-size: 36px;
                                    color: #667eea;
                                }
                                
                                .score-header h2 {
                                    font-size: 24px;
                                    color: #2d3748;
                                }
                                
                                .score-value {
                                    font-size: 48px;
                                    font-weight: 700;
                                    color: #667eea;
                                }
                                
                                .score-legend {
                                    display: grid;
                                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                                    gap: 15px;
                                    margin-top: 25px;
                                }
                                
                                .legend-item {
                                    display: flex;
                                    align-items: center;
                                    gap: 12px;
                                    padding: 12px 16px;
                                    background: white;
                                    border-radius: 8px;
                                    border-left: 4px solid;
                                    transition: all 0.3s ease;
                                }
                                
                                .legend-item:hover {
                                    transform: translateX(4px);
                                    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
                                }
                                
                                .legend-excellent { border-color: #10b981; }
                                .legend-moderate { border-color: #f59e0b; }
                                .legend-poor { border-color: #ef4444; }
                                .legend-very-poor { border-color: #dc2626; }
                                
                                .legend-icon {
                                    font-size: 24px;
                                }
                                
                                .legend-text {
                                    font-size: 14px;
                                    color: #4a5568;
                                }
                                
                                .legend-text strong {
                                    display: block;
                                    color: #2d3748;
                                    font-size: 15px;
                                    margin-bottom: 2px;
                                }
                                
                                .score-display {
                                    margin-top: 15px;
                                    padding: 15px;
                                    border-radius: 12px;
                                    text-align: center;
                                    color: white;
                                    font-size: 24px;
                                    font-weight: 600;
                                    box-shadow: 0 8px 16px rgba(0, 0, 0, 0.15);
                                    transition: all 0.3s ease;
                                }
                                
                                .excellent { 
                                    background: linear-gradient(135deg, #10b981 0%, #059669 100%);
                                }
                                .moderate { 
                                    background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
                                }
                                .poor { 
                                    background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
                                }
                                .very-poor { 
                                    background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);
                                }
                                
                                .section {
                                    background: white;
                                    border-radius: 12px;
                                    padding: 25px;
                                    margin-bottom: 20px;
                                    border: 1px solid #e2e8f0;
                                    transition: all 0.3s ease;
                                }
                                
                                .section:hover {
                                    box-shadow: 0 8px 16px rgba(0, 0, 0, 0.08);
                                    transform: translateY(-2px);
                                }
                                
                                .section h2, .section h3 {
                                    color: #2d3748;
                                    margin-bottom: 15px;
                                    display: flex;
                                    align-items: center;
                                    gap: 12px;
                                }
                                
                                .section h2 {
                                    font-size: 20px;
                                    padding-bottom: 12px;
                                    border-bottom: 2px solid #e2e8f0;
                                }
                                
                                .section h3 {
                                    font-size: 16px;
                                    color: #4a5568;
                                }
                                
                                .issues {
                                    background: linear-gradient(135deg, #fee2e2 0%, #fecaca 100%);
                                    border-left: 4px solid #ef4444;
                                    padding: 16px;
                                    margin: 12px 0;
                                    border-radius: 8px;
                                }
                                
                                .suggestions {
                                    background: linear-gradient(135deg, #d1fae5 0%, #a7f3d0 100%);
                                    border-left: 4px solid #10b981;
                                    padding: 16px;
                                    margin: 12px 0;
                                    border-radius: 8px;
                                }
                                
                                .issues h4, .suggestions h4 {
                                    font-size: 15px;
                                    margin-bottom: 10px;
                                    color: #2d3748;
                                }
                                
                                ul {
                                    margin: 8px 0;
                                    padding-left: 24px;
                                }
                                
                                ul li {
                                    margin: 6px 0;
                                    color: #4a5568;
                                }
                                
                                footer {
                                    text-align: center;
                                    padding: 30px;
                                    background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
                                    color: white;
                                    font-size: 14px;
                                }
                                
                                footer a {
                                    color: #fbbf24;
                                    text-decoration: none;
                                }
                                
                                @media print {
                                    body {
                                        background: white;
                                        padding: 0;
                                    }
                                    .container {
                                        box-shadow: none;
                                    }
                                    .section:hover {
                                        transform: none;
                                        box-shadow: none;
                                    }
                                }
                                
                                @media (max-width: 768px) {
                                    body {
                                        padding: 20px 10px;
                                    }
                                    .header {
                                        padding: 30px 20px;
                                    }
                                    .content-wrapper {
                                        padding: 20px;
                                    }
                                    .header h1 {
                                        font-size: 24px;
                                    }
                                    .score-legend {
                                        grid-template-columns: 1fr;
                                    }
                                    .header-top {
                                        flex-direction: column;
                                        text-align: center;
                                    }
                                    .website-link-container {
                                        text-align: center;
                                    }
                                    .timestamp {
                                        justify-content: center;
                                        text-align: center;
                                    }
                                }
                            </style>
                        </head>""")
        
        script = ("""<script>
                    function getURLParameter(name) {
                        const urlParams = new URLSearchParams(window.location.search);
                        return urlParams.get(name);
                    }

                    function displayValueAndCategorize() {
                        const reportValue = getURLParameter('report');
                        let scoreValue = document.getElementById('passedValue');
                        let scoreDisplay = document.getElementById("scoreDisplay");
                        let healthStatus = document.getElementById("healthStatus");

                        if (reportValue) {
                            let numericScore = parseFloat(reportValue);
                            scoreValue.innerText = numericScore.toFixed(2);
                            categorizeHealth(numericScore);
                        } else {
                            scoreValue.innerText = 'N/A';
                            healthStatus.innerText = "No Score Available";
                            scoreDisplay.className = "score-display moderate";
                        }
                    }

                    function categorizeHealth(score) {
                        let container = document.getElementById("scoreDisplay");
                        let statusText = document.getElementById("healthStatus");

                        if (score >= 80) {
                            statusText.innerText = "Excellent Security Posture";
                            container.className = "score-display excellent";
                        } else if (score >= 60) {
                            statusText.innerText = "Moderate Security Status";
                            container.className = "score-display moderate";
                        } else if (score >= 40) {
                            statusText.innerText = "Poor Security Status";
                            container.className = "score-display poor";
                        } else {
                            statusText.innerText = "Critical Security Issues";
                            container.className = "score-display very-poor";
                        }
                    }
                    
                    window.addEventListener('load', displayValueAndCategorize);
                </script>""")
        
        body = ("""<body>
                    <div class="container">
                        <div class="header">
                            <div class="header-content">
                                <div class="header-top">
                                    <i class="fas fa-shield-alt header-icon"></i>
                                    <div>
                                        <h1>""" + config.REPORT_HEADER + """</h1>
                                        <h2>""" + config.ANALYSIS_REPORT_HEADER + """</h2>
                                    </div>
                                </div>
                                <div class="website-link-container">
                                    <h3>
                                        <a href=""" + website + """ target="_blank">
                                            <i class="fas fa-external-link-alt"></i>
                                            """ + website + """
                                        </a>
                                    </h3>
                                </div>
                            </div>
                        </div>
                        
                        <div class="timestamp">
                            <i class="far fa-clock"></i>
                            <strong>Report Generated:</strong> """  + report_timestamp + """
                        </div>
                        
                        <div class="content-wrapper">
                            <div class="score-section">
                                <div class="score-header">
                                    <i class="fas fa-chart-line"></i>
                                    <div>
                                        <h2>Overall Security Score</h2>
                                        <div class="score-value"><span id="passedValue"></span>%</div>
                                    </div>
                                </div>
                                
                                <div class="score-legend">
                                    <div class="legend-item legend-excellent">
                                        <span class="legend-icon">✅</span>
                                        <div class="legend-text">
                                            <strong>80%+ Excellent</strong>
                                            Well-optimized with minimal issues
                                        </div>
                                    </div>
                                    <div class="legend-item legend-moderate">
                                        <span class="legend-icon">⚠️</span>
                                        <div class="legend-text">
                                            <strong>60-79% Moderate</strong>
                                            Needs some improvements
                                        </div>
                                    </div>
                                    <div class="legend-item legend-poor">
                                        <span class="legend-icon">❌</span>
                                        <div class="legend-text">
                                            <strong>40-59% Poor</strong>
                                            Several issues require attention
                                        </div>
                                    </div>
                                    <div class="legend-item legend-very-poor">
                                        <span class="legend-icon">🚨</span>
                                        <div class="legend-text">
                                            <strong>Below 40% Critical</strong>
                                            Urgent action needed
                                        </div>
                                    </div>
                                </div>
                                
                                <div id="scoreDisplay" class="score-display">
                                    <i class="fas fa-heartbeat"></i> <span id="healthStatus"></span>
                                </div>
                            </div>
                            
                            """ + server_location + """
                            """ + SSL_Cert + """
                            """ + whois + """
                            """ + server_info + """
                            """ + web_header + """
                            """ + cookies + """
                            """ + http_security + """
                            """ + DNS_Server + """
                            """ + tls_cipher_suit + """
                            """ + dns_records + """
                            """ + txt_records + """ 
                            """ + server_status + """
                            """ + email_config + """
                            """ + redirect_chain + """
                            """ + open_ports + """
                            """ + Archive + """
                            """ + Asso_Host + """
                            """ + Block_Detect + """
                            """ + CO2_print + """
                            """ + crawl_rule + """
                            """ + site_feature + """
                            """ + DNS_Security + """
                            """ + tech_stack + """
                            """ + firewall + """
                            """ + social_tags + """
                            """ + threats + """
                            """ + global_rank + """
                            """ + security_TXT + """ """)
        
        if nmap_ops:
            body += (f"""
                            """ + nmap_ops[1] + """
                            """ + nmap_ops[3] + """
                            """ + nmap_ops[5] + """
                            """ + nmap_ops[7] + """
                            """ + nmap_ops[9] + """
                            """ + nmap_ops[11] + """
                            """ + nmap_ops[13] + """
                            """ + nmap_ops[15] + """ """)
        
        body += ("""
                        </div>
                        
                        <footer>
                            <p>""" + config.ANALYSIS_REPORT_FOOTER + """ &copy; """ + config.YEAR + """</p>
                            <p style="margin-top: 10px; font-size: 12px; opacity: 0.8;">
                                This report is auto-generated for security analysis purposes
                            </p>
                        </footer>
                    </div>
                </body>
                </html>""")

        if nmap_ops:
            Analysis_report = "%s_%s_%s_%s.html" % (config.ANALYSIS_REPORT_FILE_NAME, self.domain, config.REPORT_NMAP_FILE_NAME, self.timestamp.strftime("%d%b%Y_%H-%M-%S"))
        else:    
            Analysis_report = "%s_%s_%s.html" % (config.ANALYSIS_REPORT_FILE_NAME, self.domain, self.timestamp.strftime("%d%b%Y_%H-%M-%S"))

        Analysis_report = os.path.join("./output", Analysis_report)

        with open(Analysis_report, "a", encoding="UTF-8") as f:
            f.write(header)
            f.write(script)
            f.write(body)