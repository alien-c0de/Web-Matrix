from colorama import Fore, Style
import re
from bs4 import BeautifulSoup
from time import perf_counter
import traceback
from util.config_uti import Configuration
from util.report_util import Report_Utility
from util.issue_config import Issue_Config

class Tech_Stack:
    Error_Title = None

    def __init__(self, url, response, domain):
        self.url = url
        self.response = response
        self.domain = domain

    async def Get_Tech_Stack(self):
        config = Configuration()
        self.Error_Title = config.TECH_STACK
        output = []

        try:
            self.response.raise_for_status()

            # Parse HTML content using BeautifulSoup
            soup = BeautifulSoup(self.response.text, "html.parser")

            # Extract headers
            headers = self.response.headers if self.response.headers else {}

            # Detect Web Server (handle Cloudflare proxy)
            server_header = headers.get('Server', 'Unknown')
            
            # If Cloudflare is detected, try to get the real server from other headers
            if 'cloudflare' in server_header.lower():
                # Check for CF-RAY which indicates Cloudflare proxy
                cf_server = headers.get('CF-Cache-Status', None)
                # Try to detect actual server from other clues
                powered_by = headers.get('X-Powered-By', '')
                if 'ASP.NET' in powered_by:
                    web_server = "IIS (behind Cloudflare)"
                elif 'PHP' in powered_by:
                    web_server = "Apache/Nginx (behind Cloudflare)"
                else:
                    web_server = f"{server_header} (Proxy/CDN)"
            else:
                web_server = server_header

            technologies = {
                'Web Server': web_server,
                'X-Powered-By': headers.get('X-Powered-By', 'Not specified'),
                'X-AspNet-Version': headers.get('X-AspNet-Version', 'Not specified'),
            }

            # Detect CMS (multiple methods)
            cms = await self.__detect_cms(soup, self.response.text, headers)
            technologies["CMS"] = cms

            # Detect JavaScript Frameworks & Versions (improved)
            js_frameworks = await self.__detect_javascript_frameworks(soup, self.response.text)
            technologies["JavaScript Frameworks"] = js_frameworks

            # Detect Analytics
            analytics = await self.__detect_analytics(self.response.text, soup)
            technologies["Analytics"] = analytics

            # Detect CDN Providers (improved)
            cdn = await self.__detect_cdn(headers, soup)
            technologies["CDN"] = cdn

            # Detect Security Features (expanded)
            security = await self.__detect_security_features(headers, self.response.text, soup)
            technologies["Security"] = security

            # Generate HTML Table Output
            output = await self.__html_table(technologies)
            print(f"✅ {config.MODULE_TECH_STACK} has been successfully completed.")
            return output

        except Exception as ex:
            error_type, error_message, tb = ex.__class__.__name__, str(ex), traceback.extract_tb(ex.__traceback__)
            error_details = tb[-1]
            file_name = error_details.filename
            method_name = error_details.name
            line_number = error_details.lineno

            error_msg = f"❌ {self.Error_Title} => ERROR in method '{method_name}' at line {line_number} : {error_type}: {error_message}"
            print(error_msg)
            output = await self.__empty_output(error_message)
            return output

    async def __detect_cms(self, soup, html_content, headers):
        """Detect CMS using multiple methods"""
        
        # Method 1: Meta generator tag
        generator = soup.find("meta", {"name": "generator"})
        if generator and generator.get("content"):
            return generator["content"]
        
        # Method 2: Common CMS signatures in HTML
        cms_signatures = {
            'WordPress': ['/wp-content/', '/wp-includes/', 'wp-json'],
            'Joomla': ['/components/com_', 'Joomla!'],
            'Drupal': ['/sites/default/', 'Drupal.settings'],
            'Magento': ['/skin/frontend/', 'Mage.Cookies'],
            'Shopify': ['cdn.shopify.com', 'Shopify.theme'],
            'Wix': ['wix.com', 'parastorage'],
            'Squarespace': ['squarespace.com', 'squarespace-cdn'],
            'Webflow': ['webflow.com', 'webflow.io'],
            'Ghost': ['ghost.org', 'ghost.io'],
            'HubSpot': ['hubspot.com', 'hs-scripts']
        }
        
        for cms_name, signatures in cms_signatures.items():
            if any(sig in html_content for sig in signatures):
                return cms_name
        
        # Method 3: Check headers for CMS indicators
        x_powered_by = headers.get('X-Powered-By', '')
        if 'WordPress' in x_powered_by:
            return 'WordPress'
        
        return "Not Detected"

    async def __detect_javascript_frameworks(self, soup, html_content):
        """Detect JavaScript frameworks with improved version detection"""
        
        scripts = [script.get("src", "") for script in soup.find_all("script") if script.get("src")]
        framework_versions = {}

        # Improved version patterns for CDN URLs
        version_patterns = {
            "React": [
                re.compile(r"react[@/-]?([\d.]+)", re.IGNORECASE),
                re.compile(r"react\.(?:production\.min|development)\.js", re.IGNORECASE)
            ],
            "Angular": [
                re.compile(r"angular[@/-]?([\d.]+)", re.IGNORECASE),
                re.compile(r"angular\.min\.js", re.IGNORECASE)
            ],
            "Vue.js": [
                re.compile(r"vue[@/-]?([\d.]+)", re.IGNORECASE),
                re.compile(r"vue\.(?:global\.)?(?:prod|runtime)\.js", re.IGNORECASE)
            ],
            "jQuery": [
                re.compile(r"jquery[/-]?([\d.]+)", re.IGNORECASE),
                re.compile(r"jquery\.min\.js", re.IGNORECASE)
            ],
            "Next.js": [
                re.compile(r"next[/-]?([\d.]+)", re.IGNORECASE),
                re.compile(r"_next/static", re.IGNORECASE)
            ],
            "Gatsby": [
                re.compile(r"gatsby[/-]?([\d.]+)", re.IGNORECASE)
            ]
        }

        # Check script sources
        for script in scripts:
            for framework, patterns in version_patterns.items():
                for pattern in patterns:
                    match = pattern.search(script)
                    if match:
                        version = match.group(1) if match.lastindex and match.group(1) else "Detected"
                        if framework not in framework_versions:
                            framework_versions[framework] = version
                        break

        # Check inline scripts for framework signatures
        inline_scripts = soup.find_all("script", string=True)
        for script in inline_scripts:
            script_text = script.string or ""
            
            # React detection
            if "React" not in framework_versions:
                if "React.createElement" in script_text or "ReactDOM.render" in script_text:
                    framework_versions["React"] = "Detected"
            
            # Vue detection
            if "Vue.js" not in framework_versions:
                if "new Vue(" in script_text or "Vue.createApp" in script_text:
                    framework_versions["Vue.js"] = "Detected"
            
            # Angular detection
            if "Angular" not in framework_versions:
                if "ng-app" in html_content or "angular.module" in script_text:
                    framework_versions["Angular"] = "Detected"

        if framework_versions:
            return ", ".join([f"{k} {v}" if v != "Detected" else k for k, v in framework_versions.items()])
        else:
            return "Not Detected"

    async def __detect_analytics(self, html_content, soup):
        """Detect analytics platforms"""
        
        analytics_platforms = []
        
        # Google Analytics
        if any(x in html_content for x in ['gtag(', 'ga(', 'google-analytics.com', 'googletagmanager.com']):
            analytics_platforms.append("Google Analytics")
        
        # Google Tag Manager
        if 'googletagmanager.com' in html_content:
            if "Google Analytics" not in analytics_platforms:
                analytics_platforms.append("Google Tag Manager")
        
        # Other analytics platforms
        analytics_signatures = {
            'Adobe Analytics': ['omniture.com', 'adobe.com/analytics'],
            'Matomo': ['matomo.js', 'piwik.js'],
            'Mixpanel': ['mixpanel.com'],
            'Segment': ['segment.com', 'analytics.js'],
            'Hotjar': ['hotjar.com'],
            'Facebook Pixel': ['facebook.net/en_US/fbevents.js', 'fbq('],
            'Clarity': ['clarity.ms']
        }
        
        for platform, signatures in analytics_signatures.items():
            if any(sig in html_content for sig in signatures):
                analytics_platforms.append(platform)
        
        return ", ".join(analytics_platforms) if analytics_platforms else "Not Detected"

    async def __detect_cdn(self, headers, soup):
        """Detect CDN providers from headers and content"""
        
        cdn_providers = []
        
        # Check headers
        server = headers.get('Server', '').lower()
        cf_ray = headers.get('CF-RAY', '')
        x_cache = headers.get('X-Cache', '').lower()
        via = headers.get('Via', '').lower()
        
        # Cloudflare
        if 'cloudflare' in server or cf_ray:
            cdn_providers.append("Cloudflare")
        
        # AWS CloudFront
        if 'cloudfront' in x_cache or 'cloudfront' in via:
            cdn_providers.append("AWS CloudFront")
        
        # Fastly
        if 'fastly' in via or headers.get('X-Fastly-Request-ID'):
            cdn_providers.append("Fastly")
        
        # Akamai
        if 'akamai' in server or headers.get('X-Akamai-Transformed'):
            cdn_providers.append("Akamai")
        
        # Check script sources for CDN usage
        scripts = [script.get("src", "") for script in soup.find_all("script") if script.get("src")]
        
        cdn_domains = {
            "Cloudflare": ["cloudflare.com", "cdnjs.cloudflare.com"],
            "jsDelivr": ["jsdelivr.net"],
            "unpkg": ["unpkg.com"],
            "Google CDN": ["googleapis.com", "gstatic.com"],
            "AWS": ["amazonaws.com", "cloudfront.net"],
            "MaxCDN": ["maxcdn.com"],
            "KeyCDN": ["keycdn.com"]
        }
        
        for script in scripts:
            for cdn_name, domains in cdn_domains.items():
                if any(domain in script for domain in domains):
                    if cdn_name not in cdn_providers:
                        cdn_providers.append(cdn_name)
        
        return ", ".join(cdn_providers) if cdn_providers else "Not Detected"

    async def __detect_security_features(self, headers, html_content, soup):
        """Detect security features and technologies"""
        
        security_features = []
        
        # Security headers
        if 'Content-Security-Policy' in headers or 'Content-Security-Policy-Report-Only' in headers:
            security_features.append("CSP Header")
        
        if 'Strict-Transport-Security' in headers:
            security_features.append("HSTS")
        
        if 'X-Frame-Options' in headers:
            security_features.append("X-Frame-Options")
        
        if 'X-Content-Type-Options' in headers:
            security_features.append("X-Content-Type-Options")
        
        # reCAPTCHA
        if 'google.com/recaptcha' in html_content or 'recaptcha' in html_content:
            security_features.append("reCAPTCHA")
        
        # hCaptcha
        if 'hcaptcha.com' in html_content:
            security_features.append("hCaptcha")
        
        # Cloudflare Bot Management
        if headers.get('CF-RAY'):
            security_features.append("Cloudflare Protection")
        
        # WAF indicators
        waf_headers = ['X-WAF', 'X-WebKnight', 'X-Sucuri-ID']
        for waf_header in waf_headers:
            if waf_header in headers:
                security_features.append("WAF Detected")
                break
        
        return ", ".join(security_features) if security_features else "Not Detected"

    async def __html_table(self, tech_stack):
        rep_data = []
        html = ""
        if not tech_stack:
            report_util = Report_Utility()
            table = await report_util.Empty_Table()
        else:
            percentage, html = await self.__tech_stack_score(tech_stack)
            rows = [
                f"""
                <tr>
                    <td>{key}</td>
                    <td>{value}</td>
                </tr>"""
                for key, value in tech_stack.items()
            ]

            table = f"""
            <table>
                <tr>
                    <td colspan="2">
                        <div class="progress-bar-container">
                            <div class="progress" style="width: {str(percentage)}%;">{str(percentage)}%</div>
                        </div>
                    </td>
                </tr>
                    {''.join(rows)}
            </table>"""

        rep_data.append(table)
        rep_data.append(html)
        return rep_data

    async def __tech_stack_score(self, tech_stack):
        score = 0
        max_score = 10  # Fixed max score for consistency
        issues = []
        suggestions = []

        # Web Server scoring
        web_server = tech_stack.get('Web Server', 'Unknown')
        if 'Unknown' in web_server:
            issues.append(Issue_Config.ISSUE_TECH_STACK_WEBSERVER)
            suggestions.append(Issue_Config.SUGGESTION_TECH_STACK_WEBSERVER)
        else:
            score += 1

        # X-Powered-By scoring (hiding is better)
        powered_by = tech_stack.get('X-Powered-By', '')
        if powered_by == 'Not specified':
            score += 1
        else:
            issues.append(Issue_Config.ISSUE_TECH_STACK_X_POWERED_BY.format(powered_by))
            suggestions.append(Issue_Config.SUGGESTION_TECH_STACK_X_POWERED_BY)

        # CMS scoring
        cms = tech_stack.get('CMS', 'Not Detected')
        if cms != 'Not Detected':
            if 'WordPress' in cms or 'Joomla' in cms:
                issues.append(Issue_Config.ISSUE_TECH_STACK_CMS.format(cms))
                suggestions.append(Issue_Config.SUGGESTION_TECH_STACK_CMS)
            score += 1
        else:
            score += 1

        # JavaScript Frameworks
        js_frameworks = tech_stack.get('JavaScript Frameworks', 'Not Detected')
        if js_frameworks != 'Not Detected':
            issues.append(Issue_Config.ISSUE_TECH_STACK_JS_FRAMEWORK)
            suggestions.append(Issue_Config.SUGGESTION_TECH_STACK_JS_FRAMEWORK)
            if 'Version Unknown' in js_frameworks or 'Detected' in js_frameworks:
                issues.append(Issue_Config.ISSUE_TECH_STACK_JS_FRAMEWORK_VER)
                suggestions.append(Issue_Config.SUGGESTION_TECH_STACK_JS_FRAMEWORK_VER)
        else:
            score += 1

        # Analytics
        if tech_stack.get('Analytics', 'Not Detected') != 'Not Detected':
            score += 1

        # CDN scoring
        cdn = tech_stack.get('CDN', 'Not Detected')
        if cdn == 'Not Detected':
            issues.append(Issue_Config.SUGGESTION_TECH_STACK_CDN)
            suggestions.append(Issue_Config.SUGGESTION_TECH_STACK_CDN)
        else:
            score += 2

        # Security features scoring (most important)
        security = tech_stack.get('Security', 'Not Detected')
        if security == 'Not Detected':
            issues.append(Issue_Config.ISSUE_TECH_STACK_SECURITY)
            suggestions.append(Issue_Config.SUGGESTION_TECH_STACK_SECURITY)
        else:
            # Count security features
            # security_count = len(security.split(','))
            # score += min(security_count, 3)  # Max 3 points for security
            score += 3

        # Calculate percentage
        percentage_score = (score / max_score) * 100
        percentage_score = max(0, min(percentage_score, 100))

        report_util = Report_Utility()
        html_tags = await report_util.analysis_table(
            Configuration.ICON_TECH_STACK, 
            Configuration.MODULE_TECH_STACK, 
            issues, 
            suggestions, 
            int(percentage_score)
        )
        return int(percentage_score), html_tags

    async def __empty_output(self, error):
        report_util = Report_Utility()
        table = await report_util.Empty_Table(f"Error: {error}", 100)
        
        return [table, ""]