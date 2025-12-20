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
            # start_time = perf_counter()
            self.response.raise_for_status()  # Ensure response is valid

            # Parse HTML content using BeautifulSoup
            soup = BeautifulSoup(self.response.text, "html.parser")

            # Extract headers
            headers = self.response.headers if self.response.headers else {}

            # Detect Web Server & Other Headers
            technologies = {
                'Web Server': headers.get('Server', 'Unknown'),
                'X-Powered-By': headers.get('X-Powered-By', 'Not specified'),
                'X-AspNet-Version': headers.get('X-AspNet-Version', 'Not specified'),
            }

            # Detect CMS (from meta generator)
            generator = soup.find("meta", {"name": "generator"})
            technologies["CMS"] = generator["content"] if generator else "Not Detected"

            # Detect JavaScript Frameworks & Versions
            scripts = [script.get("src", "") for script in soup.find_all("script") if script.get("src")]
            framework_versions = {}

            version_patterns = {
                "React": re.compile(r"react(?:[-.]min)?\.js(?:\?v?=([\d.]+))?", re.IGNORECASE),
                "Angular": re.compile(r"angular(?:[-.]min)?\.js(?:\?v?=([\d.]+))?", re.IGNORECASE),
                "Vue.js": re.compile(r"vue(?:[-.]min)?\.js(?:\?v?=([\d.]+))?", re.IGNORECASE),
                "jQuery": re.compile(r"jquery(?:[-.]min)?\.js(?:\?v?=([\d.]+))?", re.IGNORECASE),
            }

            for script in scripts:
                for framework, pattern in version_patterns.items():
                    match = pattern.search(script)
                    if match:
                        framework_versions[framework] = match.group(1) if match.group(1) else "Version Unknown"

            technologies["JavaScript Frameworks"] = ", ".join([f"{k} ({v})" for k, v in framework_versions.items()]) or "Not Detected"

            # Detect Analytics
            analytics = "Google Analytics" if "gtag(" in self.response.text or "googletagmanager" in self.response.text else "Not Detected"
            technologies["Analytics"] = analytics

            # Detect CDN Providers
            cdn_providers = {
                "Cloudflare": any("cloudflare" in script for script in scripts),
                "AWS": any("amazonaws" in script for script in scripts),
                "Google CDN": any("googleapis" in script for script in scripts)
            }
            technologies["CDN"] = ", ".join([k for k, v in cdn_providers.items() if v]) or "Not Detected"

            # Detect Security Features
            security_features = {
                "reCAPTCHA": "reCAPTCHA" if "www.google.com/recaptcha" in self.response.text else "Not Detected",
                "CSP Header": "Yes" if "Content-Security-Policy" in str(headers) else "Not Detected"
            }
            technologies["Security"] = ", ".join([k for k, v in security_features.items() if v != "Not Detected"]) or "Not Detected"

            # Generate HTML Table Output
            output = await self.__html_table(technologies)
            # print(f"✅ {config.MODULE_TECH_STACK} has been successfully completed in {round(perf_counter() - start_time, 2)} seconds.")
            print(f"✅ {config.MODULE_TECH_STACK} has been successfully completed.")
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
                            <div class="progress" style="width: {str(percentage) }%;">{str(percentage)}%</div>
                        </div>
                    </td>
                </tr>
                    {''.join(rows)}
            </table>"""

        rep_data.append(table)
        rep_data.append(html)
        return rep_data

    async def __tech_stack_score(self, tech_stack):
        score = 0  # Initial security score
        max_score = len(tech_stack)  # Maximum possible score (each parameter contributes)
        issues = []  # List to store detected issues
        suggestions = []  # List to store improvement recommendations

        # Define risk deductions and scores based on the technology stack
        risk_factors = {
            "Web Server": {
                "Apache": 0,  # Neutral
                "Nginx": 1,  # Slightly better
                "Unknown": -1  # Higher risk
            },
            "X-Powered-By": {
                "Not specified": 1,  # Good practice to hide this
                "PHP": -1,  # Older PHP versions often have security risks
                "ASP.NET": 0
            },
            "X-AspNet-Version": {
                "Not specified": 1,  # Hiding the version is a security best practice
                "4.0": -1,  # Older versions are vulnerable
                "2.0": -2
            },
            "CMS": {
                "Not Detected": 0,  # Some CMSs introduce security risks, but unknown is still a risk
                "WordPress": -1,  # Commonly targeted
                "Joomla": -1
            },
            "JavaScript Frameworks": {
                "jQuery (Version Unknown)": -1,  # jQuery with an unknown version could be outdated
                "React": 1,
                "Angular": 1
            },
            "Analytics": {
                "Google Analytics": 1,  # No security impact
                "Other": 0
            },
            "CDN": {
                "Not Detected": -1,  # Using a CDN improves security against DDoS
                "Cloudflare": 1,  # Cloudflare improves security
                "AWS": 1
            },
            "Security": {
                "reCAPTCHA": 1,  # Adds security but not a major impact
                "CSP Header": 2  # Content Security Policy is crucial
            }
        }

        # Apply risk deductions based on the tech stack
        for key, value in tech_stack.items():
            if key in risk_factors:
                score_contribution = risk_factors[key].get(value, 0)  # Default to 0 if unknown
                score += score_contribution

                # Identify issues
                if score_contribution < 0:
                    issues.append(f"{key}: {value} {Issue_Config.ISSUE_TECH_STACK_MAIN}")

                # Provide recommendations
                if key == "Web Server" and value == "Apache":
                    suggestions.append(Issue_Config.SUGGESTION_TECH_STACK_WEBSERVER)
                elif key == "JavaScript Frameworks" and "Version Unknown" in value:
                    suggestions.append(Issue_Config.SUGGESTION_TECH_STACK_JAVESCRIPT)
                elif key == "CDN" and value == "Not Detected":
                    suggestions.append(Issue_Config.SUGGESTION_TECH_STACK_CDN)
                elif key == "Security" and "CSP Header" not in value:
                    suggestions.append(Issue_Config.SUGGESTION_TECH_STACK_SECURITY)

        # Calculate percentage score
        percentage_score = (score / max_score) * 100
        percentage_score = max(0, min(percentage_score, 100))  # Keep within 0-100%

        report_util = Report_Utility()
        html_tags = await report_util.analysis_table(Configuration.ICON_TECH_STACK, Configuration.MODULE_TECH_STACK, issues, suggestions, int(percentage_score))
        return int(percentage_score), html_tags

    async def __empty_output(self, error):
        report_util = Report_Utility()
        table = await report_util.Empty_Table(f"Error: {error}", 100)
        
        return [table, ""]
