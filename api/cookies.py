from colorama import Fore, Style
from datetime import datetime, timezone
import re
from time import perf_counter
import traceback
from util.config_uti import Configuration
from util.issue_config import Issue_Config
from util.report_util import Report_Utility

class Cookies():
    Error_Title = None

    def __init__(self, url, response, domain):
        self.url = url
        self.response = response
        self.domain = domain

    async def Get_Cookies(self):
        config = Configuration()
        self.Error_Title = config.COOKIES
        output = []
        try:
            # Check if response exists
            if not self.response:
                error_msg = f"❌ {self.Error_Title} => Failed to retrieve response from website. Unable to check for cookies."
                print(error_msg)
                output = await self.__empty_output("Failed to retrieve website response. Unable to check for cookies.")
                return output

            # Check HTTP status code
            status_code = self.response.status_code
            
            # Handle access denied (403) or not found (404) gracefully
            if status_code in [403, 404, 401]:
                # Still try to get cookies even if access was denied
                cookies = self.response.cookies
                
                if not cookies or len(cookies) == 0:
                    warning_msg = f"⚠️  {self.Error_Title} => Website returned HTTP {status_code}. No cookies detected."
                    print(warning_msg)
                    output = await self.__empty_output(f"Website access restricted (HTTP {status_code}). No cookies found.")
                    return output
                else:
                    # We got cookies despite the error code
                    print(f"⚠️  {self.Error_Title} => Website returned HTTP {status_code}, but found {len(cookies)} cookie(s).")
            
            # Get cookies from response
            cookies = self.response.cookies
            cookie_info = []
            
            # Process each cookie
            for cookie in cookies:
                try:
                    cookie_info.append({
                        'name': cookie.name,
                        'value': cookie.value,
                        'domain': cookie.domain if cookie.domain else self.domain,
                        'path': cookie.path if cookie.path else '/',
                        'expires': cookie.expires,
                        'secure': cookie.secure,
                        'httponly': getattr(cookie, 'has_nonstandard_attr', lambda x: False)('HttpOnly'),
                        'samesite': getattr(cookie, 'get_nonstandard_attr', lambda x: None)('SameSite')
                    })
                except Exception as cookie_error:
                    # Skip this cookie if there's an error processing it
                    print(f"⚠️  {self.Error_Title} => Error processing cookie '{cookie.name}': {str(cookie_error)}")
                    continue

            output = await self.__html_cookies_table(cookie_info)
            print(f"✅ {config.MODULE_COOKIES} has been successfully completed.")
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

    async def __html_cookies_table(self, cookie_info):
        rep_data = []
        html = ""
        
        if not cookie_info or len(cookie_info) == 0:
            report_util = Report_Utility()
            table = await report_util.Empty_Table("This website does not use cookies.", 100)
            rep_data.append(table)
            rep_data.append("")
            return rep_data
        
        # Calculate overall score based on all cookies
        percentage, html = await self.__cookies_score(cookie_info)
        
        # Build table for all cookies
        table_rows = []
        
        for idx, cookie in enumerate(cookie_info):
            name = cookie.get('name', 'Unknown')
            value = cookie.get('value', '')
            domain = cookie.get('domain', 'Not set')
            path = cookie.get('path', '/')
            secure = cookie.get('secure', False)
            httponly = cookie.get('httponly', False)
            samesite = cookie.get('samesite', 'Not set')
            
            # Format expiration
            expires_timestamp = cookie.get('expires')
            if expires_timestamp:
                try:
                    expires = datetime.fromtimestamp(expires_timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                except:
                    expires = "Invalid date"
            else:
                expires = "Session (no expiration)"
            
            # Truncate long values for display
            display_value = value[:50] + "..." if len(value) > 50 else value
            
            # Add cookie section header if multiple cookies
            if len(cookie_info) > 1:
                table_rows.append(f"""
                    <tr>
                        <td colspan="2" style="text-align: left; background: rgba(0, 212, 255, 0.1); font-weight: 600;">
                            <h4>Cookie #{idx + 1}: {name}</h4>
                        </td>
                    </tr>""")
            
            table_rows.append(f"""
                <tr>
                    <td>Name</td>
                    <td>{name}</td>
                </tr>
                <tr>
                    <td>Value</td>
                    <td style="word-break: break-all;"><small>{display_value}</small></td>
                </tr>
                <tr>
                    <td>Domain</td>
                    <td>{domain}</td>
                </tr>
                <tr>
                    <td>Path</td>
                    <td>{path}</td>
                </tr>
                <tr>
                    <td>Expires</td>
                    <td>{expires}</td>
                </tr>
                <tr>
                    <td>Secure</td>
                    <td>{"✅ Yes" if secure else "❌ No"}</td>
                </tr>
                <tr>
                    <td>HttpOnly</td>
                    <td>{"✅ Yes" if httponly else "❌ No"}</td>
                </tr>
                <tr>
                    <td>SameSite</td>
                    <td>{samesite if samesite else "❌ Not set"}</td>
                </tr>""")
        
        table = f"""<table>
                        <tr>
                            <td colspan="2">
                                <div class="progress-bar-container">
                                    <div class="progress" style="width: {percentage}%;">{percentage}%</div>
                                </div>
                            </td>
                        </tr>
                        <tr>
                            <td colspan="2" style="text-align: left;">
                                <strong>Total Cookies Found: {len(cookie_info)}</strong>
                            </td>
                        </tr>
                        {''.join(table_rows)}
                    </table>"""
        
        rep_data.append(table)
        rep_data.append(html)
        return rep_data

    async def __cookies_score(self, cookie_info):
        """Calculate security score for all cookies"""
        total_score = 0
        max_score = 0
        issues = []
        suggestions = []
        
        if not cookie_info:
            return 100, ""
        
        # Evaluate each cookie
        for cookie in cookie_info:
            cookie_score = 0
            cookie_max = 6  # 6 security checks per cookie
            
            name = cookie.get('name', '')
            value = cookie.get('value', '')
            domain = cookie.get('domain', '')
            path = cookie.get('path', '/')
            expires = cookie.get('expires')
            secure = cookie.get('secure', False)
            httponly = cookie.get('httponly', False)
            samesite = cookie.get('samesite')
            
            # 1. Secure flag check (CRITICAL)
            if secure:
                cookie_score += 1
            else:
                issues.append(f"Cookie '{name}': {Issue_Config.ISSUE_COOKIES_SECURE}")
                suggestions.append(Issue_Config.SUGGESTION_COOKIES_SECURE)
            
            # 2. HttpOnly flag check (IMPORTANT)
            if httponly:
                cookie_score += 1
            else:
                issues.append(f"Cookie '{name}': Missing HttpOnly flag (vulnerable to XSS)")
                suggestions.append("Set HttpOnly flag to prevent JavaScript access to cookies")
            
            # 3. SameSite attribute check (IMPORTANT)
            if samesite and samesite.lower() in ['strict', 'lax']:
                cookie_score += 1
            else:
                issues.append(f"Cookie '{name}': Missing or weak SameSite attribute")
                suggestions.append("Set SameSite=Strict or SameSite=Lax to prevent CSRF attacks")
            
            # 4. Session ID complexity check
            if value and len(value) >= 16 and re.match(r'^[a-zA-Z0-9_\-+=]{16,}$', value):
                cookie_score += 1
            else:
                issues.append(f"Cookie '{name}': Weak or short value")
                suggestions.append(Issue_Config.SUGGESTION_COOKIES_SESSION_VALUE)
            
            # 5. Path restriction check
            if path != '/':
                cookie_score += 1
            else:
                issues.append(f"Cookie '{name}': {Issue_Config.ISSUE_COOKIES_PATH}")
                suggestions.append(Issue_Config.SUGGESTION_COOKIES_PATH)
            
            # 6. Domain specificity check
            if domain and domain != 'localhost' and not domain.startswith('.'):
                cookie_score += 1
            else:
                if domain.startswith('.'):
                    issues.append(f"Cookie '{name}': Overly broad domain scope")
                    suggestions.append("Avoid wildcard domains for better security")
            
            total_score += cookie_score
            max_score += cookie_max
        
        # Calculate percentage
        percentage_score = (total_score / max_score * 100) if max_score > 0 else 0
        
        # Remove duplicate suggestions
        suggestions = list(dict.fromkeys(suggestions))[:5]  # Keep max 5 unique suggestions
        issues = list(dict.fromkeys(issues))[:10]  # Keep max 10 unique issues
        
        # Generate analysis report
        report_util = Report_Utility()
        html_tags = await report_util.analysis_table(
            Configuration.ICON_COOKIES, 
            Configuration.MODULE_COOKIES, 
            issues, 
            suggestions, 
            int(percentage_score)
        )
        
        return int(percentage_score), html_tags
    
    async def __empty_output(self, error):
        report_util = Report_Utility()
        
        # Check if it's a 403/404 error - these are not really errors for cookie checking
        if "403" in str(error) or "404" in str(error):
            table = await report_util.Empty_Table("Website returned access denied. No cookies detected.", 100)
        else:
            table = await report_util.Empty_Table(f"Error: {error}", 0)
        
        return [table, ""]