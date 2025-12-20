from colorama import Fore, Style
from time import perf_counter
import traceback

from util.config_uti import Configuration
from util.report_util import Report_Utility
from util.issue_config import Issue_Config

class HTTP_Security:
    Error_Title = None

    def __init__(self, url, response, domain):
        self.url = url
        self.response = response
        self.domain = domain

    async def Get_HTTP_Security(self):
        config = Configuration()
        self.Error_Title = config.HTTP_SECURITY
        output = []
        try:
            # start_time = perf_counter()
            headers = self.response.headers

            http_sec = await self.__html_http_Sec_table(headers)
            header =  await self.__html_headers_table(headers)
            output = http_sec + header
            # print(f"✅ {config.MODULE_HTTP_SECURITY} has been successfully completed in {round(perf_counter() - start_time, 2)} seconds.")
            print(f"✅ {config.MODULE_HTTP_SECURITY} has been successfully completed.")
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

    async def __html_headers_table(self, data):
        rep_data = []
        html = ""
        if not data:
            report_util = Report_Utility()
            table = await report_util.Empty_Table()
        else:
            server = data.get("Server", None)
            date = data.get("Date", None)
            content_type = data.get("Content-Type", None)
            transfer_encoding = data.get("Transfer-Encoding", None)
            connection = data.get("Connection", None)
            x_frame_option = data.get("X-Frame-Options", None)
            x_content_type_options = data.get("X-Content-Type-Options", None)
            referrer_policy = data.get("Referrer-Policy", None)

            percentage, html = await self.__header_score(server, content_type, transfer_encoding, connection, x_frame_option, x_content_type_options, referrer_policy)
            table = (
                f"""<table>
                        <tr>
                            <td colspan="2">
                                <div class="progress-bar-container">
                                    <div class="progress" style="width: {str(percentage) }%;">{str(percentage)}%</div>
                                </div>
                            </td>
                        </tr>
                        <tr>
                            <td>Server</td>
                            <td>"""+ str(server) + """</td>
                        </tr>
                        <tr>
                            <td>Date</td>
                            <td>""" + str(date) + """</td>
                        </tr>
                        <tr>
                            <td>Content-Type</td>
                            <td>""" + str(content_type) + """</td>
                        </tr>
                        <tr>
                            <td>transfer-encoding</td>
                            <td>""" + str(transfer_encoding) + """</td>
                        </tr>
                        <tr>
                            <td>connection</td>
                            <td>""" + str(connection) + """</td>
                        </tr>
                        <tr>
                            <td>x-frame-options</td>
                            <td>""" + str(x_frame_option) + """</td>
                        </tr>
                        <tr>
                            <td>x-content-type-options</td>
                            <td>""" + str(x_content_type_options) + """</td>
                        </tr>
                        <tr>
                            <td>referrer-policy</td>
                            <td>""" + str(referrer_policy) + """</td>
                        </tr>
                    </table>"""
            )
        rep_data.append(table)
        rep_data.append(html)
        return rep_data

    async def __html_http_Sec_table(self, data):
        rep_data = []
        html = ""
        if not data:
            report_util = Report_Utility()
            table = await report_util.Empty_Table()
        else:
            cont_sec = "No" if data.get("Content-Security-Policy", None) is None else "Yes"
            trans_sec = ("No" if data.get("Strict-Transport-Security", None) is None else "Yes")
            cont_type = "No" if data.get("X-Content-Type-Options", None) is None else "Yes"
            x_frame = "No" if data.get("X-Frame-Options", None) is None else "Yes"
            x_xss = "No" if data.get("X-XSS-Protection", None) is None else "Yes"
            # "No" if data('Connection', None) is None else "Yes"

            percentage, html = await self.__http_security_score(cont_sec, trans_sec, cont_type, x_frame, x_xss)

            table = (
                f"""<table>
                        <tr>
                            <td colspan="2">
                                <div class="progress-bar-container">
                                    <div class="progress" style="width: {str(percentage) }%;">{str(percentage)}%</div>
                                </div>
                            </td>
                        </tr>
                        <tr>
                            <td>Content Security Policy</td>
                            <td> {'✅ Yes' if str(cont_sec) == 'Yes'  else '❌ No'}</td>
                        </tr>
                        <tr>
                            <td>Strict Transport Policy</td>
                            <td>{'✅ Yes' if str(trans_sec) == 'Yes'  else '❌ No'}</td>
                        </tr>
                        <tr>
                            <td>X-Content-Type-Options</td>
                            <td>{'✅ Yes' if str(cont_type) == 'Yes'  else '❌ No'}</td>
                        </tr>
                        <tr>
                            <td>X-Frame-Options</td>
                            <td>{'✅ Yes' if str(x_frame) == 'Yes'  else '❌ No'}</td>
                        </tr>
                        <tr>
                            <td>X-XSS-Protection</td>
                            <td>{'✅ Yes' if str(x_xss) == 'Yes'  else '❌ No'}</td>
                        </tr>
                </table>"""
            )
        rep_data.append(table)
        rep_data.append(html)
        return rep_data

    async def __header_score(self, server, content_type, trans_encoding, connection, x_frame, x_content, ref_policy):
        score = 0
        max_score = 7
        issues = []
        suggestions = []

        if server is not None:
            issues.append(Issue_Config.ISSUE_HEADERS_SERVER)
            suggestions.append(Issue_Config.SUGGESTION_HEADERS_SERVER)
        else:
            score += 1

        # Check Content-Type Header
        if 'charset' not in content_type:
            issues.append(Issue_Config.ISSUE_HEADERS_CHARSET)
            suggestions.append(Issue_Config.SUGGESTION_HEADERS_CHARSET)
        else:
            score += 1

        # Check Transfer-Encoding Header
        if trans_encoding is not None:
            issues.append(Issue_Config.ISSUE_HEADERS_TRAN_ENCODE)
            suggestions.append(Issue_Config.SUGGESTION_HEADERS_TRAN_ENCODE)
        else:
            score += 1

        # Check Connection Header
        if connection == 'Keep-Alive':
            issues.append(Issue_Config.ISSUE_HEADERS_CONNECTION)
            suggestions.append(Issue_Config.SUGGESTION_HEADERS_CONNECTION)
        else:
            score += 1

        # Check X-Frame-Options Header
        if x_frame is None:
            issues.append(Issue_Config.ISSUE_HEADERS_X_FRAME)
            suggestions.append(Issue_Config.SUGGESTION_HEADERS_X_FRAME)
        else:
            score += 1

        # Check X-Content-Type-Options Header
        if x_content != 'nosniff':
            issues.append(Issue_Config.ISSUE_HEADERS_X_CONTENT)
            suggestions.append(Issue_Config.SUGGESTION_HEADERS_X_CONTENT)
        else:
            score += 1

        # Check Referrer-Policy Header
        if ref_policy is None:
            issues.append(Issue_Config.ISSUE_HEADERS_REF_POLICY)
            suggestions.append(Issue_Config.SUGGESTION_HEADERS_REF_POLICY)
        else:
            score += 1

        percentage_score = (score / max_score) * 100
        report_util = Report_Utility()
        html_tags = await report_util.analysis_table(Configuration.ICON_HEADERS, Configuration.MODULE_HEADERS, issues, suggestions, int(percentage_score))

        return int(percentage_score), html_tags

    async def __http_security_score(self, cont_sec, trans_sec, cont_type, x_frame, x_xss):
        score = 0
        max_score = 5
        issues = []
        suggestions = []

        # Check Content Security Policy (CSP)
        if cont_sec != 'Yes':
            issues.append(Issue_Config.ISSUE_HTTP_SEC_CONTENT_SECURITY)
            suggestions.append(Issue_Config.SUGGESTION_HTTP_SEC_CONTENT_SECURITY)
        else:
            score += 1

        # Check Strict Transport Security (HSTS)
        if trans_sec  != 'Yes':
            issues.append(Issue_Config.ISSUE_HTTP_SEC_STRICT_TRANS)
            suggestions.append(Issue_Config.SUGGESTION_HTTP_SEC_STRICT_TRANS)
        else:
            score += 1

        # Check X-Content-Type-Options
        if cont_type != 'Yes':
            issues.append(Issue_Config.ISSUE_HTTP_SEC_X_TYPE)
            suggestions.append(Issue_Config.SUGGESTION_HTTP_SEC_X_TYPE)
        else:
            score += 1

        # Check X-Frame-Options
        if x_frame != 'Yes':
            issues.append(Issue_Config.ISSUE_HTTP_SEC_X_OPTIONS)
            suggestions.append(Issue_Config.SUGGESTION_HTTP_SEC_X_OPTIONS)
        else:
            score += 1

        # Check X-XSS-Protection
        if x_xss != 'Yes':
            issues.append(Issue_Config.ISSUE_HTTP_SEC_X_XSS)
            suggestions.append(Issue_Config.SUGGESTION_HTTP_SEC_X_XSS)
        else:
            score += 1

        percentage_score = (score / max_score) * 100
        report_util = Report_Utility()
        html_tags = await report_util.analysis_table(Configuration.ICON_HTTP_SECURITY, Configuration.MODULE_HTTP_SECURITY, issues, suggestions, int(percentage_score))

        return int(percentage_score), html_tags
    
    async def __empty_output(self, error):
        report_util = Report_Utility()
        table = await report_util.Empty_Table(f"Error : {error}", 100)
        
        return [table, "", table, ""]
