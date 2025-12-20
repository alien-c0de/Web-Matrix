from bs4 import BeautifulSoup
from colorama import Fore, Style
from time import perf_counter
import traceback
from util.config_uti import Configuration
from util.report_util import Report_Utility
from util.issue_config import Issue_Config

class Social_Tags:
    Error_Title = None

    def __init__(self, url, response, domain):
        self.url = url
        self.response = response
        self.domain = domain

    async def Get_Social_Tags(self):
        config = Configuration()
        self.Error_Title = config.SOCIAL_TAGS
        output = []

        try:
            # start_time = perf_counter()
            if self.response.status_code == 200:
                html = self.response.text
                soup = BeautifulSoup(html, 'html.parser')

            metadata = {
                # Basic meta tags
                'title': soup.find('title').get_text() if soup.find('title') else None,
                'description': soup.find('meta', attrs={'name': 'description'})['content'] if soup.find('meta', attrs={'name': 'description'}) else None,
                'keywords': soup.find('meta', attrs={'name': 'keywords'})['content'] if soup.find('meta', attrs={'name': 'keywords'}) else None,
                'canonicalUrl': soup.find('link', attrs={'rel': 'canonical'})['href'] if soup.find('link', attrs={'rel': 'canonical'}) else None,

                # OpenGraph Protocol
                'ogTitle': soup.find('meta', attrs={'property': 'og:title'})['content'] if soup.find('meta', attrs={'property': 'og:title'}) else None,
                'ogType': soup.find('meta', attrs={'property': 'og:type'})['content'] if soup.find('meta', attrs={'property': 'og:type'}) else None,
                'ogImage': soup.find('meta', attrs={'property': 'og:image'})['content'] if soup.find('meta', attrs={'property': 'og:image'}) else None,
                'ogUrl': soup.find('meta', attrs={'property': 'og:url'})['content'] if soup.find('meta', attrs={'property': 'og:url'}) else None,
                'ogDescription': soup.find('meta', attrs={'property': 'og:description'})['content'] if soup.find('meta', attrs={'property': 'og:description'}) else None,
                'ogSiteName': soup.find('meta', attrs={'property': 'og:site_name'})['content'] if soup.find('meta', attrs={'property': 'og:site_name'}) else None,

                # Twitter Cards
                'twitterCard': soup.find('meta', attrs={'name': 'twitter:card'})['content'] if soup.find('meta', attrs={'name': 'twitter:card'}) else None,
                'twitterSite': soup.find('meta', attrs={'name': 'twitter:site'})['content'] if soup.find('meta', attrs={'name': 'twitter:site'}) else None,
                'twitterCreator': soup.find('meta', attrs={'name': 'twitter:creator'})['content'] if soup.find('meta', attrs={'name': 'twitter:creator'}) else None,
                'twitterTitle': soup.find('meta', attrs={'name': 'twitter:title'})['content'] if soup.find('meta', attrs={'name': 'twitter:title'}) else None,
                'twitterDescription': soup.find('meta', attrs={'name': 'twitter:description'})['content'] if soup.find('meta', attrs={'name': 'twitter:description'}) else None,
                'twitterImage': soup.find('meta', attrs={'name': 'twitter:image'})['content'] if soup.find('meta', attrs={'name': 'twitter:image'}) else None,

                # Misc
                'themeColor': soup.find('meta', attrs={'name': 'theme-color'})['content'] if soup.find('meta', attrs={'name': 'theme-color'}) else None,
                'robots': soup.find('meta', attrs={'name': 'robots'})['content'] if soup.find('meta', attrs={'name': 'robots'}) else None,
                'googlebot': soup.find('meta', attrs={'name': 'googlebot'})['content'] if soup.find('meta', attrs={'name': 'googlebot'}) else None,
                'generator': soup.find('meta', attrs={'name': 'generator'})['content'] if soup.find('meta', attrs={'name': 'generator'}) else None,
                'viewport': soup.find('meta', attrs={'name': 'viewport'})['content'] if soup.find('meta', attrs={'name': 'viewport'}) else None,
                'author': soup.find('meta', attrs={'name': 'author'})['content'] if soup.find('meta', attrs={'name': 'author'}) else None,
                'publisher': soup.find('link', attrs={'rel': 'publisher'})['href'] if soup.find('link', attrs={'rel': 'publisher'}) else None,
                'favicon': soup.find('link', attrs={'rel': 'icon'})['href'] if soup.find('link', attrs={'rel': 'icon'}) else None
            }

            output = await self.__html_table(metadata)
            # print(f"✅ {config.MODULE_SOCIAL_TAGS} has been successfully completed in {round(perf_counter() - start_time, 2)} seconds.")
            print(f"✅ {config.MODULE_SOCIAL_TAGS} has been successfully completed.")
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

    async def __html_table(self, metadata):
        rep_data = []
        html = ""
        if not metadata:
            report_util = Report_Utility()
            table = await report_util.Empty_Table()
        else:
            title = str(metadata.get ('title', 'N/A'))
            description = str(metadata.get('description', 'N/A'))
            keywords = str(metadata.get('keywords', 'N/A'))
            cononical = str(metadata.get('canonicalUrl', 'N/A'))
            twitter  =str(metadata.get('twitterSite', 'N/A'))
            author = str(metadata.get('author', 'N/A'))

            percentage, html = await self.__social_tags_score(title, description, keywords, cononical, twitter, author)
            table = (
                f"""<table>
                        <tr>
                            <td colspan="2">
                                <div class="progress-bar-container">
                                    <div class="progress" style="width: {str(percentage)}%;">{str(percentage)}%</div>
                                </div>
                            </td>
                        </tr>
                        <tr>
                            <td>Title</td>
                            <td>{title}</td>
                        </tr>
                        <tr>
                            <td>Description</td>
                            <td>{description}</td>
                        </tr>
                        <tr>
                            <td>Keywords</td>
                            <td>{keywords}</td>
                        </tr>
                        <tr>
                            <td>Canonical URL</td>
                            <td>{cononical}</td>
                        </tr>
                        <tr>
                            <td>Twitter Site</td>
                            <td>{twitter}</td>
                        </tr>
                        <tr>
                            <td>Author</td>
                            <td>{author}</td>
                        </tr>
                    </table>"""
            )
        rep_data.append(table)
        rep_data.append(html)
        return rep_data

    async def __social_tags_score(self, title, description, keywords, canonical_url, twitter_site, author):
        score = 0
        max_score = 6
        issues = []
        suggestions = []
        html_tags = ""

        # Check Title
        if not title:
            issues.append(Issue_Config.ISSUE_SOCIAL_TAGS_TITLE)
            suggestions.append(Issue_Config.SUGGESTION_SOCIAL_TAGS_TITLE)
        else:
            score += 1

        # Check Description
        if not description:
            issues.append(Issue_Config.ISSUE_SOCIAL_TAGS_DESC)
            suggestions.append(Issue_Config.SUGGESTION_SOCIAL_TAGS_DESC)
        elif len(description) > 160:
            issues.append(Issue_Config.ISSUE_SOCIAL_TAGS_DESC_LONG)
            suggestions.append(Issue_Config.SUGGESTION_SOCIAL_TAGS_DESC_LONG)
        else:
            score += 1

        # Check Keywords
        if not keywords:
            issues.append(Issue_Config.ISSUE_SOCIAL_TAGS_KEYWORDS)
            suggestions.append(Issue_Config.SUGGESTION_SOCIAL_TAGS_KEYWORDS)
        else:
            score += 1
        
        # Check Canonical URL
        if not canonical_url:
            issues.append(Issue_Config.ISSUE_SOCIAL_TAGS_CANONICAL)
            suggestions.append(Issue_Config.SUGGESTION_SOCIAL_TAGS_CANONICAL)
        else:
            score += 1
        
        # Check Twitter Site
        if not twitter_site:
            issues.append(Issue_Config.ISSUE_SOCIAL_TAGS_TWITTER)
            suggestions.append(Issue_Config.SUGGESTION_SOCIAL_TAGS_TWITTER)
        else:
            score += 1
        
        # Check Author
        if not author:
            issues.append(Issue_Config.ISSUE_SOCIAL_TAGS_AUTHOR)
            suggestions.append(Issue_Config.SUGGESTION_SOCIAL_TAGS_AUTHOR)
        else:
            score += 1

        percentage_score = (score / max_score) * 100
        report_util = Report_Utility()
        html_tags = await report_util.analysis_table(Configuration.ICON_SOCIAL_TAGS, Configuration.MODULE_SOCIAL_TAGS, issues, suggestions, int(percentage_score))

        return int(percentage_score), html_tags
    
    async def __empty_output(self, error):
        report_util = Report_Utility()
        table = await report_util.Empty_Table(f"Error: {error}", 100)
        
        return [table, ""]

