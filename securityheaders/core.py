# -*- coding: utf-8 -*-

"""
    Retriev and Parse Security Headers from a given URL.
"""

import os
import requests
from collections import OrderedDict
from bs4 import BeautifulSoup

__SECURITY_HEADERS_URL__ = os.environ.get("SEUCRITY_HEADERS_URL", "https://securityheaders.io/?q={0}")


def analyze_url(url):
    """
        Analyze the security relevant headers
        of the given URL.

        :param str url: the URL to analyze.

        :returns: the security headers with rating and comments.
        :rtype: dict
    """
    data = {}
    api_url = __SECURITY_HEADERS_URL__.format(url)
    response = requests.get(api_url)

    soup = BeautifulSoup(response.text, "html.parser")
    data["ip"] = soup.find_all("th", "tableLabel", text="IP Address:")[0].find_next_sibling("td").text.strip()
    data["site"] = soup.find_all("th", "tableLabel", text="Site:")[0].find_next_sibling("td").text.strip()

    headers = OrderedDict()
    # Parse Raw Headers Report Table
    for header, value in get_report_table("Raw Headers", soup):
        headers[header] = {
            "rating": "info",
            "value": value
        }

    # Parse ratings from badges
    raw_headers = soup.find_all("th", "tableLabel", text="Headers:")[0].find_next_sibling("td").find_all("li")
    for raw_header in raw_headers:
        rating = "good" if "pill-green" in raw_header["class"] else "bad"
        if raw_header.text not in headers:
            headers[raw_header.text] = {}
        headers[raw_header.text]["rating"] = rating


    # Parse Missing Headers Report Table
    for header, value in get_report_table("Missing Headers", soup):
        headers[header]["description"] = value

    # Parse Additional Information Report Table
    for header, value in get_report_table("Additional Information", soup):
        headers[header]["description"] = value

    data["headers"] = headers
    return data


def get_report_table(title, soup):
    """
        Returns the data of the report table
        with the given title.

        :param str title: the title of the report table

        :returns: key/value pairs
        :rtype: generator
    """
    try:
        report_body = soup.find_all("div", "reportTitle", text=title)[0].find_next_sibling("div")
    except IndexError:
        return []
    else:
        report_th = (x.text for x in report_body.select("table tbody tr th"))
        report_td = (x.text for x in report_body.select("table tbody tr td"))
        return zip(report_th, report_td)
