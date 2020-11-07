from bs4 import BeautifulSoup
from termcolor import cprint
import sys
import re
# Scrape CSRF token


def get_csrf_token(page_source):
    soup = BeautifulSoup(page_source, "lxml")
    return soup.find(attrs={"name": "csrf_token"}).attrs["value"]

# parse search results from source


def get_query_results(page_source):
    results = re.findall(
        r"host/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", page_source)
    search_results = []
    for result in results:
        res = result.split("/")[1]
        search_results.append(res)
    return search_results


# Check if the page_source contains no search-results
def is_not_last_page(page_source):
    if "Daily search usage limit reached" in page_source:
        cprint("[-] Daily search usage limit reached", "red", file=sys.stderr)
    return bool(re.findall("<a.*>Next</a>", page_source))
