from bs4 import BeautifulSoup

# Scrape CSRF token


def get_csrf_token(page_source):
    soup = BeautifulSoup(page_source, "lxml")
    return soup.find(attrs={"name": "csrf_token"}).attrs["value"]

# parse search results from source


def get_query_results(page_source):
    soup = BeautifulSoup(page_source, "lxml")
    results = soup.find_all(attrs={"class": "search-result"})
    search_results = []
    for result in results:
        res = {}
        res["ip"] = result.find(attrs={"class": "ip"}).a.string
        res["banner"] = str(result.pre).replace(
            "<pre>", "").replace("</pre>", "")
        search_results.append(res)
    return search_results


# Check if the page_source contains no search-results
def is_last_page(page_source):
    soup = BeautifulSoup(page_source, "lxml")
    return (len(soup.find(attrs={"class": "pagination"}).find_all("a")) <= 1)
