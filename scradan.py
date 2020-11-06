import json
import sys
import requests
import parse_source
from argparse import ArgumentParser
from getpass import getpass
from termcolor import colored, cprint
headers = {}


# Parse Arguments
parser = ArgumentParser()
parser.add_argument("-q", "--query", required=True, help="Search query")
parser.add_argument("-l", "--limit", default=-1,
                    help="No. of pages to limit the search (Optional)")
parser.add_argument("-u", "--username", help="Username")
args = parser.parse_args()

QUERY = args.query
PAGE_LIMIT = int(args.limit)

with open("headers.json") as headers_file:
    headers = dict(json.loads(headers_file.read()))


sess = requests.Session()


def login(session, Headers):
    # Getting Credentials
    if not args.username:
        cprint("Username :", "cyan", file=sys.stderr, end="")
        username = input()
    else:
        username = args.username
    password = getpass(prompt=colored("Password : ", "cyan"))
    try:
        # Initial GET request for getting login csrf_token
        resp = session.get("https://account.shodan.io/login", headers=Headers)

        # Parsing  the html and getting value for csrf_token
        csrf_token = parse_source.get_csrf_token(resp.text)

        cprint("[+] Logging in", "blue", file=sys.stderr)
        # POST request to /login for logging in
        post_data = {"username": username, "password": password, "csrf_token": csrf_token,
                     "login_submit": "Login", "continue": "https://account.shodan.io/", "grant_type": "password"}
        resp = session.post("https://account.shodan.io/login",
                            data=post_data, headers=Headers)
        # Check for Invalid credentials
        if "Invalid username or password" in resp.text:
            cprint("[-] Invalid credentials.Exiting now....",
                   "red", file=sys.stderr)
            sys.exit()

        cprint("[+] Logged in succesfully", "blue", file=sys.stderr)
    except Exception as e:
        cprint(e, "grey", file=sys.stderr)
        cprint("[-] Problem logging in.Exiting now", "red", file=sys.stderr)
        sys.exit()


# Function for navigating to next pages
def next_page(session, query, Headers, curr_page, page_limit):
    try:
        resp = session.get("https://www.shodan.io/search",
                           params={"query": query, "page": curr_page}, headers=Headers)
        # Check if we've reached the page_limit or further search is giving empty results
        if (page_limit != -1 and curr_page > page_limit) or (parse_source.is_last_page(resp.text)):
            return
        # Print results and Proceed for further search if results are available in current page
        else:
            results = parse_source.get_query_results(resp.text)
            print(*results, sep="\n")
            next_page(session, query, Headers, curr_page+1, page_limit)
    except Exception as e:
        cprint(e, "grey", file=sys.stderr)
        cprint("[-] Problem in fetching results from page {}".format(str(curr_page)),
               "red", file=sys.stderr)
        sys.exit()


def search(session, query, headers, page_limit=-1):
    cprint("[+] Started Querying", "blue", file=sys.stderr)
    next_page(session, query, headers, 0, page_limit)


login(sess, headers)
search(sess, QUERY, headers, PAGE_LIMIT)
