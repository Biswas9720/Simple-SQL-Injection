import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"

def get_forms(url):
    try:
        response = s.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")
    except requests.exceptions.RequestException as e:
        print(f"Error fetching URL: {e}")
        return []

def form_details(form):
    details_of_form = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get")
    inputs = []

    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({
            "type": input_type,
            "name": input_name,
            "value": input_value,
        })
    details_of_form['action'] = action
    details_of_form['method'] = method
    details_of_form['inputs'] = inputs
    return details_of_form

def vulnerable(response):
    errors = {"error in your SQL syntax", "warning: mysql", "unclosed quotation mark"}

    for error in errors:
        if error in response.content.decode().lower():
            return True
    return False

def sql_injection_scan(url):
    forms = get_forms(url)
    if not forms:
        print(f"[+] Detected 0 forms on {url}.")
        return

    print(f"[+] Detected {len(forms)} forms on {url}.")

    for form in forms:
        details = form_details(form)
        for i in "\"'":
            data = {}
            for input_tag in details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    data[input_tag['name']] = input_tag["value"] + i
                elif input_tag["type"] != "submit":
                    data[input_tag['name']] = f"test{i}"

            form_action = details['action']
            form_url = urljoin(url, form_action)

            try:
                if details["method"].lower() == "post":
                    res = s.post(form_url, data=data)
                elif details["method"].lower() == "get":
                    res = s.get(form_url, params=data)
                if vulnerable(res):
                    print(f"SQL Injection Vulnerable: {form_url}")
                else:
                    print(f"No SQL Injection Vulnerable: {form_url}")
            except requests.exceptions.RequestException as e:
                print(f"Error submitting form: {e}")

if __name__ == "__main__":
    url_to_be_checked = "http://testphp.vulnweb.com/search.php?test=query"
    sql_injection_scan(url_to_be_checked)
