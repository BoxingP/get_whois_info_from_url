import sys
import csv
import tldextract
import whois
import urllib2
from sys import argv

reload(sys)
sys.setdefaultencoding('utf-8')

script, filename = argv
headers = ['url', 'domain_name', 'registrar', 'name_server', 'org', 'location']
results = []

def read_url(filename):
    with open(filename) as urls_file:
        lines = [line.rstrip() for line in urls_file]
    return lines

def get_domain_name(url):
    words = tldextract.extract(url)
    return words.domain + '.' + words.suffix

def generate_location_info(address):
    if address[4] is None:
        address[3] = None
    return ' '.join(str(part) for part in address if part is not None)

def get_org(org):
    if isinstance(org, list):
        return '/'.join(org)
    return org

def get_whois_info(url):

    try:        
        domain = get_domain_name(url)
        w = whois.whois(domain)

        info = {
            "url": url,
            "domain_name": domain,
            "registrar": w.registrar,
            "org": get_org(w.org),
            "location": generate_location_info([w.city, w.state, w.country, ',', w.zipcode]),
            "name_server": ('/'.join(sorted(list(dict.fromkeys(map(lambda x:x.lower(), w.name_servers))))))
        }
    except Exception as e:
        info = {
            "url": url,
            "domain_name": '',
            "registrar": '',
            "org": '',
            "location": '',
            "name_server": ''
        }
    
    return info

urls = read_url(filename)

for url in urls:
    result = get_whois_info(url)
    results.append(result)

with open('results.csv', 'wb') as csv_file:
    writer = csv.DictWriter(csv_file, fieldnames=headers)
    writer.writeheader()
    for result in results:
        writer.writerow(result)