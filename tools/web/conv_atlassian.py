import requests
from bs4 import BeautifulSoup

cert_file = '/home/raf/Zscaler/Zscaler-AWS.pem'
# url = "https://confluence.collegeboard.org/display/DataServices/DATA+Home"
url = 'https://collegeboard.atlassian.net/wiki/spaces/DataServices/pages/73337084/National+Merit+Reporting+2018+Onwards'

orig_site = requests.get(url, verify=cert_file)

print(orig_site.status_code)
print(orig_site.content)

orig_soup = BeautifulSoup(orig_site.content, 'html.parser')

orig_links = orig_soup.find_all('a')

orig_titles = [link.text for link in orig_links]

print(orig_links)
print()
print(orig_titles)