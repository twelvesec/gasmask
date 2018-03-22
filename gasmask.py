#!/usr/bin/env python
# encoding: UTF-8

"""
    GasMasK - All in one Information gathering tool - OSINT
    This file is part of GasMasK Project

    Written by: @maldevel
    Website: https://www.twelvesec.com/
    GIT: https://github.com/twelvesec/gasmask

    TwelveSec (@Twelvesec)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    For more see the file 'LICENSE' for copying permission.
"""

__author__ = "maldevel"
__license__ = "GPLv3"
__version__ = "1.1"

#######################################################

import argparse
from argparse import RawTextHelpFormatter
import validators
import sys
import socket
import whois
import dns.resolver
import collections
import re
import os
import random
from dns import reversename, resolver
import requests
import time

#######################################################

from requests.packages.urllib3.exceptions import InsecureRequestWarning #remove insecure https warning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning) #remove insecure https warning

#######################################################

message = """
   ______           __  ___           __ __
  / ____/___ ______/  |/  /___ ______/ //_/
 / / __/ __ `/ ___/ /|_/ / __ `/ ___/ ,<
/ /_/ / /_/ (__  ) /  / / /_/ (__  ) /| |
\____/\__,_/____/_/  /_/\__,_/____/_/ |_|

GasMasK - All in one Information gathering tool - OSINT
Ver. {}
Written by: @maldevel
https://www.twelvesec.com/
""".format(__version__)

#######################################################

## Validate Domain name ##

def CheckDomain(value):
    if not validators.domain(value):
        raise argparse.ArgumentTypeError('Invalid {} domain.'.format(value))
    return value

#######################################################

## Verify domain/ip ##

def CheckDomainOrIP(value):

    if not validators.domain(value) and not validators.ip_address.ipv4(value):
        raise argparse.ArgumentTypeError('Invalid domain or ip address ({}).'.format(value))
    return value

#######################################################

## Get Domain ip address ##

def VerifyHostname(value):

    try:
        ip = socket.gethostbyname(value)
        return ip
    except Exception as e:
        return False

#######################################################

## Perform whois query ##

def WhoisQuery(value):

    whoisData = collections.OrderedDict()
    whoisData["name"] = ["-", "Name:"]
    whoisData["org"] = ["-", "Organization:"]
    whoisData["address"] = ["-", "Address:"]
    whoisData["city"] = ["-", "City:"]
    whoisData["zipcode"] = ["-", "Zip code:"]
    whoisData["country"] = ["-", "Country:"]
    whoisData["emails"] = ["-", "Emails:"]
    whoisData["registrar"] = ["-", "Registrar:"]
    whoisData["whois_server"] = ["-", "Whois Server:"]
    whoisData["updated_date"] = ["-", "Updated Date:"]
    whoisData["expiration_date"] = ["-", "Expiration Date:"]
    whoisData["creation_date"] = ["-", "Creation Date:"]
    whoisData["name_servers"] = ["-", "Name Servers:"]

    domain = whois.whois(value)

    for rec in whoisData:
        if domain[rec]:
            if isinstance(domain[rec], list):
                if rec is 'name_servers':
                    whoisData[rec][0] = []
                    for val in domain[rec]:
                        whoisData[rec][0].append(val + ":" + VerifyHostname(val))
                else:
                    whoisData[rec][0] = []
                    for val in domain[rec]:
                        whoisData[rec][0].append(val)
            else:
                whoisData[rec][0] = str(domain[rec])

    return whoisData

#######################################################

## Perform DNS queries ##

def _query(value, dnsserver, record):

    myresolver = dns.resolver.Resolver()
    myresolver.nameservers = [dnsserver]

    try:
        answers = myresolver.query(value, record)
        for answer in answers:
            if record is 'NS':
                return answer.to_text() + ":" + VerifyHostname(answer.to_text())
            elif record is 'MX':
                domain_name = re.search(' (.*)\.', answer.to_text(), re.IGNORECASE).group(1)
                return answer.to_text() + ":" + VerifyHostname(domain_name)
            else:
                return answer.to_text()
    except Exception as e:
        return '-'

    return dnsData


def DnsQuery(value, dnsserver, record=None):

    dnsData = {
        "A":[],
        "CNAME":[],
        "HINFO":[],
        "MX":[],
        "NS":[],
        "PTR":[],
        "SOA":[],
        "TXT":[],
        "SPF":[],
        "SRV":[],
        "RP":[]
    }

    if record is None:
        for record in dnsData:
            dnsData[record].append(_query(value, dnsserver, record))
    else:
        dnsData[record].append(_query(value, dnsserver, record))

    return dnsData

#######################################################

## IP DNS Reverse lookup ##

def ReverseIPQuery(value, dnsserver):

    try:
        revname = reversename.from_address(value)
        myresolver = dns.resolver.Resolver()
        myresolver.nameservers = [dnsserver]
        return str(myresolver.query(revname, 'PTR')[0]).rstrip('.')
    except Exception as e:
        print e
        return ''

#######################################################

## Clean HTML tags ##

def CleanHTML(results):

    res = results
    res = re.sub('<em>', '', res)
    res = re.sub('<b>', '', res)
    res = re.sub('</b>', '', res)
    res = re.sub('</em>', '', res)
    res = re.sub('%2f', ' ', res)
    res = re.sub('%3a', ' ', res)
    res = re.sub('<strong>', '', res)
    res = re.sub('</strong>', '', res)
    res = re.sub('<wbr>', '', res)
    res = re.sub('</wbr>', '', res)
    res = re.sub('&lt;', '', res)

    return res

#######################################################

## Extract Emails ##

def GetEmails(results, value):

    res = results
    res = CleanHTML(res)

    temp = re.compile(
        '[a-zA-Z0-9.\-_+#~!$&\',;=:]+' +
        '@' +
        '[a-zA-Z0-9.-]*' +
        value)

    emails = temp.findall(res)
    final = []
    for email in emails:
        final.append(email.lower())

    return sorted(set(final))

#######################################################

## Extract Hostnames ##

def GetHostnames(results, value):

    res = results
    res = CleanHTML(res)

    temp = re.compile('[a-zA-Z0-9.-]*\.' + value)
    hostnames = temp.findall(res)
    final = []
    for host in hostnames:
        final.append(host.lower())

    return sorted(set(final))

#######################################################

## Get All Hostnames ##

def GetHostnamesAll(results):

    res = results
    temp = re.compile('<cite>(.*?)</cite>')
    hostname = temp.findall(res)
    vhosts = []

    for x in hostname:
        r = ''
        if x.count(':'):
            r = x.split(':')[1].split('/')[2]
        else:
            r = x.split("/")[0]
        vhosts.append(r)

    return sorted(set(vhosts))

#######################################################

## Get All Hostnames ##

def GetDNSDumpsterHostnames(value, results):

    tbl_regex = re.compile('<a name="hostanchor"><\/a>Host Records.*?<table.*?>(.*?)</table>', re.S)
    link_regex = re.compile('<td class="col-md-4">(.*?)<br>', re.S)
    links = []
    subdomains=[]

    try:
        results_tbl = tbl_regex.findall(results)[0]
    except IndexError:
        results_tbl = ''
    links_list = link_regex.findall(results_tbl)
    links = list(set(links_list))

    for link in links:
        subdomain = link.strip()
        if not subdomain.endswith(value):
            continue
        if subdomain and subdomain not in subdomains and subdomain != value:
            subdomains.append(subdomain.strip())

    return sorted(set(subdomains))

#######################################################

## Pick random User-Agent string ##

def PickRandomUA(value):

    if value:
        secure_random = random.SystemRandom()
        return secure_random.choice(value)

    return None

#######################################################

## Pick random User-Agent string ##

def PickRandomTimeout(value):

    if value:
        secure_random = random.SystemRandom()
        return secure_random.choice(value)

    return 5

#######################################################

## Common search ##

def CommonSearch(value, urltemplate, quantity, step, limit, uas, proxies, timeouts):

    counter = 0
    results = ""

    while counter <= limit:
        try:
            url = urltemplate.format(quantity=quantity, counter=counter, value=value)
            s = requests.Session()
            r = s.get(url, verify=False, headers={'User-Agent': PickRandomUA(uas)}, proxies=proxies)
            if r.status_code != 200:
                 print "[-] Something is going wrong (status code: {})".format(r.status_code)
                 return [], []
            results += r.content
        except Exception,e:
            print e

        time.sleep(PickRandomTimeout(timeouts))
        counter += step

    return GetEmails(results, value), GetHostnames(results, value)

#######################################################

## Common search ##

def CommonSearch2(value, urltemplate, step, limit, uas, proxies, timeouts):

    counter = 1
    results = ""

    while counter <= limit:
        try:
            url = urltemplate.format(counter=counter, value=value)
            s = requests.Session()
            r = s.get(url, verify=False, headers={'User-Agent': PickRandomUA(uas)}, proxies=proxies)
            if r.status_code != 200:
                 print "[-] Something is going wrong (status code: {})".format(r.status_code)
                 return [], []
            results += r.content
        except Exception,e:
            print e

        time.sleep(PickRandomTimeout(timeouts))
        counter += step

    return GetEmails(results, value), GetHostnames(results, value)

#######################################################

## Google search ##

def GoogleSearch(value, limit, uas, proxies, timeouts):

    quantity = 100
    step = 100
    url = "https://www.google.com/search?num={quantity}&start={counter}&hl=en&meta=&q=%40%22{value}%22"

    return CommonSearch(value, url, quantity, step, limit, uas, proxies, timeouts)

#######################################################

## Bing search ##

def BingSearch(value, limit, uas, proxies, timeouts):

    quantity = 50
    step = 50
    url = "https://www.bing.com/search?q=%40{value}&count={quantity}&first={counter}"

    return CommonSearch(value, url, quantity, step, limit, uas, proxies, timeouts)

#######################################################

## ASK search ##

def AskSearch(value, limit, uas, proxies, timeouts):

    step = 1
    url = "https://www.ask.com/web?q=%40%22{value}%22&page={counter}"

    return CommonSearch2(value, url, step, limit, uas, proxies, timeouts)

#######################################################

## Dogpile search ##

def DogpileSearch(value, limit, uas, proxies, timeouts):

    step = 15
    url = "https://www.dogpile.com/search/web?qsi={counter}&q=%40{value}"

    return CommonSearch2(value, url, step, limit, uas, proxies, timeouts)

#######################################################

## Yahoo search ##

def YahooSearch(value, limit, uas, proxies, timeouts):

    step = 10
    url = "https://search.yahoo.com/search?p=%40{value}&b={counter}&pz=10"

    return CommonSearch2(value, url, step, limit, uas, proxies, timeouts)

#######################################################

## Yandex search ##

def YandexSearch(value, limit, uas, proxies, timeouts):

    server = "yandex.com"
    quantity = 50
    step = 50
    results = ""
    page = 0
    counter = 0

    while counter <= limit:
        try:
            url = "https://" + server + "/search/?text=%22%40" + value + "%22&numdoc=" + str(quantity) + "&p=" + str(page) + "&lr=10418"
            s = requests.Session()
            r = s.get(url, verify=False, headers={'User-Agent': PickRandomUA(uas)}, proxies=proxies)
            if r.status_code != 200:
                 print "[-] Something is going wrong (status code: {})".format(r.status_code)
                 return [], []
            results += r.content
        except Exception,e:
            print e

        time.sleep(PickRandomTimeout(timeouts))
        counter += step
        page += 1

    return GetEmails(results, value), GetHostnames(results, value)

#######################################################

## CRT search ##

def CrtSearch(value, uas, proxies):

    server = "crt.sh"
    results = ""

    try:
        url = "https://" + server + "/?q=%25" + value
        s = requests.Session()
        r = s.get(url, verify=False, headers={'User-Agent': PickRandomUA(uas)}, proxies=proxies)
        if r.status_code != 200:
             print "[-] Something is going wrong (status code: {})".format(r.status_code)
             return [], []
        results += r.content
    except Exception,e:
        print e

    return GetHostnames(results, value)

#######################################################

## DNSdumpster search ##

def DNSDumpsterSearch(value, uas, proxies):

    server = "dnsdumpster.com"
    results = ""
    timeout = 25

    try:
        url = "https://" + server + "/"
        s = requests.Session()
        myheaders={'User-Agent': PickRandomUA(uas), 'Referer': 'https://dnsdumpster.com'}
        r = s.get(url, verify=False, headers=myheaders, proxies=proxies, timeout=timeout)
        if r.status_code != 200:
             print "[-] Something is going wrong (status code: {})".format(r.status_code)
             return [], []

        # get csrf token
        csrf_regex = re.compile("<input type='hidden' name='csrfmiddlewaretoken' value='(.*?)' />", re.S)
        token = csrf_regex.findall(r.content)[0]
        token = token.strip()

        params = {'csrfmiddlewaretoken': token, 'targetip': value}
        pr = s.post(url, verify=False, headers=myheaders, proxies=proxies, data=params, timeout=timeout)
        if pr.status_code != 200:
             print "[-] Something is going wrong (status code: {})".format(pr.status_code)
             return [], []

    except Exception,e:
        print e

    return GetDNSDumpsterHostnames(value, pr.content)

#######################################################

## PGP search ##

def PGPSearch(value, uas, proxies):

    server = "pgp.mit.edu"
    results = ""

    try:
        url = "https://" + server + "/pks/lookup?search=" + value + "&op=index"
        s = requests.Session()
        r = s.get(url, verify=False, headers={'User-Agent': PickRandomUA(uas)}, proxies=proxies)
        if r.status_code != 200:
             print "[-] Something is going wrong (status code: {})".format(r.status_code)
             return [], []
        results += r.content
    except Exception,e:
        print e

    return GetEmails(results, value), GetHostnames(results, value)

#######################################################

## Netcraft search ##

def NetcraftSearch(value, uas, proxies):

    server = "searchdns.netcraft.com"
    results = ""

    try:
        url = "https://" + server + "?restriction=site+ends+with&host=" + value
        s = requests.Session()
        r = s.get(url, verify=False, headers={'User-Agent': PickRandomUA(uas)}, proxies=proxies)
        if r.status_code != 200:
             print "[-] Something is going wrong (status code: {})".format(r.status_code)
             return [], []
        results += r.content
    except Exception,e:
        print e

    return GetHostnames(results, value)

#######################################################

## virustotal search ##

def VTSearch(value, uas, proxies):

    server = "www.virustotal.com"
    results = ""

    try:
        url = "https://" + server + "/en/domain/" + value + "/information/"
        s = requests.Session()
        r = s.get(url, verify=False, headers={'User-Agent': PickRandomUA(uas)}, proxies=proxies)
        if r.status_code != 200:
             print "[-] Something is going wrong (status code: {})".format(r.status_code)
             return [], []
        results += r.content
    except Exception,e:
        print e

    return GetHostnames(results, value)

#######################################################

## site: + Google search ##

def SiteSearch(value, site, limit, uas, proxies, timeouts):

    server = "www.google.com"
    quantity = 100
    counter = 0
    step = 100
    results = ""

    while counter <= limit:
        try:
            url = "https://" + server + "/search?num=" + str(quantity) + "&start=" + str(counter) + "&hl=en&meta=&q=site%3A" + site + "%20%40%22" + value + "%22"
            s = requests.Session()
            r = s.get(url, verify=False, headers={'User-Agent': PickRandomUA(uas)}, proxies=proxies)
            if r.status_code != 200:
                 print "[-] Something is going wrong (status code: {})".format(r.status_code)
                 return [], []
            results += r.content
        except Exception,e:
            print e

        time.sleep(PickRandomTimeout(timeouts))
        counter += step

    return GetEmails(results, value), GetHostnames(results, value)
    

#######################################################

## Censys.io search ##

def CensysSearch(value, api_id, api_secret):
    try:
        censys_certificates = censys.certificates.CensysCertificates(api_id=api_id, api_secret=api_secret)
        certificate_query = 'parsed.names: %s' % value
        certificates_search_results = censys_certificates.search(certificate_query, fields=['parsed.names'])
        subdomains = []
        for search_result in certificates_search_results:
            subdomains.extend(search_result['parsed.names'])
        
        return set(subdomains)
    except censys.base.CensysUnauthorizedException:
        sys.stderr.write('[-] Your Censys credentials look invalid.\n')
        exit(1)
    except censys.base.CensysRateLimitExceededException:
        sys.stderr.write('[-] Looks like you exceeded your Censys account limits rate. Exiting\n')
        exit(1)

#######################################################

## Bing Virtual Hosts ##

def BingVHostsSearch(value, limit, uas, proxies, timeouts):

    server = "www.bing.com"
    quantity = 50
    step = 50
    counter = 0
    results = ""
    vhosts = []

    while counter <= limit:
        try:
            url = "https://" + server + "/search?q=ip%3A" + value + "&go=&count=" + str(quantity) + "&FORM=QBHL&qs=n&first=" + str(counter)
            s = requests.Session()
            r = s.get(url, verify=False, headers={'User-Agent': PickRandomUA(uas)}, proxies=proxies)
            if r.status_code != 200:
                 print "[-] Something is going wrong (status code: {})".format(r.status_code)
                 return [], []
            results += r.content
        except Exception,e:
            print e

        time.sleep(PickRandomTimeout(timeouts))
        counter += step

    all_hostnames = GetHostnamesAll(results)

    for x in all_hostnames:
        x = re.sub(r'[[\<\/?]*[\w]*>]*','',x)
        x = re.sub('<','',x)
        x = re.sub('>','',x)
        vhosts.append(x)

    return sorted(set(vhosts))

#######################################################

## Emails & Hostnames Console report ##

def Report(engine, emails, hostnames, output_basename):

    print
    print "Emails:"
    for email in emails:
        print email

    print
    print "Hostnames:"
    for host in hostnames:
        print host
    print

    if output_basename:
        output1 = output_basename + ".txt"
        output2 = output_basename + ".md"
        output3 = output_basename + ".xml"
        output4 = output_basename + ".html"

        with open(output1, 'a') as txt, open(output2, 'a') as md, open(output3, 'a') as xml, open(output4, 'a') as html:
            txt.write("[+] {} results\n".format(engine))
            txt.write("-------------------------\n")
            md.write("---\n\n")
            md.write("## {} results\n".format(engine))
            xml.write("<{}Results>\n".format(engine))
            html.write("<h3>{} results</h3>\n".format(engine))

            txt.write("\n")
            md.write("\n")

            txt.write("Emails:\n")
            md.write("### Emails\n\n")
            xml.write("<Emails>\n")
            html.write("<h4>Emails</h4>\n<ul>\n")

            for email in emails:
                txt.write("{}\n".format(email))
                md.write("* {}\n".format(email))
                xml.write("<email>{}</email>\n".format(email))
                html.write("<li>{}</li>\n".format(email))

            html.write("</ul>\n")
            xml.write("</Emails>\n")
            txt.write("\n")
            md.write("\n")

            txt.write("Hostnames:\n")
            md.write("### Hostnames\n\n")
            xml.write("<Hostnames>\n")
            html.write("<h4>Hostnames</h4>\n<ul>\n")

            for host in hostnames:
                txt.write("{}\n".format(host))
                md.write("* {}\n".format(host))
                xml.write("<hostname>{}</hostname>\n".format(host))
                html.write("<li>{}</li>\n".format(host))

            html.write("</ul>\n")
            xml.write("</Hostnames>\n")
            txt.write("\n")
            md.write("\n")
            xml.write("</{}Results>\n".format(engine))

#######################################################

## Hostnames Console report ##

def HostnamesReport(engine, hostnames, output_basename):

    print
    print "Hostnames:"
    for host in hostnames:
        print host
    print

    if output_basename:
        output1 = output_basename + ".txt"
        output2 = output_basename + ".md"
        output3 = output_basename + ".xml"
        output4 = output_basename + ".html"

        with open(output1, 'a') as txt, open(output2, 'a') as md, open(output3, 'a') as xml, open(output4, 'a') as html:
            txt.write("[+] {} results\n".format(engine))
            txt.write("-------------------------\n")
            md.write("---\n\n")
            md.write("## {} results\n".format(engine))
            xml.write("<{}Results>\n".format(engine))
            html.write("<h3>{} results</h3>\n".format(engine))

            txt.write("\n")
            md.write("\n")

            txt.write("Hostnames:\n")
            md.write("### Hostnames\n\n")
            xml.write("<Hostnames>\n")
            html.write("<h4>Hostnames</h4>\n<ul>\n")

            for host in hostnames:
                txt.write("{}\n".format(host))
                md.write("* {}\n".format(host))
                xml.write("<hostname>{}</hostname>\n".format(host))
                html.write("<li>{}</li>\n".format(host))

            html.write("</ul>\n")
            xml.write("</Hostnames>\n")
            txt.write("\n")
            md.write("\n")
            xml.write("</{}Results>\n".format(engine))

#######################################################

## Information Console report ##

def InfoReport(mode, limit, dnsserver, proxy, domain, ip, uas, output_basename):

    print "[+] Information gathering: {}".format(mode)
    print "[+] Looking into first {} search engines results".format(limit)
    print "[+] Using DNS server: {}".format(dnsserver)
    if proxy:
        print "[+] Using Proxy server: {}".format(proxy)
    print "[+] Target: {}:{}".format(domain, ip)
    print "[+] User-agent strings: {}".format(uas)
    print

    if output_basename:
        output1 = output_basename + ".txt"
        output2 = output_basename + ".md"
        output3 = output_basename + ".xml"
        output4 = output_basename + ".html"

        with open(output1, 'w') as txt, open(output2, 'w') as md, open(output3, 'w') as xml, open(output4, 'w') as html:
            txt.write("{}\n".format(message))
            md.write("```\n")
            md.write("{}\n".format(message))
            md.write("```\n\n")
            xml.write('<!--\n{}\n-->\n'.format(message))
            xml.write('<?xml version="1.0" encoding="UTF-8"?>\n')
            xml.write("<report>\n")
            xml.write("<information>\n")
            html.write("<!DOCTYPE html><html><head><title>GasMasK Report</title></head><body>\n")
            html.write("<pre>{}</pre>\n</br>\n<ul>\n".format(message))

            txt.write("[+] Information gathering: {}\n".format(",".join(mode)))
            md.write("---\n\n")
            md.write("* Information gathering: {}\n".format(",".join(mode)))
            html.write("<li>Information gathering: <b>{}</b></li>\n".format(",".join(mode)))
            xml.write("<InformationGathering>\n")

            for m in mode:
                xml.write("<query>{}</query>\n".format(m))
            xml.write("</InformationGathering>\n")

            txt.write("[+] Looking into first {} search engine results\n".format(limit))
            md.write("* Looking into first {} search engine results\n".format(limit))
            xml.write("<SearchEngineResults>{}</SearchEngineResults>\n".format(limit))
            html.write("<li>Search Engine Results: <b>{}</b></li>\n".format(limit))

            txt.write("[+] Using DNS server: {}\n".format(dnsserver))
            md.write("* Using DNS server: {}\n".format(dnsserver))
            xml.write("<DNSServer>{}</DNSServer>\n".format(dnsserver))
            html.write("<li>Using DNS server: <b>{}</b></li>\n".format(dnsserver))

            if proxy:
                txt.write("[+] Using Proxy server: {}\n".format(proxy))
                md.write("* Using Proxy server: {}\n".format(proxy))
                xml.write("<ProxyServer>{}</ProxyServer>\n".format(proxy))
                html.write("<li>Using Proxy server: <b>{}</b></li>\n".format(proxy))

            txt.write("[+] Target: {}:{}\n".format(domain, ip))
            md.write("* Target: {}:{}\n".format(domain, ip))
            xml.write("<Target>\n")
            xml.write("<Domain>{}</Domain>\n".format(domain))
            xml.write("<IP>{}</IP>\n".format(ip))
            xml.write("</Target>\n")
            html.write("<li>Target: <b>{}:{}</b></li>\n".format(domain, ip))

            txt.write("[+] User-agent strings: {}\n".format(uas))
            md.write("* User-agent strings: {}\n".format(uas))
            xml.write("<UserAgentStrings>{}</UserAgentStrings>\n".format(uas))
            html.write("<li>User-agent strings: <b>{}</b></li>\n".format(uas))

            txt.write("\n")
            md.write("\n")
            xml.write("</information>\n")
            html.write("</ul>\n")

#######################################################

## Whois Console report ##

def WhoisReport(data, output_basename):

    for key,value in data.iteritems():
        if isinstance(value[0], list):
            print
            print value[1]
            for val in value[0]:
                print val
            print
        else:
            print value[1] + " " + value[0]
    print

    if output_basename:
        output1 = output_basename + ".txt"
        output2 = output_basename + ".md"
        output3 = output_basename + ".xml"
        output4 = output_basename + ".html"

        with open(output1, 'a') as txt, open(output2, 'a') as md, open(output3, 'a') as xml, open(output4, 'a') as html:
            txt.write("[+] Whois lookup\n")
            txt.write("----------------\n")
            md.write("---\n\n")
            md.write("## Whois lookup\n\n")
            xml.write("<Whois>\n")
            html.write("<h3>Whois lookup</h3>\n<ul>\n")

            for key,value in data.iteritems():
                if isinstance(value[0], list):
                    txt.write("\n")
                    md.write("\n")

                    txt.write("{}\n".format(value[1]))
                    md.write("* {}\n".format(value[1]))
                    xml.write("<{}>\n".format(key))
                    html.write("<li>{}</li>\n<ul>\n".format(value[1]))

                    for val in value[0]:
                        txt.write("{}\n".format(val))
                        md.write("  * {}\n".format(val))
                        xml.write("<data>{}</data>\n".format(val))
                        html.write("<li><b>{}</b></li>\n".format(val))

                    xml.write("</{}>\n".format(key))
                    html.write("</ul>\n")

                    txt.write("\n")
                    md.write("\n")
                else:
                    txt.write("{} {}\n".format(value[1], value[0]))
                    md.write("* {} {}\n".format(value[1], value[0]))
                    xml.write("<{}>{}</{}>\n".format(key, value[0], key))
                    html.write("<li>{} <b>{}</b></li>\n".format(value[1], value[0]))

            txt.write("\n")
            md.write("\n")
            xml.write("</Whois>\n")
            html.write("</ul>\n")

#######################################################

## DNS Console report ##

def DNSReport(data, output_basename):

    for key,value in data.iteritems():
        if(len(value) == 1):
            print key + " DNS record: " + value[0]
        else:
            print
            print key + " DNS record: "
            for val in value:
                print val
            print
    print

    if output_basename:
        output1 = output_basename + ".txt"
        output2 = output_basename + ".md"
        output3 = output_basename + ".xml"
        output4 = output_basename + ".html"

        with open(output1, 'a') as txt, open(output2, 'a') as md, open(output3, 'a') as xml, open(output4, 'a') as html:
            txt.write("[+] DNS queries\n")
            txt.write("---------------\n")
            md.write("---\n\n")
            md.write("## DNS queries\n\n")
            xml.write("<DNSQueries>\n")
            html.write("<h3>DNS queries</h3>\n<ul>\n")

            for key,value in data.iteritems():
                if(len(value) == 1):
                    txt.write("{} DNS record: {}\n".format(key, value[0]))
                    md.write("* {} DNS record: {}\n".format(key, value[0]))
                    xml.write("<{}>{}</{}>\n".format(key, value[0], key))
                    html.write("<li>{} DNS record: <b>{}</b></li>\n".format(key, value[0]))

                else:
                    txt.write("\n")
                    md.write("\n")

                    txt.write("{} DNS record:\n".format(key))
                    md.write("* {} DNS record:\n".format(key))
                    xml.write("<{}>\n".format(key))
                    html.write("<li>{} DNS record:</li>\n<ul>\n".format(key))

                    for val in value:
                        txt.write("{}\n".format(val))
                        md.write("  * {}\n".format(val))
                        xml.write("<data>{}</data>\n".format(val))
                        html.write("<li><b>{}</b></li>\n".format(val))

                    html.write("</ul>\n")
                    md.write("</{}>\n".format(key))
                    txt.write("\n")
                    md.write("\n")

            txt.write("\n")
            md.write("\n")
            xml.write("</DNSQueries>\n")
            html.write("</ul>\n")
            
#######################################################

## Reverse DNS Console report ##

def ReverseDNSReport(ip, data, output_basename):

    if data:
        print ip + ":" + data
    print

    if output_basename:
        output1 = output_basename + ".txt"
        output2 = output_basename + ".md"
        output3 = output_basename + ".xml"
        output4 = output_basename + ".html"

        with open(output1, 'a') as txt, open(output2, 'a') as md, open(output3, 'a') as xml, open(output4, 'a') as html:
            txt.write("[+] Reverse DNS Lookup\n")
            txt.write("----------------------\n")
            md.write("---\n\n")
            md.write("## Reverse DNS Lookup\n\n")
            xml.write("<ReverseDNSLookup>\n")
            html.write("<h3>Reverse DNS Lookup</h3>\n")

            if data:
                txt.write("{}:{}\n".format(ip, data))
                md.write("* {}:{}\n".format(ip, data))
                xml.write("<IP>{}</IP>\n".format(ip))
                xml.write("<Domain>{}</Domain>\n".format(data))
                html.write("<ul><li>{}:{}</li></ul>\n".format(ip, data))

            txt.write("\n")
            md.write("\n")
            xml.write("</ReverseDNSLookup>\n")

#######################################################

## VHosts Console report ##

def VHostsReport(data, output_basename):

    for host in data:
        print host
    print

    if output_basename:
        output1 = output_basename + ".txt"
        output2 = output_basename + ".md"
        output3 = output_basename + ".xml"
        output4 = output_basename + ".html"

        with open(output1, 'a') as txt, open(output2, 'a') as md, open(output3, 'a') as xml, open(output4, 'a') as html:
            txt.write("[+] Bing Virtual Hosts\n")
            txt.write("----------------------\n")
            md.write("---\n\n")
            md.write("## Bing Virtual Hosts\n\n")
            xml.write("<BingVHosts>\n")
            html.write("<h3>Bing Virtual Hosts</h3>\n<ul>\n")

            for host in data:
                txt.write("{}\n".format(host))
                md.write("* {}\n".format(host))
                xml.write("<host>{}</host>\n".format(host))
                html.write("<li>{}</li>\n".format(host))

            txt.write("\n")
            md.write("\n")
            xml.write("</BingVHosts>\n")
            html.write("</ul>\n")

#######################################################

## All major formats final report ##

def FinalReport(info, output_basename):

    print
    print "[+] Search engines results - Final Report"
    print "-----------------------------------------"

    print
    print "Emails:"
    for email in info['all_emails']:
        print email

    print
    print "Hostnames:"
    for host in info['all_hosts']:
        print host
    print

    if output_basename:
        output1 = output_basename + ".txt"
        output2 = output_basename + ".md"
        output3 = output_basename + ".xml"
        output4 = output_basename + ".html"

        with open(output1, 'a') as txt, open(output2, 'a') as md, open(output3, 'a') as xml, open(output4, 'a') as html:
            txt.write("[+] Search engines results - Final Report\n")
            txt.write("-----------------------------------------\n")
            md.write("---\n\n")
            md.write("## Search engines results - Final Report\n")
            xml.write("<FinalReport>\n")
            html.write("<h3>Search engines results - Final Report</h3>\n")

            txt.write("\n")
            md.write("\n")

            txt.write("Emails:\n")
            md.write("### Emails\n\n")
            xml.write("<Emails>\n")
            html.write("<h4>Emails</h4>\n<ul>\n")

            for email in info['all_emails']:
                txt.write("{}\n".format(email))
                md.write("* {}\n".format(email))
                xml.write("<email>{}</email>\n".format(email))
                html.write("<li>{}</li>\n".format(email))

            html.write("</ul>\n")
            xml.write("</Emails>\n")
            txt.write("\n")
            md.write("\n")

            txt.write("Hostnames:\n")
            md.write("### Hostnames\n\n")
            xml.write("<Hostnames>\n")
            html.write("<h4>Hostnames</h4>\n<ul>\n")

            for host in info['all_hosts']:
                txt.write("{}\n".format(host))
                md.write("* {}\n".format(host))
                xml.write("<hostname>{}</hostname>\n".format(host))
                html.write("<li>{}</li>\n".format(host))

            html.write("</ul>\n")
            xml.write("</Hostnames>\n")
            txt.write("\n")
            md.write("\n")
            xml.write("</FinalReport>\n")

#######################################################

## Main Function ##

def MainFunc():

    print message

    info = {}
    info['all_emails'] = []
    info['all_hosts'] = []
    uas = []

    user_agent_strings_file = 'common-ua.txt'
    timeouts = [5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]

    modes = ['basic','whois', 'dns', 'revdns', 'vhosts', 'google', 'bing', 'yahoo','ask', 'dogpile', 'yandex','censys.io', 'linkedin', 'twitter', 'googleplus', 'youtube', 'reddit','github', 'instagram', 'crt', 'pgp', 'netcraft', 'virustotal', 'dnsdump']
    
    parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter)
    parser.add_argument("-d", '--domain', action="store", metavar='DOMAIN', dest='domain',default=None, type=CheckDomain, help="Domain to search.", required=True)
    parser.add_argument("-s", '--server', action="store", metavar='NAMESERVER', dest='dnsserver',default='8.8.8.8', type=CheckDomainOrIP, help="DNS server to use.")
    parser.add_argument('-x', '--proxy', action="store", metavar='PROXY', dest='proxy',default=None, type=str, help="Use a proxy server when retrieving results from search engines (eg. '-x http://127.0.0.1:8080')")
    parser.add_argument("-l", '--limit', action="store", metavar='LIMIT', dest='limit',type=int, default=100, help="Limit the number of search engine results (default: 100).")
    parser.add_argument("-i", '--info', action="store", metavar='MODE', dest='mode',type=str, default='basic', help="Limit information gathering (" + ','.join(modes) + ").")
    parser.add_argument('-o', '--output', action='store', metavar='BASENAME', dest='basename',type=str, default=None, help='Output in the four major formats at once (markdown, txt, xml and html).')
    parser.add_argument('--censys-api-id',action='store', dest='censys_api_id',type=str, default=None, help='Provide the authentication ID for the censys.io search engine')
    parser.add_argument('--censys-api-secret',action='store', dest='censys_api_secret',type=str, default=None, help='Provide the secret hash for the censys.io search engine')

    if len(sys.argv) is 1:
        parser.print_help()
        sys.exit()

    args = parser.parse_args()

    info['domain'] = args.domain
    info['proxies'] = {}

#######################################################

## Load User-Agents strings from file ##

    if os.path.isfile(user_agent_strings_file):
        uas = [line.strip() for line in open(user_agent_strings_file)]
    else:
        print "[-] An error occured while loading user-agent strings from file"
        sys.exit()

    output_basename = None
    if args.basename is not None:
        output_basename = args.basename

#######################################################

## information ##

    info['mode'] = [x.strip() for x in args.mode.lower().split(',')]
    info['limit'] = args.limit
    info['dnsserver'] = args.dnsserver
    info['ip'] = VerifyHostname(info['domain'])

    if args.proxy:
        print "[+] Proxy will ONLY be used during search engines searches"
        info['proxies'] = {
              'http': args.proxy,
              'https': args.proxy,
          }

    InfoReport(info['mode'], info['limit'], info['dnsserver'], args.proxy, info['domain'], info['ip'], len(uas), output_basename)

#######################################################

## Whois query report ##

    if any(i in ['whois', 'basic'] for i in info['mode']):
        print "[+] Whois lookup"
        print "----------------"
        info['whois'] = WhoisQuery(info['domain'])
        WhoisReport(info['whois'], output_basename)

#######################################################

## DNS records report ##

    if any(i in ['dns', 'basic'] for i in info['mode']):
        print "[+] DNS queries"
        print "---------------"
        info['dns'] = DnsQuery(info['domain'], info['dnsserver'])
        DNSReport(info['dns'], output_basename)

#######################################################

## IP Reverse DNS lookup report ##

    if any(i in ['revdns', 'basic'] for i in info['mode']):
        print "[+] Reverse DNS Lookup"
        print "----------------------"
        info['revdns'] = ReverseIPQuery(info['ip'], info['dnsserver'])
        ReverseDNSReport(info['ip'], info['revdns'], output_basename)

#######################################################

# Bing Virtual Hosts search results report ##

    if any(i in ['vhosts', 'basic'] for i in info['mode']):
        print "[+] Bing Virtual Hosts"
        print "----------------------"
        info['bingvhosts'] = BingVHostsSearch(info['ip'], info['limit'], uas, info['proxies'], timeouts)
        VHostsReport(info['bingvhosts'], output_basename)

#######################################################

## Google search ##

    if any(i in ['google'] for i in info['mode']):
        print "[+] Searching in Google.."
        temp1, temp2 = GoogleSearch(info['domain'], info['limit'], uas, info['proxies'], timeouts)
        info['all_emails'].extend(temp1)
        info['all_hosts'].extend(temp2)
        Report("Google", temp1, temp2, output_basename)

#######################################################

## Bing search ##

    if any(i in ['bing'] for i in info['mode']):
        print "[+] Searching in Bing.."
        temp1, temp2 = BingSearch(info['domain'], info['limit'], uas, info['proxies'], timeouts)
        info['all_emails'].extend(temp1)
        info['all_hosts'].extend(temp2)
        Report("Bing", temp1, temp2, output_basename)

#######################################################

## Yahoo search ##

    if any(i in ['yahoo'] for i in info['mode']):
        print "[+] Searching in Yahoo.."
        temp1, temp2 = YahooSearch(info['domain'], info['limit'], uas, info['proxies'], timeouts)
        info['all_emails'].extend(temp1)
        info['all_hosts'].extend(temp2)
        Report("Yahoo", temp1, temp2, output_basename)

#######################################################

## ASK search ##

    if any(i in ['ask'] for i in info['mode']):
        print "[+] Searching in ASK.."
        temp1, temp2 = AskSearch(info['domain'], 5, uas, info['proxies'], timeouts) #5 pages
        info['all_emails'].extend(temp1)
        info['all_hosts'].extend(temp2)
        Report("ASK", temp1, temp2, output_basename)

#######################################################

## Dogpile search ##

    if any(i in ['dogpile'] for i in info['mode']):
        print "[+] Searching in Dogpile.."
        temp1, temp2 = DogpileSearch(info['domain'], info['limit'], uas, info['proxies'], timeouts)
        info['all_emails'].extend(temp1)
        info['all_hosts'].extend(temp2)
        Report("Dogpile", temp1, temp2, output_basename)

#######################################################

## Yandex search ##

    if any(i in ['yandex'] for i in info['mode']):
        print "[+] Searching in Yandex.."
        temp1, temp2 = YandexSearch(info['domain'], info['limit'], uas, info['proxies'], timeouts)
        info['all_emails'].extend(temp1)
        info['all_hosts'].extend(temp2)
        Report("Yandex", temp1, temp2, output_basename)

#######################################################

## crt search ##

    if any(i in ['crt'] for i in info['mode']):
        print "[+] Searching in Crt.."
        temp = CrtSearch(info['domain'], uas, info['proxies'])
        info['all_hosts'].extend(temp)
        HostnamesReport("CRT", temp, output_basename)

#######################################################

## dnsdumpster search ##

    if any(i in ['dnsdump'] for i in info['mode']):
        print "[+] Searching in DNSdumpster.."
        temp = DNSDumpsterSearch(info['domain'], uas, info['proxies'])
        info['all_hosts'].extend(temp)
        HostnamesReport("DNSdumpster", temp, output_basename)

#######################################################

## PGP search ##

    if any(i in ['pgp'] for i in info['mode']):
        print "[+] Searching in PGP.."
        temp1, temp2 = PGPSearch(info['domain'], uas, info['proxies'])
        info['all_emails'].extend(temp1)
        info['all_hosts'].extend(temp2)
        Report("PGP", temp1, temp2, output_basename)

#######################################################

## netcraft search ##

    if any(i in ['netcraft'] for i in info['mode']):
        print "[+] Searching in Netcraft.."
        temp = NetcraftSearch(info['domain'], uas, info['proxies'])
        info['all_hosts'].extend(temp)
        HostnamesReport("Netcraft", temp, output_basename)

#######################################################

## virustotal search ##

    if any(i in ['virustotal'] for i in info['mode']):
        print "[+] Searching in VirusTotal.."
        temp = VTSearch(info['domain'], uas, info['proxies'])
        info['all_hosts'].extend(temp)
        HostnamesReport("VirusTotal", temp, output_basename)

#######################################################

## LinkedIn search ##

    if any(i in ['linkedin'] for i in info['mode']):
        print "[+] Searching in LinkedIn.."
        temp1, temp2 = SiteSearch(info['domain'], 'linkedin.com', info['limit'], uas, info['proxies'], timeouts)
        info['all_emails'].extend(temp1)
        info['all_hosts'].extend(temp2)
        Report("LinkedIn", temp1, temp2, output_basename)

#######################################################

## Twitter search ##

    if any(i in ['twitter'] for i in info['mode']):
        print "[+] Searching in Twitter.."
        temp1, temp2 = SiteSearch(info['domain'], "twitter.com", info['limit'], uas, info['proxies'], timeouts)
        info['all_emails'].extend(temp1)
        info['all_hosts'].extend(temp2)
        Report("Twitter", temp1, temp2, output_basename)

#######################################################

## Google+ search ##

    if any(i in ['googleplus'] for i in info['mode']):
        print "[+] Searching in Google+.."
        temp1, temp2 = SiteSearch(info['domain'], "plus.google.com", info['limit'], uas, info['proxies'], timeouts)
        info['all_emails'].extend(temp1)
        info['all_hosts'].extend(temp2)
        Report("Google+", temp1, temp2, output_basename)

#######################################################

## Youtube search ##

    if any(i in ['youtube'] for i in info['mode']):
        print "[+] Searching in Youtube.."
        temp1, temp2 = SiteSearch(info['domain'], "youtube.com", info['limit'], uas, info['proxies'], timeouts)
        info['all_emails'].extend(temp1)
        info['all_hosts'].extend(temp2)
        Report("Youtube", temp1, temp2, output_basename)

#######################################################

## Reddit search ##

    if any(i in ['reddit'] for i in info['mode']):
        print "[+] Searching in Reddit.."
        temp1, temp2 = SiteSearch(info['domain'], "reddit.com", info['limit'], uas, info['proxies'], timeouts)
        info['all_emails'].extend(temp1)
        info['all_hosts'].extend(temp2)
        Report("Reddit", temp1, temp2, output_basename)

#######################################################

## Github search ##

    if any(i in ['github'] for i in info['mode']):
        print "[+] Searching in Github.."
        temp1, temp2 = SiteSearch(info['domain'], "github.com", info['limit'], uas, info['proxies'], timeouts)
        info['all_emails'].extend(temp1)
        info['all_hosts'].extend(temp2)
        Report("Github", temp1, temp2, output_basename)

#######################################################

## Instagram search ##

    if any(i in ['instagram'] for i in info['mode']):
        print "[+] Searching in Instagram.."
        temp1, temp2 = SiteSearch(info['domain'], "instagram.com", info['limit'], uas, info['proxies'], timeouts)
        info['all_emails'].extend(temp1)
        info['all_hosts'].extend(temp2)
        Report("Instagram", temp1, temp2, output_basename)

#######################################################

## Search Results Final Report ##

    info['all_emails'] = sorted(set(info['all_emails']))
    info['all_hosts'] = sorted(set(info['all_hosts']))
    FinalReport(info, output_basename)

#######################################################

## Close tags for xml and html ##

    if output_basename:
        output = output_basename + ".xml"
        output1 = output_basename + ".html"

        with open(output, 'a') as xml, open(output1, 'a') as html:
            xml.write("</report>\n")
            html.write("</body></html>\n")

#######################################################

## Censys.io search ##

    if any(i in ['censys'] for i in info['mode']):
        print "[+] Searching in Censys.io.."
        temp1 = CensysSearch(info['domain'], info['censys_api_id'], info['censys_api_secret'])
        info['domain'].extend(temp1)
        #info['all_hosts'].extend(temp2)
        #Report("Censys", temp1, temp2, output_basename)

#######################################################


if __name__ == '__main__':

    try:
        MainFunc()
    except KeyboardInterrupt:
        print "Search interrupted by user.."
    except:
        sys.exit()

#######################################################
