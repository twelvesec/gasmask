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
__credits__ = ["maldevel", "mikismaos", "xvass", "ndamoulianos", "sbrb"]
__license__ = "GPLv3"
__version__ = "2.0"

#######################################################

import argparse
import json
import mmap
import tempfile
from argparse import RawTextHelpFormatter
from pathlib import Path

import censys.certificates
import validators
import sys
import socket
import whois
import dns.resolver
import collections
import re
import os
import random

from censys.base import CensysException
from censys.ipv4 import CensysIPv4
from colorama import Style, Fore
from dns import reversename
import requests
import time
import shodan
import pprint
# import pdb

#######################################################

# remove insecure https warning
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#######################################################

message = """
___________              .__                _________              
\__    ___/_  _  __ ____ |  |___  __ ____  /   _____/ ____   ____  
  |    |  \ \/ \/ // __ \|  |\  \/ // __ \ \_____  \_/ __ \_/ ___\ 
  |    |   \     /\  ___/|  |_\   /\  ___/ /        \  ___/\  \___ 
  |____|    \/\_/  \___  >____/\_/  \___  >_______  /\___  >\___  >
                       \/               \/        \/     \/     \/ 

GasMasK v. {} - All in one Information gathering tool - OSINT
GasMasK is an open source tool licensed under GPLv3.
Written by: @maldevel, mikismaos, xvass, ndamoulianos, sbrb
https://www.twelvesec.com/
Please visit https://github.com/twelvesec/gasmask for more..
""".format(__version__)


# ######################  Global Variables ##################  #

pp = pprint.PrettyPrinter(indent=4)
KEYS_FILE = Path(__file__).parent.absolute().joinpath('api_keys.txt')
DEBUG = True


# ######################  Censys.io  ######################### #

def print_short(res):
    """
    Build Short results - Censys.io
    :param res: results, type: `dict`
    :return:
    """
    max_title_len = 50
    # public_info = []
    title_head = 'Title: '
    cut = '[...]'
    http_title = res.get('80.http.get.title', 'N/A')
    cert_name = res.get('443.https.tls.certificate.parsed.subject.common_name', '')
    cert_alt = res.get('443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names',
                       '')
    as_name = res.get('autonomous_system.name', 'N/A')
    as_num = res.get('autonomous_system.asn', '')
    loc = '%s / %s' % (res.get('location.country_code', 'N/A'), res.get('location.city', 'N/A'))
    os = res.get('metadata.os', 'N/A')
    tags = res.get('tags', '')
    ip = res.get('ip', 'N/A')

    http_title = http_title.replace('\n', '\\n')
    http_title = http_title.replace('\r', '\\r')

    # cleanup of list values
    if isinstance(cert_name, list):
        if len(cert_name) > 1:
            cert_name = cert_name[0] + "+"
        else:
            cert_name = cert_name[0]
    if isinstance(cert_alt, list):
        if len(cert_alt) > 1:
            cert_alt = cert_alt[0] + "+"
        else:
            cert_alt = cert_alt[0]

    # encoding to UTF-8
    http_title = str(http_title.encode('UTF-8'), errors='ignore')
    cert_name = str(cert_name.encode('UTF-8'), errors='ignore')
    cert_alt = str(cert_alt.encode('UTF-8'), errors='ignore')
    tags = ', '.join([str(t.encode('UTF-8'), errors='ignore') for t in tags])
    as_name = str(as_name.encode('UTF-8'), errors='ignore')
    os = str(os.encode('UTF-8'), errors='ignore')
    loc = str(loc.encode('UTF-8'), errors='ignore')

    if cert_alt != '' and cert_alt != cert_name:
        cert_name = cert_name + ' + ' + cert_alt

    # shorten title if too long
    if len(http_title) > (max_title_len - len(title_head) - 1):
        http_title = http_title[:max_title_len - len(title_head) - len(cut) - 1] + cut

    ret = (ip.ljust(16) +
           ((title_head + '%s') % http_title).ljust(max_title_len) +
           ('SSL: %s' % cert_name).ljust(50) +
           ('AS: %s (%s)' % (as_name, as_num)).ljust(40) +
           ('Loc: %s' % loc).ljust(30) +
           ('OS: %s' % os).ljust(15) +
           ('Tags: %s' % tags))
    print(ret)

    return ret


def CensysPublicReport(engine, public_info, output_basename):
    """ Censys Public Scan report """
    if output_basename:
        output1 = output_basename + ".txt"
        output2 = output_basename + ".md"
        output3 = output_basename + ".xml"
        output4 = output_basename + ".html"

        with open(output1, 'a') as txt, open(output2, 'a') as md, \
                open(output3, 'a') as xml, open(output4, 'a') as html:
            txt.write("[+] {} results\n".format(engine))
            txt.write("-------------------------\n")
            md.write("---\n\n")
            md.write("## {} results\n".format(engine))
            xml.write("<{}Results>\n".format(engine))
            html.write("<h3>{} results</h3>\n".format(engine))

            txt.write("\n")
            md.write("\n")

            txt.write("Censys Public Scan:\n")
            md.write("### Censys\n\n")
            xml.write("<Censys>\n")
            html.write("<h4>Censys</h4>\n<ul>\n")

            for publicscan in public_info:
                txt.write("%s\n" % publicscan)
                # md.write("* {}\n".format(publicscan))
                # xml.write("<Public_Censys>{}</Public_Censys>\n".format(publicscan))
                # html.write("<li>{}</li>\n" % publicscan)

            html.write("</ul>\n")
            xml.write("</Censys>\n")
            txt.write("\n")
            md.write("\n")


def CensysPublicScan(api_id, api_sec, output_basename, args, report_buckets,
                     match, public_info, custom_filter_fields=None):
    """ Censys.io Public Scan - Censys.io """
    if (args.mode == 'censys' and (
            args.Limit != float('inf') or args.asn != None or args.report != None or
            args.html != False or args.http_server != None or args.tags != None or
            args.cert_org != None or args.cert_host != None or args.count != False or
            args.html_body != None or args.html_title != None or args.country != None)):
        q, s = BuildQuery(api_id, api_sec, args)
        # count the number of results
        try:
            count = q.report(s, "updated_at")['metadata']['count']
        except CensysException as e:
            print(e.message)
            sys.exit(-1)

        if args.report:
            try:
                r = q.report(s, args.report, report_buckets)
            except CensysException as e:
                print(e.message)
                sys.exit(-1)
            sys.stderr.write("Number of results: %d\n" % count)
            print_report(r, args.report, public_info, output_basename)
            sys.exit(0)

        if args.count:
            print("Number of results: %d\n" % count)
            sys.exit(0)
        else:
            sys.stderr.write("Number of results: %d\n" % count)

        # prepare temp dir for html files
        if args.html:
            htmldir = tempfile.mkdtemp()
            open(htmldir + "/README", "w").write(
                "html body dumped via command:" + ' '.join(sys.argv))
            print("HTML body dumped to %s" % htmldir)

        public_info2 = []
        # search the API 
        if args.filter:
            filter_fields = args.filter.split(',')
        else:
            filter_fields = custom_filter_fields
        r = q.search(s, fields=filter_fields)
        i = 0
        for e in r:
            if i >= float(args.Limit):
                break
            if args.verbose:
                pp.pprint(q.view(e['ip']))
            elif args.filter:
                print(e)  # todo: by default dump raw JSON if filters are used
            else:
                public_info = print_short(e)
                public_info2.extend(public_info)
                if args.html:
                    dump_html_to_file(htmldir, e)
                if match != 'None':
                    print_match(q.view(e['ip']), match)
                i += 1

        return True
    return False


def print_match(res, m):
    """ finding matching results - Censys.io """
    for k in list(res.keys()):
        json_find(res[k], k, list(), m)
    print()


def print_report(res, key, public_info, output_basename):
    """ Format the result output - Censys.io """
    r = res['results']
    print("count".ljust(10) + "\t" + key.split(".")[-1])
    for e in r:
        print(("%d" % e['doc_count']).ljust(10) + "\t" + str(e['key']).ljust(30))
        public_info = ("%d" % e['doc_count']).ljust(10) + "\t" + str(e['key']).ljust(30)

    CensysPublicReport('censys', public_info, output_basename)


def build_query_string(args):
    """ Build the Query String - Censys.io """
    if len(args.arguments) == 0:
        s = '*'
    else:
        s = "(" + args.arguments[0] + ")"
    if args.tags:
        if ',' in args.tags:
            tags_l = args.tags.split(',')
            tags_q = " AND tags:" + " AND tags:".join(tags_l)
        else:
            tags_q = " AND tags:%s" % args.tags
        s += tags_q
    if args.asn:
        s += " AND autonomous_system.asn:%s" % args.asn
    if args.cert_org:
        s += " AND 443.https.tls.certificate.parsed.subject.organization:%s" % args.cert_org
    if args.cert_issuer:
        s += " AND 443.https.tls.certificate.parsed.issuer.organization:%s" % args.cert_issuer
    if args.cert_host:
        s += " AND 443.https.tls.certificate.parsed.subject.common_name:%s" % args.cert_host
    if args.country:
        s += " AND location.country_code:%s" % args.country
    if args.http_server:
        s += " AND 80.http.get.headers.server:%s" % args.http_server
    if args.html_title:
        if " " in args.html_title:
            title = "\"%s\"" % args.html_title
        else:
            title = args.html_title
        s += " AND 80.http.get.title:%s" % title
    if args.html_body:
        if " " in args.html_body:
            body = "\"%s\"" % args.html_body
        else:
            body = args.html_body
        s += " AND 80.http.get.body:%s" % body
    if args.debug:
        print('Query: %s' % s)
    return s


def is_contained(a, b):
    """ returns true if b is contained inside a """
    if type(a) == type(b):
        m = re.search(b, a, re.UNICODE + re.IGNORECASE)
        if m:
            return True
        else:
            return False


def BuildQuery(api_id, api_sec, pargs):
    """ uild The Query - Censys.io """
    # build up query
    q = CensysIPv4(api_id, api_sec)
    s = build_query_string(pargs)
    return q, s


def print_res(path, match, val):
    """ Printing Results - Censys.io """
    sep = ' '
    pre = '[...]'
    post = pre
    pos = match.lower().index(val.lower())
    if len(match) >= 80:
        if pos < 35:
            pre = ''
        match_c = Style.DIM + pre + match[pos - 35:pos] + Fore.RED + Style.BRIGHT + match[
                                                                                    pos:pos + len(
                                                                                        val)] + \
                  Style.RESET_ALL + Style.DIM + match[
                                                pos + len(val):pos + 35] + post + Style.RESET_ALL
        match = pre + match[pos - 35:pos + 35] + post
    else:
        match_c = Style.DIM + match[:pos] + Fore.RED + Style.BRIGHT + match[pos:pos + len(val)] + \
                  Style.RESET_ALL + Style.DIM + match[pos + len(val):] + Style.RESET_ALL

    match_c = match_c.replace('\n', '\\n')
    match_c = match_c.replace('\r', '\\r')
    match = match.replace('\n', '\\n')
    match = match.replace('\r', '\\r')

    if len(path) >= 60:
        sep = '\n\t'
    if sys.stdout.isatty():
        print("  %s:%s%s" % (path, sep, match_c))
    else:
        print("  %s:%s%s" % (path, sep, match))


def append_if_new(l, e):
    if e not in l:
        return l + [e]
    else:
        return l


def json_find(obj, k, visited, val):
    """
    Searching JSON - Censys.io
    recursively find values in dict 'obj' that macthes 'val'
    store the keys to access the matching value in 'path'
    """
    if visited is None:
        visited = list()

    # case of sub-dict : recursivity
    if isinstance(obj, dict):
        visited = append_if_new(visited, k)
        # visited = visited + [k]
        for key in list(obj.keys()):
            visited = json_find(obj[key], key, visited, val)

    # case of list : check all members
    elif isinstance(obj, list):
        for e in obj:
            if is_contained(e, val):
                print_res('.'.join(visited + [k]), e, val)

    # finally easiest case, leaf
    elif is_contained(obj, val):
        print_res('.'.join(visited + [k]), obj, val)

    # remove nodes already visited before returning
    if k in visited:
        visited.pop()
    return visited


def dump_html_to_file(d, rec):
    """ Dump HTML to file - Censys.io """
    html = rec.get('80.http.get.body')
    if html:
        filename = "%s/%s.html" % (d, rec['ip'])
        open(filename, "w").write(html.encode('UTF-8', errors='ignore'))


def DomainSearchCensys(domain_name, api_id, api_sec, output_basename, domains):
    """ Domain Searching with Censys.io """
    if domain_name != None:
        subdomains = CensysSearch(domain_name, api_id, api_sec)
        domains.extend(subdomains)
        SubdomainsReport('Censys', subdomains, output_basename)
        return True

    return False

#######################################################


def checkFile():
    """ Check if file exists """
    is_true = os.path.isfile(KEYS_FILE)
    if is_true != True:
        return False
    if os.path.getsize(KEYS_FILE) == 0:
        return False
    else:
        return True


def checkUser(engine):
    """ Check if engine exists in API key file """
    chk = checkFile()
    if not chk:
        return False
    else:
        with open(KEYS_FILE) as f:
            s = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            if s.find(engine) != -1:
                return True
            else:
                return False


# ################# API KEYS ################## #

def readFileContents():
    """ Read API Keys from file """
    with open(KEYS_FILE) as f:
        lines = f.read().splitlines()
        print(
            "|       Engine       |                API Keys ID              |              API Secret Keys            |"
        )
        print(
            "|========================================================================================================|"
        )
        for line in lines:
            print("|", line.split(":")[0], " " * (17 - len(line.split(":")[0])), "|",
                  line.split(":")[1], " " * (38 - len(line.split(":")[1])), "|",
                  line.split(":")[2], " " * (38 - len(line.split(":")[2])), "|")


def createFileAndStoreAPIKeys(engine):
    """ Create file and Store the API Keys """
    f = open(KEYS_FILE, "w+")
    api_id = input("[*] please provide the new %s API ID: " % engine)
    api_sec = input("[*] please provide the new %s API Secret: " % engine)
    f.write(engine + ":" + api_id + ":" + api_sec)
    f.close()
    return ("stored")


def updateAPIKeys(engine):
    """ Update API Keys """
    ckhstored = checkUser(engine)
    api_id = input("[*] please provide the new %s API ID: " % engine)
    api_sec = input("[*] please provide the new %s API Secret: " % engine)
    with open(KEYS_FILE, "r+") as op:
        lines = op.read().splitlines()
        if ckhstored == True:
            for line in lines:
                if line != line.split(":")[0]:
                    with open(KEYS_FILE, "w+") as f:
                        f.write(line)

            for line in lines:
                if line != line.split(":")[0]:
                    with open(KEYS_FILE, "w+") as f1:
                        f1.write(engine + ":" + api_id + ":" + api_sec)
            return 'y'

        if ckhstored == False:
            print("[!] user does not exist in file")
            return 'n'


# ############### Check Domain, IP, Hostname  ###################### #

def CheckDomain(value):
    """ Validate Domain name """
    if not validators.domain(value):
        raise argparse.ArgumentTypeError('Invalid {} domain.'.format(value))
    return value


def CheckDomainOrIP(value):
    """ Verify domain/ip  """
    if not validators.domain(value) and not validators.ip_address.ipv4(value):
        raise argparse.ArgumentTypeError('Invalid domain or ip address ({}).'.format(value))
    return value


def VerifyHostname(value):
    """ Get Domain ip address """
    try:
        ip = socket.gethostbyname(value)
        return ip
    except Exception as e:
        return False


# #####################  Whois, DNS  ########################### #

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
                if rec == 'name_servers':
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


def _query(value, dnsserver, record):
    myresolver = dns.resolver.Resolver()
    myresolver.nameservers = [dnsserver]

    try:
        answers = myresolver.resolve(value, record)
        for answer in answers:
            # TODO check: this for loop is returning on first loop
            if record == 'NS':
                return answer.to_text() + ":" + VerifyHostname(answer.to_text())
            elif record == 'MX':
                domain_name = re.search(' (.*)\.', answer.to_text(), re.IGNORECASE).group(1)
                return answer.to_text() + ":" + VerifyHostname(domain_name)
            else:
                return answer.to_text()
    except Exception:
        return '-'

    return None  # dnsData?


def DnsQuery(value, dnsserver, record=None):
    """ Perform DNS queries  """
    dnsData = {
        "A": [],
        "CNAME": [],
        "HINFO": [],
        "MX": [],
        "NS": [],
        "PTR": [],
        "SOA": [],
        "TXT": [],
        "SPF": [],
        "SRV": [],
        "RP": []
    }

    if record is None:
        for record in dnsData:
            dnsData[record].append(_query(value, dnsserver, record))
    else:
        dnsData[record].append(_query(value, dnsserver, record))

    return dnsData


def ReverseIPQuery(value, dnsserver):
    """ IP DNS Reverse lookup """
    try:
        revname = reversename.from_address(value)
        myresolver = dns.resolver.Resolver()
        myresolver.nameservers = [dnsserver]
        return str(myresolver.resolve(revname, 'PTR')[0]).rstrip('.')
    except Exception as e:
        print(e)
        return ''


# ##########  Parse the Results to get usefull data ############## #

def CleanHTML(results):
    """ Clean HTML tags """
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


def GetEmails(results, value):
    """ Extract Emails """
    res = results
    res = CleanHTML(res)

    # todo this regex needs improvement per case/service
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


def GetHostnames(results, value):
    """ Extract Hostnames """
    res = results
    res = CleanHTML(res)

    temp = re.compile('[a-zA-Z0-9.-]*\.' + value)
    hostnames = temp.findall(res)
    final = []
    for host in hostnames:
        final.append(host.lower())

    return sorted(set(final))


def GetHostnamesAll(results):
    """ Get All Hostnames """
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


def GetDNSDumpsterHostnames(value, results):
    tbl_regex = re.compile('<a name="hostanchor"><\/a>Host Records.*?<table.*?>(.*?)</table>',
                           re.S)
    link_regex = re.compile('<td class="col-md-4">(.*?)<br>', re.S)
    subdomains = []

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


def SpyseGetDomains(data):
    """
    :type data: dict
    :rtype: list
    """
    domains = []
    try:
        domains = [i['name'] for i in data['data']['items']]
    except IndexError:
        print("Unrecognised data returned by Spyse")

    return domains


# ################## User Agent #################### #

def PickRandomUA(value):
    """ Pick random User-Agent string """
    if value:
        secure_random = random.SystemRandom()
        return secure_random.choice(value)

    return None


def PickRandomTimeout(value):
    if value:
        secure_random = random.SystemRandom()
        return secure_random.choice(value)

    return 5


# #######################  Common search  ########################### #

def CommonSearch(value, urltemplate, quantity, step, limit, uas, proxies, timeouts):
    counter = 0
    results = ""

    while counter <= limit:
        try:
            url = urltemplate.format(quantity=quantity, counter=counter, value=value)
            s = requests.Session()
            r = s.get(url, verify=False, headers={'User-Agent': PickRandomUA(uas)},
                      proxies=proxies)
            if r.status_code != 200:
                print("[-] Something is going wrong (status code: {})".format(r.status_code))
                return [], []
            results += r.text
        except Exception as e:
            print(e)

        time.sleep(PickRandomTimeout(timeouts))
        counter += step

    return GetEmails(results, value), GetHostnames(results, value)


def CommonSearch2(value, urltemplate, step, limit, uas, proxies, timeouts):
    counter = 1
    results = ""

    while counter <= limit:
        try:
            url = urltemplate.format(counter=counter, value=value)
            s = requests.Session()
            r = s.get(url, verify=False, headers={'User-Agent': PickRandomUA(uas)},
                      proxies=proxies)
            if r.status_code != 200:
                print("[-] Something is going wrong (status code: {})".format(r.status_code))
                return [], []
            results += r.text
        except Exception as e:
            print(e)

        time.sleep(PickRandomTimeout(timeouts))
        counter += step

    return GetEmails(results, value), GetHostnames(results, value)


# ######################  Search Engines & Services ######################### #

def GoogleSearch(value, limit, uas, proxies, timeouts):
    quantity = 100
    step = 100
    url = "https://www.google.com/search?num={quantity}&start={counter}&hl=en&meta=&q=%40%22{value}%22"

    return CommonSearch(value, url, quantity, step, limit, uas, proxies, timeouts)


def BingSearch(value, limit, uas, proxies, timeouts):
    quantity = 50
    step = 50
    url = "https://www.bing.com/search?q=%40{value}&count={quantity}&first={counter}"

    return CommonSearch(value, url, quantity, step, limit, uas, proxies, timeouts)


def AskSearch(value, limit, uas, proxies, timeouts):
    step = 1
    url = "https://www.ask.com/web?q=%40%22{value}%22&page={counter}"

    return CommonSearch2(value, url, step, limit, uas, proxies, timeouts)


# todo captcha
def DogpileSearch(value, limit, uas, proxies, timeouts):
    step = 15
    url = "https://www.dogpile.com/search/web?qsi={counter}&q=%40{value}"

    return CommonSearch2(value, url, step, limit, uas, proxies, timeouts)


def YahooSearch(value, limit, uas, proxies, timeouts):
    step = 10
    url = "https://search.yahoo.com/search?p=%40{value}&b={counter}&pz=10"

    return CommonSearch2(value, url, step, limit, uas, proxies, timeouts)


def YandexSearch(value, limit, uas, proxies, timeouts):
    server = "yandex.com"
    quantity = 50
    step = 50
    results = ""
    page = 0
    counter = 0

    while counter <= limit:
        try:
            url = "https://" + server + "/search/?text=%22%40" + value + "%22&numdoc=" \
                  + str(quantity) + "&p=" + str(page) + "&lr=10418"
            s = requests.Session()
            r = s.get(url, verify=False, headers={'User-Agent': PickRandomUA(uas)},
                      proxies=proxies)
            if r.status_code != 200:
                print("[-] Something is going wrong (status code: {})".format(r.status_code))
                return [], []
            results += r.text
        except Exception as e:
            print(e)

        time.sleep(PickRandomTimeout(timeouts))
        counter += step
        page += 1

    return GetEmails(results, value), GetHostnames(results, value)


def CrtSearch(value, uas, proxies):
    server = "crt.sh"
    results = ""

    try:
        url = "https://" + server + "/?q=" + value
        s = requests.Session()
        r = s.get(url, verify=False, headers={'User-Agent': PickRandomUA(uas)}, proxies=proxies)
        if r.status_code != 200:
            print("[-] Something is going wrong (status code: {})".format(r.status_code))
            return [], []
        results += r.text
    except Exception as e:
        print(e)

    return GetHostnames(results, value)


def DNSDumpsterSearch(targetip, uas, proxies):
    server = "dnsdumpster.com"
    results = ""
    timeout = 25
    subdomains = None

    try:
        url = "https://" + server + "/"
        s = requests.Session()
        myheaders = {'User-Agent': PickRandomUA(uas), 'Referer': 'https://dnsdumpster.com'}
        r = s.get(url, verify=False, headers=myheaders, proxies=proxies, timeout=timeout)
        if r.status_code != 200:
            print("[-] Something is going wrong (status code: {})".format(r.status_code))
            return [], []

        # get csrf token
        csrf_regex = re.compile('name="csrfmiddlewaretoken" value="(.*?)"', re.S)
        try:
            token = csrf_regex.findall(r.text)[0]
        except IndexError:
            print("[-] CSRF Token not found")
            return None

        params = {'csrfmiddlewaretoken': token, 'targetip': targetip}
        pr = s.post(url, verify=False, headers=myheaders, proxies=proxies, data=params,
                    timeout=timeout)
        if pr.status_code != 200:
            print("[-] Something is going wrong (status code: {})".format(pr.status_code))
            return [], []

        subdomains = GetDNSDumpsterHostnames(targetip, pr.text)

    except Exception as e:
        print(e)

    return subdomains


# todo pgp.mit.edu lookup service seems down
def PGPSearch(value, uas, proxies):
    server = "pgp.mit.edu"
    results = ""

    try:
        url = "https://" + server + "/pks/lookup?search=" + value + "&op=index"
        s = requests.Session()
        r = s.get(url, verify=False, headers={'User-Agent': PickRandomUA(uas)}, proxies=proxies)
        if r.status_code != 200:
            print("[-] Something is going wrong (status code: {})".format(r.status_code))
            return [], []
        results += r.text
    except Exception as e:
        print(e)

    return GetEmails(results, value), GetHostnames(results, value)


def NetcraftSearch(value, uas, proxies):
    server = "searchdns.netcraft.com"
    results = ""

    try:
        url = "https://" + server + "?restriction=site+ends+with&host=" + value
        s = requests.Session()
        r = s.get(url, verify=False, headers={'User-Agent': PickRandomUA(uas)}, proxies=proxies)
        if r.status_code != 200:
            print("[-] Something is going wrong (status code: {})".format(r.status_code))
            return [], []
        results += r.text
    except Exception as e:
        print(e)

    return GetHostnames(results, value)


def VTSearch(value, uas, proxies):
    server = "www.virustotal.com"
    results = ""

    try:
        url = "https://" + server + "/en/domain/" + value + "/information/"
        s = requests.Session()
        r = s.get(url, verify=False, headers={'User-Agent': PickRandomUA(uas)}, proxies=proxies)
        if r.status_code != 200:
            print("[-] Something is going wrong (status code: {})".format(r.status_code))
            return [], []
        results += r.text
    except Exception as e:
        print(e)

    return GetHostnames(results, value)


def SpyseSearch(value, apikey, limit=100, proxies=None):
    server = "api.spyse.com"
    data = {}

    try:
        url = f'https://{server}/v2/data/domain/subdomain?limit={limit}&domain={value}'
        headers = {
            'accept': 'application/json',
            'Authorization': f'Bearer {apikey}',
        }
        s = requests.Session()
        r = s.get(url, verify=False, headers=headers, proxies=proxies)
        if DEBUG: print(r.text)
        if r.status_code != 200:
            print(f'[-] Something is going wrong - status code: {r.status_code}')
        else:
            data = json.loads(r.text)
    except (ValueError, TypeError):
        print("Unrecognised data returned by spyse api")
    except NameError as e:
        print("Error: Insufficient data passed to SpyseSearch")
        print(e)
    except Exception as e:
        print(e)

    return data


def CensysSearch(value, api_id, api_secret):
    try:
        censys_certificates = censys.certificates.CensysCertificates(api_id=api_id,
                                                                     api_secret=api_secret)
        certificate_query = 'parsed.names: %s' % value
        certificates_search_results = censys_certificates.search(certificate_query,
                                                                 fields=['parsed.names'])
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


def GoogleSearchEngine(value, site, limit, uas, proxies, timeouts):
    """ google search in site """
    server = "www.google.com"
    quantity = 100
    counter = 0
    step = 100
    results = ""

    while counter <= limit:
        try:
            url = "https://" + server + "/search?num=" + str(quantity) + "&start=" + str(
                counter) + "&hl=en&meta=&q=site%3A" + site + "%20%40%22" + value + "%22"
            s = requests.Session()
            r = s.get(url, verify=False, headers={'User-Agent': PickRandomUA(uas)},
                      proxies=proxies)
            if r.status_code != 200:
                print("[-] Something is going wrong (status code: {})".format(r.status_code))
                return [], []
            results += r.text
        except Exception as e:
            print(e)

        time.sleep(PickRandomTimeout(timeouts))
        counter += step

    return GetEmails(results, value), GetHostnames(results, value)


def BingVHostsSearch(value, limit, uas, proxies, timeouts):
    """ Bing Virtual Hosts Search """
    server = "www.bing.com"
    quantity = 50
    step = 50
    counter = 0
    results = ""
    vhosts = []

    while counter <= limit:
        try:
            url = "https://" + server + "/search?q=ip%3A" + value + "&go=&count=" + str(
                quantity) + "&FORM=QBHL&qs=n&first=" + str(counter)
            s = requests.Session()
            r = s.get(url, verify=False, headers={'User-Agent': PickRandomUA(uas)},
                      proxies=proxies)
            if r.status_code != 200:
                print("[-] Something is going wrong (status code: {})".format(r.status_code))
                return [], []
            results += r.text
        except Exception as e:
            print(e)

        time.sleep(PickRandomTimeout(timeouts))
        counter += step

    all_hostnames = GetHostnamesAll(results)

    for x in all_hostnames:
        x = re.sub(r'[[\<\/?]*[\w]*>]*', '', x)
        x = re.sub('<', '', x)
        x = re.sub('>', '', x)
        vhosts.append(x)

    return sorted(set(vhosts))


# todo if the API is used (valid key), the rtype is `dict` else
# the search is done via the website and the rtype is a `set` of vhosts
def ShodanSearch(api_key, domain, value, uas, proxies, timeouts, limit=0):

    api = shodan.Shodan(api_key)
    server = "shodan.io"
    counter = 0
    quantity = 10
    step = 10
    vhosts = []
    results = ''

    # Warning: Shodan api needs a payment plan!
    # Wrap the request in a try/ except block to catch errors
    try:
        # Search by hostname
        query = 'hostname:' + domain
        return api.search(query)

    except shodan.APIError as e:
        print('Error: %s' % e)

    while counter <= limit:
        try:
            url = "https://" + server + "/search?q=ip%3A" + value + "&go=&count=" + str(
                quantity) + "&FORM=QBHL&qs=n&first=" + str(counter)
            s = requests.Session()
            r = s.get(url, verify=False, headers={'User-Agent': PickRandomUA(uas)},
                      proxies=proxies)
            if r.status_code != 200:
                print("[-] Something is going wrong (status code: {})".format(r.status_code))
                return [], []
            results += r.text
        except Exception as e:
            print(e)

        time.sleep(PickRandomTimeout(timeouts))
        counter += step

    all_hostnames = GetHostnamesAll(results)

    for x in all_hostnames:
        x = re.sub(r'[[\<\/?]*[\w]*>]*', '', x)
        x = re.sub('<', '', x)
        x = re.sub('>', '', x)
        vhosts.append(x)

    return sorted(set(vhosts))


# ##################  Reports  ######################## #

def Report(engine, emails, hostnames, output_basename):
    """ Emails & Hostnames Console report """
    print()
    print("Emails:")
    for email in emails:
        print(email)

    print()
    print("Hostnames:")
    for host in hostnames:
        print(host)
    print()

    if output_basename:
        output1 = output_basename + ".txt"
        output2 = output_basename + ".md"
        output3 = output_basename + ".xml"
        output4 = output_basename + ".html"

        with open(output1, 'a') as txt, open(output2, 'a') as md, \
                open(output3, 'a') as xml, open(output4, 'a') as html:
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


def SubdomainsReport(engine, subdomains, output_basename):
    """ Subdomains Console report """
    assert type(subdomains) in (list, tuple, dict)  # should be list
    if len(subdomains) == 0:
        print('[-] Did not find any subdomain')
        return

    print('')
    print('[*] Found %d subdomains' % (len(subdomains)))
    print('')
    for subdomain in subdomains:
        print(subdomain)
    print('')

    if output_basename:
        output1 = output_basename + ".txt"
        output2 = output_basename + ".md"
        output3 = output_basename + ".xml"
        output4 = output_basename + ".html"

        with open(output1, 'a') as txt, open(output2, 'a') as md, open(output3, 'a') as xml, open(
                output4, 'a') as html:
            txt.write("[+] {} results\n".format(engine))
            txt.write("-------------------------\n")
            md.write("---\n\n")
            md.write("## {} results\n".format(engine))
            xml.write("<{}Results>\n".format(engine))
            html.write("<h3>{} results</h3>\n".format(engine))

            txt.write("\n")
            md.write("\n")

            txt.write("Subdomains:\n")
            md.write("### Subdomains\n\n")
            xml.write("<Subdomains>\n")
            html.write("<h4>Subdomains</h4>\n<ul>\n")

            for subdomain in subdomains:
                txt.write("{}\n".format(subdomain))
                md.write("* {}\n".format(subdomain))
                xml.write("<Subdomain>{}</Subdomains>\n".format(subdomain))
                html.write("<li>{}</li>\n".format(subdomain))

            html.write("</ul>\n")
            xml.write("</Subdomains>\n")
            txt.write("\n")
            md.write("\n")


def ShodanReport(results, output_basename):
    """ Shodan Console Report """
    engine = "Shodan"
    if len(results) == 0:
        print('[-] Did not find any results')
        return

    if type(results) in (set, list, tuple):
        print('Shodan Report is not available for the current results')
        print('Results found: %s' % len(results))
        for r in results:
            print(r)
        return

    print()
    print('Results found: %s' % results['total'])
    print('------------------')
    print()

    # pdb.set_trace()

    for result in results['matches']:

        # Print host info
        print('IP: %s' % result['ip_str'])
        print('-------------------')
        print('Hostnames: ' + ','.join(result['hostnames']))
        print('Organization: %s' % result.get('org', 'n/a'))
        print('Operating System: %s' % result.get('os', 'n/a'))
        print('Port: %s' % result['port'])

        # Print banner
        banner = result.get('data')
        if banner is not None:
            print('Banner:')
            print(result['data'])
            print()

    # Output to file
    if output_basename:
        output1 = output_basename + ".txt"
        output2 = output_basename + ".md"
        output3 = output_basename + ".xml"
        output4 = output_basename + ".html"

        with open(output1, 'a') as txt, open(output2, 'a') as md, open(output3, 'a') as xml, open(
                output4, 'a') as html:
            txt.write("[+] {} results\n".format(engine))
            txt.write("-------------------------\n")
            md.write("---\n\n")
            md.write("## {} results\n".format(engine))
            xml.write("<{}Results>\n".format(engine))
            html.write("<h3>{} results</h3>\n".format(engine))

            txt.write("\n")
            md.write("\n")

            for result in results['matches']:
                ip = result['ip_str']
                hostnames = ','.join(result['hostnames'])
                organization = result.get('org', 'n/a')
                os = result.get('os', 'n/a')
                port = result['port']
                banner = result['data']

                # Print IP
                PrintField("IP", ip, txt, md, xml, html)

                # Print Hostnames
                PrintField("Hostnames", hostnames, txt, md, xml, html)

                # Print Organization
                PrintField("Organization", organization, txt, md, xml, html)

                # Print Operating System
                PrintField("OS", os, txt, md, xml, html)

                # Print Port
                PrintField("Port", port, txt, md, xml, html)

                # Print Banner
                PrintField("Banner", banner, txt, md, xml, html)

            xml.write("</{}Results>\n".format(engine))


def PrintField(label, value, txt, md, xml, html):
    """ Print field to output files """
    txt.write("{}:\n".format(label))
    md.write("### {}\n\n".format(label))
    xml.write("<{}>\n".format(label))
    html.write("<h4>{}</h4>\n<ul>\n".format(label))

    txt.write("{}\n".format(value))
    md.write("* {}\n".format(value))
    xml.write("<{}>{}</{}>\n".format(label, value, label))
    html.write("<li>{}</li>\n".format(value))

    html.write("</ul>\n")
    xml.write("</{}>\n".format(label))
    txt.write("\n")
    md.write("\n")


def HostnamesReport(engine, hostnames, output_basename):
    """ Hostnames Console report """
    assert type(hostnames) in (list, tuple, dict)  # should be list

    print()
    print("Hostnames:")
    for host in hostnames:
        print(host)
    print()

    if output_basename:
        output1 = output_basename + ".txt"
        output2 = output_basename + ".md"
        output3 = output_basename + ".xml"
        output4 = output_basename + ".html"

        with open(output1, 'a') as txt, open(output2, 'a') as md, open(output3, 'a') as xml, open(
                output4, 'a') as html:
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


def InfoReport(mode, limit, dnsserver, proxy, domain, ip, uas, output_basename):
    """ Information Console report """
    print("[+] Information gathering: {}".format(mode))
    print("[+] Looking into first {} search engines results".format(limit))
    print("[+] Using DNS server: {}".format(dnsserver))
    if proxy:
        print("[+] Using Proxy server: {}".format(proxy))
    print("[+] Target: {}:{}".format(domain, ip))
    print("[+] User-agent strings: {}".format(uas))
    print()

    if output_basename:
        output1 = output_basename + ".txt"
        output2 = output_basename + ".md"
        output3 = output_basename + ".xml"
        output4 = output_basename + ".html"

        with open(output1, 'w') as txt, open(output2, 'w') as md, open(output3, 'w') as xml, open(
                output4, 'w') as html:
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


def WhoisReport(data, output_basename):
    """ Whois Console report"""
    for key, value in data.items():
        if isinstance(value[0], list):
            print()
            print(value[1])
            for val in value[0]:
                print(val)
            print()
        else:
            print(value[1] + " " + value[0])
    print()

    if output_basename:
        output1 = output_basename + ".txt"
        output2 = output_basename + ".md"
        output3 = output_basename + ".xml"
        output4 = output_basename + ".html"

        with open(output1, 'a') as txt, open(output2, 'a') as md, open(output3, 'a') as xml, open(
                output4, 'a') as html:
            txt.write("[+] Whois lookup\n")
            txt.write("----------------\n")
            md.write("---\n\n")
            md.write("## Whois lookup\n\n")
            xml.write("<Whois>\n")
            html.write("<h3>Whois lookup</h3>\n<ul>\n")

            for key, value in data.items():
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


def DNSReport(data, output_basename):
    """ DNS Console report """
    for key, value in data.items():
        if len(value) == 1:
            print(key + " DNS record: " + value[0])
        else:
            print()
            print(key + " DNS record: ")
            for val in value:
                print(val)
            print()
    print()

    if output_basename:
        output1 = output_basename + ".txt"
        output2 = output_basename + ".md"
        output3 = output_basename + ".xml"
        output4 = output_basename + ".html"

        with open(output1, 'a') as txt, open(output2, 'a') as md, open(output3, 'a') as xml, open(
                output4, 'a') as html:
            txt.write("[+] DNS queries\n")
            txt.write("---------------\n")
            md.write("---\n\n")
            md.write("## DNS queries\n\n")
            xml.write("<DNSQueries>\n")
            html.write("<h3>DNS queries</h3>\n<ul>\n")

            for key, value in data.items():
                if len(value) == 1:
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


def ReverseDNSReport(ip, data, output_basename):
    """ Reverse DNS Console report """
    if data:
        print(ip + ":" + data)
    print()

    if output_basename:
        output1 = output_basename + ".txt"
        output2 = output_basename + ".md"
        output3 = output_basename + ".xml"
        output4 = output_basename + ".html"

        with open(output1, 'a') as txt, open(output2, 'a') as md, open(output3, 'a') as xml, open(
                output4, 'a') as html:
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


def VHostsReport(data, output_basename):
    """ VHosts Console report """
    for host in data:
        print(host)
    print()

    if output_basename:
        output1 = output_basename + ".txt"
        output2 = output_basename + ".md"
        output3 = output_basename + ".xml"
        output4 = output_basename + ".html"

        with open(output1, 'a') as txt, open(output2, 'a') as md, open(output3, 'a') as xml, open(
                output4, 'a') as html:
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


def FinalReport(info, output_basename):
    """ All major formats final report """
    print()
    print("[+] Search engines results - Final Report")
    print("-----------------------------------------")

    if info['all_emails']:
        print()
        print("Emails:")
        print()
        for email in info['all_emails']:
            print(email)

    if info['all_hosts']:
        print()
        print("Hostnames:")
        print()
        for host in info['all_hosts']:
            print(host)

    if info['domains']:
        print()
        print("Subdomains:")
        print()
        for domain in info['domains']:
            print(domain)
        print()

    if output_basename:
        output1 = output_basename + ".txt"
        output2 = output_basename + ".md"
        output3 = output_basename + ".xml"
        output4 = output_basename + ".html"

        with open(output1, 'a') as txt, open(output2, 'a') as md, open(output3, 'a') as xml, open(
                output4, 'a') as html:
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

            txt.write("Subdomains:\n")
            md.write("### Subdomains\n\n")
            xml.write("<Subdomains>\n")
            html.write("<h4>Subdomains</h4>\n<ul>\n")

            for host in info['domains']:
                txt.write("{}\n".format(host))
                md.write("* {}\n".format(host))
                xml.write("<Subdomain>{}</Subdomain>\n".format(host))
                html.write("<li>{}</li>\n".format(host))

            html.write("</ul>\n")
            xml.write("</Subdomain>\n")
            txt.write("\n")
            md.write("\n")
            xml.write("</FinalReport>\n")

#######################################################


def _get_key(service_name):
    """
    Parses the api keys file and returns the corresponding key
    Doesn't work for censys. Works only for services with one key

    :param service_name: The online service e.g spyse
    :type service_name: :class: `str`
    """
    key = None
    if checkFile():
        with open(KEYS_FILE, 'r') as fin:
            lines = fin.readlines()
            for l in lines:
                if l.lower().startswith(service_name) and ':' in l:
                    try:
                        key = l.strip(' \r\n').split(':')[1]
                    except IndexError:
                        print(KEYS_FILE
                              + " doesnt follow the correct format name:value")

    return key

#######################################################


def MainFunc():
    print(message)

    report_buckets = 50
    info = {
        'all_emails': [],
        'all_hosts': [],
        'domains': [],
        'public': []
    }
    uas = []

    user_agent_strings_file = 'common-ua.txt'
    timeouts = [5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
    report_buckets = 10
    modes = ['basic', 'nongoogle', 'whois', 'dns', 'revdns', 'vhosts', 'google', 'bing', 'yahoo',
             'ask', 'dogpile', 'yandex', 'linkedin', 'twitter', 'youtube', 'reddit',
             'github', 'instagram', 'crt', 'pgp', 'netcraft', 'virustotal', 'dnsdump', 'shodan',
             'censys', 'spyse']

    parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter)
    parser.add_argument("-d", '--domain', action="store", metavar='DOMAIN', dest='domain',
                        default=None, type=CheckDomain, help="Domain to search.")
    parser.add_argument("-s", '--server', action="store", metavar='NAMESERVER', dest='dnsserver',
                        default='8.8.8.8', type=CheckDomainOrIP, help="DNS server to use.")
    parser.add_argument('-x', '--proxy', action="store", metavar='PROXY', dest='proxy',
                        default=None, type=str, help="Use a proxy server when retrieving "
                                                     "results from search engines (eg. "
                                                     "'-x http://127.0.0.1:8080')")
    parser.add_argument("-l", '--limit', action="store", metavar='LIMIT', dest='limit', type=int,
                        default=100,
                        help="Limit the number of search engine results (default: 100).")
    parser.add_argument("-i", '--info', action="store", metavar='MODE', dest='mode', type=str,
                        default='basic',
                        help="Limit information gathering (" + ','.join(modes) + ").")
    parser.add_argument('-o', '--output', action='store', metavar='BASENAME', dest='basename',
                        type=str, default=None, help='Output in the four major formats at once '
                                                     '(markdown, txt, xml and html).')
    parser.add_argument('-k', '--shodan-key', action='store', metavar='API-KEY', dest='shodankey',
                        type=str, default=None,
                        help='API key to use with Shodan search (MODE="shodan")')
    parser.add_argument('-e', '--spyse-key', action='store', metavar='SPYSE_API_KEY',
                        dest='spysekey', type=str, default=None)
    # censys.io
    parser.add_argument('-m', '--match', default=None,
                        help='Highlight a string within an existing query result')
    parser.add_argument('-f', '--filter', default=None,
                        help="Filter the JSON keys to display for each result, use value 'help' "
                             "for interesting fields")
    parser.add_argument('--count', action='store_true', help='Print the count result and exit')
    parser.add_argument('-R', '--report', default=None,
                        help="Stats on given field (use value 'help' for listing interesting "
                             "fields)'")
    parser.add_argument('-B', '--report_bucket', default=report_buckets,
                        help='Bucket len in report mode (default: %s)' % report_buckets)
    # query filter shortcuts - censys.io
    parser.add_argument('-1', '--censys_api_id', action='store', metavar='CENSYS_API_ID',
                        dest='censys_api_id', type=str, default=None,
                        help='Provide the authentication ID for the censys.io search engine')
    parser.add_argument('-2', '--censys_api_secret', action='store', metavar='CENSYS_API_SECRET',
                        dest='censys_api_secret', type=str, default=None,
                        help='Provide the secret hash for the censys.io search engine')
    parser.add_argument('-r', '--read_api_keys', action='store_true',
                        help="Read the API Keys stored in api_keys.txt file. (e.g. '-i censys -r')")
    parser.add_argument('-u', '--update_api_keys', action='store_true',
                        help="Update the API Keys stored in api_keys.txt file. (e.g. '-i censys -u')")
    parser.add_argument('-a', '--asn', metavar='ASN', dest='asn', type=str, default=None,
                        help='Filter with ASN (e.g 5408 for GR-NET AS)')
    parser.add_argument('-c', '--country', metavar='COUNTRY', dest='country', type=str,
                        default=None,
                        help='Filter with country')
    parser.add_argument('-O', '--cert-org', metavar='CERT_ORG', dest='cert_org', type=str,
                        default=None,
                        help='Certificate issued to organization')
    parser.add_argument('-I', '--cert-issuer', metavar='CERT_ISSUER', dest='cert_issuer', type=str,
                        default=None,
                        help='Certificate issued by organization')
    parser.add_argument('-z', '--cert-host', metavar='CERT_HOST', dest='cert_host', type=str,
                        default=None,
                        help='hostname Certificate is issued to')
    parser.add_argument('-S', '--http-server', metavar='HTTP_SERVER', dest='http_server', type=str,
                        default=None,
                        help='Server header')
    parser.add_argument('-t', '--html-title', metavar='HTML_TITLE', dest='html_title', type=str,
                        default=None,
                        help='Filter on html page title')
    parser.add_argument('-b', '--html-body', metavar='HTML_BODY', dest='html_body', type=str,
                        default=None,
                        help='Filter on html body content')
    parser.add_argument('-T', '--tags', default=None,
                        help='Filter on specific tags. e.g: -T tag1,tag2,... (use keyword \'list\''
                             ' to list usual tags')
    parser.add_argument('-L', '--Limit', default=float('inf'), help='Limit to N results')
    parser.add_argument('-D', '--debug', action='store_true', help='Debug information')
    parser.add_argument('-v', '--verbose', action='store_true', help='Print raw JSON records')
    parser.add_argument('-H', '--html', action='store_true',
                        help='Renders html elements in a browser')
    parser.add_argument('arguments', metavar='arguments', nargs='*', help='Censys query')

    args = parser.parse_args()

    match = str(args.match)

    # TODO tags/fields missing:
    # fire help before doing any request
    # if args.tags in ['list', 'help']:
    #     pp.pprint(tags_available)
    #     sys.exit(0)
    # if args.report in ['list', 'help']:
    #     pp.pprint(report_fields)
    #     sys.exit(0)
    # if args.filter in ['list', 'help']:
    #     pp.pprint(filter_fields)
    #     sys.exit(0)

    if args.report_bucket:
        report_buckets = args.report_bucket

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit()

    # args = parser.parse_args()
    info['domain'] = args.domain
    info['proxies'] = {}

    #######################################################

    # Load User-Agents strings from file #
    if os.path.isfile(user_agent_strings_file):
        uas = [line.strip() for line in open(user_agent_strings_file)]
    else:
        print("[-] An error occured while loading user-agent strings from file")
        sys.exit()

    output_basename = None
    if args.basename is not None:
        output_basename = args.basename

    #######################################################

    # information #
    info['mode'] = [x.strip() for x in args.mode.lower().split(',')]
    info['limit'] = args.limit
    info['dnsserver'] = args.dnsserver
    info['ip'] = VerifyHostname(info['domain'])

    if args.proxy:
        print("[+] Proxy will ONLY be used during search engines searches")
        info['proxies'] = {
            'http': args.proxy,
            'https': args.proxy,
        }

    InfoReport(info['mode'], info['limit'], info['dnsserver'], args.proxy, info['domain'],
               info['ip'], len(uas), output_basename)

    #######################################################

    # Whois query report #
    if any(i in ['whois', 'basic', 'nongoogle'] for i in info['mode']):
        print("[+] Whois lookup")
        print("----------------")
        info['whois'] = WhoisQuery(info['domain'])
        WhoisReport(info['whois'], output_basename)

    #######################################################

    # DNS records report #
    if any(i in ['dns', 'basic', 'nongoogle'] for i in info['mode']):
        print("[+] DNS queries")
        print("---------------")
        info['dns'] = DnsQuery(info['domain'], info['dnsserver'])
        DNSReport(info['dns'], output_basename)

    #######################################################

    # IP Reverse DNS lookup report #
    if any(i in ['revdns', 'basic', 'nongoogle'] for i in info['mode']):
        print("[+] Reverse DNS Lookup")
        print("----------------------")
        info['revdns'] = ReverseIPQuery(info['ip'], info['dnsserver'])
        ReverseDNSReport(info['ip'], info['revdns'], output_basename)

    #######################################################

    # Bing Virtual Hosts search results report ##
    if any(i in ['vhosts', 'basic', 'nongoogle'] for i in info['mode']):
        print("[+] Bing Virtual Hosts")
        print("----------------------")
        info['bingvhosts'] = BingVHostsSearch(info['ip'], info['limit'], uas,
                                              info['proxies'], timeouts)
        VHostsReport(info['bingvhosts'], output_basename)

    #######################################################

    # Google search #
    if any(i in ['google'] for i in info['mode']):
        print("[+] Searching in Google..")
        temp1, temp2 = GoogleSearch(info['domain'], info['limit'], uas, info['proxies'], timeouts)
        info['all_emails'].extend(temp1)
        info['all_hosts'].extend(temp2)
        Report("Google", temp1, temp2, output_basename)

    #######################################################

    # Bing search #
    if any(i in ['bing', 'nongoogle'] for i in info['mode']):
        print("[+] Searching in Bing..")
        temp1, temp2 = BingSearch(info['domain'], info['limit'], uas, info['proxies'], timeouts)
        info['all_emails'].extend(temp1)
        info['all_hosts'].extend(temp2)
        Report("Bing", temp1, temp2, output_basename)

    #######################################################

    # Yahoo search #
    if any(i in ['yahoo', 'nongoogle'] for i in info['mode']):
        print("[+] Searching in Yahoo..")
        temp1, temp2 = YahooSearch(info['domain'], info['limit'], uas, info['proxies'], timeouts)
        info['all_emails'].extend(temp1)
        info['all_hosts'].extend(temp2)
        Report("Yahoo", temp1, temp2, output_basename)

    #######################################################

    # Shodan search #
    if any(i in ['shodan'] for i in info['mode']):

        # pdb.set_trace()

        if args.shodankey is None:
            print("[-] API key required for the Shodan search: '-k API-KEY, --shodan-key API-KEY'")
            sys.exit()
        print("[+] Searching in Shodan..")
        print("-------------------")

        results = ShodanSearch(args.shodankey, info['domain'], info['ip'], uas, info['proxies'],
                               timeouts)
        ShodanReport(results, output_basename)

    #######################################################

    # ASK search #
    if any(i in ['ask', 'nongoogle'] for i in info['mode']):
        print("[+] Searching in ASK..")
        temp1, temp2 = AskSearch(info['domain'], 5, uas, info['proxies'], timeouts)  # 5 pages
        info['all_emails'].extend(temp1)
        info['all_hosts'].extend(temp2)
        Report("ASK", temp1, temp2, output_basename)

    #######################################################

    # Dogpile search #
    if any(i in ['dogpile', 'nongoogle'] for i in info['mode']):
        print("[+] Searching in Dogpile..")
        temp1, temp2 = DogpileSearch(info['domain'], info['limit'], uas, info['proxies'], timeouts)
        info['all_emails'].extend(temp1)
        info['all_hosts'].extend(temp2)
        Report("Dogpile", temp1, temp2, output_basename)

    #######################################################

    # Yandex search #
    if any(i in ['yandex', 'nongoogle'] for i in info['mode']):
        print("[+] Searching in Yandex..")
        temp1, temp2 = YandexSearch(info['domain'], info['limit'], uas, info['proxies'], timeouts)
        info['all_emails'].extend(temp1)
        info['all_hosts'].extend(temp2)
        Report("Yandex", temp1, temp2, output_basename)

    #######################################################

    # crt search #
    if any(i in ['crt', 'nongoogle'] for i in info['mode']):
        print("[+] Searching in Crt..")
        temp = CrtSearch(info['domain'], uas, info['proxies'])
        info['all_hosts'].extend(temp)
        HostnamesReport("CRT", temp, output_basename)

    #######################################################

    # dnsdumpster search #
    if any(i in ['dnsdump', 'nongoogle'] for i in info['mode']):
        print("[+] Searching in DNSdumpster..")
        temp = DNSDumpsterSearch(info['domain'], uas, info['proxies'])
        info['all_hosts'].extend(temp)
        HostnamesReport("DNSdumpster", temp, output_basename)

    #######################################################

    # PGP search #
    if any(i in ['pgp', 'nongoogle'] for i in info['mode']):
        print("[+] Searching in PGP..")
        temp1, temp2 = PGPSearch(info['domain'], uas, info['proxies'])
        info['all_emails'].extend(temp1)
        info['all_hosts'].extend(temp2)
        Report("PGP", temp1, temp2, output_basename)

    #######################################################

    # netcraft search #
    if any(i in ['netcraft', 'nongoogle'] for i in info['mode']):
        print("[+] Searching in Netcraft..")
        temp = NetcraftSearch(info['domain'], uas, info['proxies'])
        info['all_hosts'].extend(temp)
        HostnamesReport("Netcraft", temp, output_basename)

    #######################################################

    # virustotal search #
    if any(i in ['virustotal', 'nongoogle'] for i in info['mode']):
        print("[+] Searching in VirusTotal..")
        temp = VTSearch(info['domain'], uas, info['proxies'])
        info['all_hosts'].extend(temp)
        HostnamesReport("VirusTotal", temp, output_basename)

    #######################################################

    # spyse search #
    if any(i in ['spyse', 'nongoogle'] for i in info['mode']):
        spysekey = args.spysekey or _get_key('spyse')
        if not spysekey:
            print("Api Key for spyse was neither provided in cmd line "
                  "nor located inside %s file" % KEYS_FILE)
        else:
            print("[+] Searching in Spyse..")
            temp = SpyseSearch(info['domain'], spysekey, args.limit, info['proxies'])
            subdomains = SpyseGetDomains(temp)
            info['all_hosts'].extend(subdomains)
            SubdomainsReport("SpyseSearch", subdomains, output_basename)

    # LinkedIn search #
    if any(i in ['linkedin'] for i in info['mode']):
        print("[+] Searching in LinkedIn..")
        temp1, temp2 = GoogleSearchEngine(info['domain'], 'linkedin.com', info['limit'], uas,
                                          info['proxies'], timeouts)
        info['all_emails'].extend(temp1)
        info['all_hosts'].extend(temp2)
        Report("LinkedIn", temp1, temp2, output_basename)

    #######################################################

    # Twitter search #
    if any(i in ['twitter'] for i in info['mode']):
        print("[+] Searching in Twitter..")
        temp1, temp2 = GoogleSearchEngine(info['domain'], "twitter.com", info['limit'], uas,
                                          info['proxies'], timeouts)
        info['all_emails'].extend(temp1)
        info['all_hosts'].extend(temp2)
        Report("Twitter", temp1, temp2, output_basename)

    #######################################################

    # Youtube search #
    if any(i in ['youtube'] for i in info['mode']):
        print("[+] Searching in Youtube..")
        temp1, temp2 = GoogleSearchEngine(info['domain'], "youtube.com", info['limit'], uas,
                                          info['proxies'], timeouts)
        info['all_emails'].extend(temp1)
        info['all_hosts'].extend(temp2)
        Report("Youtube", temp1, temp2, output_basename)

    #######################################################

    # Reddit search #
    if any(i in ['reddit'] for i in info['mode']):
        print("[+] Searching in Reddit..")
        temp1, temp2 = GoogleSearchEngine(info['domain'], "reddit.com", info['limit'], uas,
                                          info['proxies'], timeouts)
        info['all_emails'].extend(temp1)
        info['all_hosts'].extend(temp2)
        Report("Reddit", temp1, temp2, output_basename)

    #######################################################

    # Github search #
    if any(i in ['github'] for i in info['mode']):
        print("[+] Searching in Github..")
        temp1, temp2 = GoogleSearchEngine(info['domain'], "github.com", info['limit'], uas,
                                          info['proxies'], timeouts)
        info['all_emails'].extend(temp1)
        info['all_hosts'].extend(temp2)
        Report("Github", temp1, temp2, output_basename)

    #######################################################

    # Instagram search #
    if any(i in ['instagram'] for i in info['mode']):
        print("[+] Searching in Instagram..")
        temp1, temp2 = GoogleSearchEngine(info['domain'], "instagram.com", info['limit'], uas,
                                          info['proxies'],
                                          timeouts)
        info['all_emails'].extend(temp1)
        info['all_hosts'].extend(temp2)
        Report("Instagram", temp1, temp2, output_basename)

    #######################################################

    # Censys.io search #
    if any(i in ['censys'] for i in info['mode']):
        api_id = args.censys_api_id
        api_secret = args.censys_api_secret
        if api_id is not None and api_secret is not None:
            print("[+] Searching in Censys.io..\n")
            res1 = DomainSearchCensys(info['domain'], api_id, api_secret,
                                      output_basename, info['domains'])
            res2 = CensysPublicScan(api_id, api_secret, output_basename, args,
                                    report_buckets, match, info['public'])
            if res1 == False and res2 == False:
                print(
                    "Please use the available censys.io options in order to perform scanning. "
                    "For more information use the '--help' option")
            print()
        else:
            chkstored = checkFile()
            flag = 0
            if chkstored == False:
                chkanswer = input(
                    "[!] API Keys not provided. Would you like to store your API keys ? [y/n]: ")
                if chkanswer == 'y':
                    stored = createFileAndStoreAPIKeys('censys')
                    if stored == "stored":
                        print()
                        readFileContents()
                        print()
                        answer1 = input(
                            "[*] would you like to continue searching with censys.io ? [y/n] ")
                        print()
                        if answer1 == 'n':
                            flag = 1
                            print("[*] Exiting...")
                            exit(0)
                        if answer1 == 'y':
                            with open(KEYS_FILE) as f:
                                lines = f.read().splitlines()
                                print("[+] Searching in Censys.io..")
                                print()
                                for line in lines:
                                    res1 = DomainSearchCensys(
                                        info['domain'], line.split(":")[1], line.split(":")[2],
                                        output_basename, info['domains'])
                                    res2 = CensysPublicScan(
                                        line.split(":")[1], line.split(":")[2], output_basename,
                                        args, report_buckets, match, info['public'])
                                    if res1 == False and res2 == False:
                                        print('Please use the available censys.io options in order'
                                              'to perform scanning. For more information use the '
                                              '\'--help\' option')
                                    print()
                                    flag = 1
                    else:
                        print("[x] API keys has not been stored..")
                        print("[*] Exiting...")
                        exit(0)
                if chkanswer == 'n':
                    print(
                        "[!] Please provide the API keys in the command line to continue searching")
                    print("[*] Exiting....")
                    exit(0)

            if chkstored is True:
                if args.update_api_keys is True and args.mode == 'censys' and flag != 1:
                    keysupdate = updateAPIKeys('censys')
                    if keysupdate == 'n':
                        print("[x] the keys have not been updated")
                        print("[*] Exiting...")
                        exit(0)
                        print()
                    else:
                        print("[!] the keys have been successfully updated!")
                        answer1 = input(
                            "[*] would you like to continue searching with censys.io ? [y/n] ")
                        print()
                        if answer1 == 'y':
                            with open(KEYS_FILE) as f:
                                lines = f.read().splitlines()
                                print("[+] Searching in Censys.io..")
                                print()
                                for line in lines:
                                    res1 = DomainSearchCensys(
                                        info['domain'], line.split(":")[1], line.split(":")[2],
                                        output_basename, info['domains'])
                                    res2 = CensysPublicScan(
                                        line.split(":")[1], line.split(":")[2], output_basename,
                                        args, report_buckets, match, info['public'])
                                    if res1 == False and res2 == False:
                                        print("Please use the available censys.io options in order"
                                              " to perform scanning. For more information use "
                                              " the '--help' option\n")
                        else:
                            print("[*] Exiting...")
                            exit(0)
                else:
                    if args.read_api_keys is not True:
                        with open(KEYS_FILE) as f:
                            lines = f.read().splitlines()
                            print("[+] Searching in Censys.io..")
                            print()
                            for line in lines:
                                res1 = DomainSearchCensys(
                                    info['domain'], line.split(":")[1], line.split(":")[2],
                                    output_basename, info['domains'])
                                res2 = CensysPublicScan(
                                    line.split(":")[1], line.split(":")[2], output_basename, args,
                                    report_buckets, match, info['public'])
                                if res1 == False and res2 == False:
                                    print("Please use the available censys.io options in order to "
                                          "perform scanning. For more information use the '--help'"
                                          " option\n")

                if args.read_api_keys is True and args.mode == 'censys' and flag != 1:
                    print()
                    readFileContents()
                    print()
                    answer1 = input(
                        "[*] would you like to continue searching with censys.io ? [y/n] ")
                    print()
                    if answer1 == 'y':
                        with open(KEYS_FILE) as f:
                            lines = f.read().splitlines()
                            print("[+] Searching in Censys.io..")
                            print()
                            for line in lines:
                                res1 = DomainSearchCensys(
                                    info['domain'], line.split(":")[1], line.split(":")[2],
                                    output_basename, info['domains'])
                                res2 = CensysPublicScan(
                                    line.split(":")[1], line.split(":")[2], output_basename, args,
                                    report_buckets, match, info['public'])
                                if res1 is False and res2 is False:
                                    print(
                                        "Please use the available censys.io options in order to "
                                        "perform scanning. For more information use the "
                                        "'--help' option\n")
                    else:
                        print("[*] Exiting...")
                        exit(0)

    #######################################################

    # Search Results Final Report #
    info['all_emails'] = sorted(set(info['all_emails']))
    info['all_hosts'] = sorted(set(info['all_hosts']))
    info['domains'] = sorted(set(info['domains']))
    FinalReport(info, output_basename)

    #######################################################

    # Close tags for xml and html #
    if output_basename:
        output = output_basename + ".xml"
        output1 = output_basename + ".html"

        with open(output, 'a') as xml, open(output1, 'a') as html:
            xml.write("</report>\n")
            html.write("</body></html>\n")


#######################################################

if __name__ == '__main__':

    try:
        MainFunc()
    except KeyboardInterrupt:
        print("Search interrupted by user..")
    except Exception as e:
        if DEBUG:
            print(e)
        sys.exit()

#######################################################
