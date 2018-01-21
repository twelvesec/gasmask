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
__version__ = "1.0"

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

def DnsQuery(value, dnsserver):

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

	myresolver = dns.resolver.Resolver()
	myresolver.nameservers = [dnsserver]

	for rec in dnsData:
		try:
			answers = myresolver.query(value, rec)
			for answer in answers:
				if rec is 'NS':
					dnsData[rec].append(answer.to_text() + ":" + VerifyHostname(answer.to_text()))
				elif rec is 'MX':
					domain_name = re.search(' (.*)\.', answer.to_text(), re.IGNORECASE).group(1)
					dnsData[rec].append(answer.to_text() + ":" + VerifyHostname(domain_name))
				else:
					dnsData[rec].append(answer.to_text())
		except Exception as e:
			dnsData[rec].append('-')

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
		 	r = requests.get(url, verify=False, headers={'User-Agent': PickRandomUA(uas)}, proxies=proxies)
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
		 	r = requests.get(url, verify=False, headers={'User-Agent': PickRandomUA(uas)}, proxies=proxies)
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

## Bing search ##

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
		 	r = requests.get(url, verify=False, headers={'User-Agent': PickRandomUA(uas)}, proxies=proxies)
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
			r = requests.get(url, verify=False, headers={'User-Agent': PickRandomUA(uas)}, proxies=proxies)
			if r.status_code != 200:
		 		print "[-] Something is going wrong (status code: {})".format(r.status_code)
		 		return [], []
		 	results += r.content
			# s = requests.Session()
			# s.headers.update({'Host': server})
			# s.headers.update({'User-Agent': PickRandomUA(uas)})
			# s.headers.update({'Accept': '*/*'})
			# s.headers.update({'Accept-Language': 'en-US,en;q=0.5'})
			# s.headers.update({'Accept-Encoding': 'gzip, deflate'})
			# s.headers.update({'Connection': 'close'})
			# r = s.get("https://" + server, verify=False, proxies=proxies)
			# s.headers.update({'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'})
			# s.headers.update({'Referer': "https://"+ server + "/"})
		 	# r = s.get(url, verify=False, proxies=proxies)
		 	# results += r.content
		except Exception,e:
			print e

		time.sleep(PickRandomTimeout(timeouts))
		counter += step

	return GetEmails(results, value), GetHostnames(results, value)

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
		 	r = requests.get(url, verify=False, headers={'User-Agent': PickRandomUA(uas)}, proxies=proxies)
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

## Console report ##

def TerminalReport(emails, hostnames):
	print
	print "Emails:"
	for email in emails:
		print email
	print
	print "Hostnames:"
	for host in hostnames:
		print host
	print

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

	parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter)

	parser.add_argument("-d", '--domain', action="store", metavar='DOMAIN', dest='domain',
		default=None, type=CheckDomain, help="Domain to search.", required=True)
	parser.add_argument("-s", '--server', action="store", metavar='NAMESERVER', dest='dnsserver',
		default='8.8.8.8', type=CheckDomainOrIP, help="DNS server to use.")
	parser.add_argument('-x', '--proxy', action="store", metavar='PROXY', dest='proxy',
		default=None, type=str, help="Use a proxy server when retrieving results from search engines (eg. '-x http://127.0.0.1:8080')")
	parser.add_argument("-l", '--limit', action="store", metavar='LIMIT', dest='limit',
		type=int, default=100, help="Limit the number of search engine results (default: 100).")

    #parser.add_argument('-o', '--output', action='store', metavar='BASENAME', dest='basename',
    #                    type=str, default=None, help='Output in the four major formats at once.')

    # alternative user-agent: GasMasK {}

	if len(sys.argv) is 1:
		parser.print_help()
		sys.exit()

	args = parser.parse_args()

	info['domain'] = args.domain
	proxies = {}

#######################################################

## Load User-Agents strings from file ##

	if os.path.isfile(user_agent_strings_file):
		uas = lines = [line.strip() for line in open(user_agent_strings_file)]

#######################################################

## information ##

	limit = args.limit
	print "[+] Looking into first {} search engines results".format(limit)

	dnsserver = args.dnsserver
	print "[+] Using DNS server: " + dnsserver

	if args.proxy:
		proxies = {
		      'http': args.proxy,
		      'https': args.proxy,
		  }
		print "[+] Using Proxy server: " + args.proxy
		print

#######################################################

## target ##

	info['ip'] = VerifyHostname(info['domain'])
	print "[+] Target: " + info['domain'] + ":" + info['ip']
	print

#######################################################

## Whois query report ##

	print "[+] Whois lookup:"
	print "-----------------"
	info['whois'] = WhoisQuery(info['domain'])
	for key,value in info['whois'].iteritems():
		if isinstance(value[0], list):
			print
			print value[1]
			for val in value[0]:
				print val
			print
		else:
			print value[1] + " " + value[0]
	print

#######################################################

## DNS records report ##

	print "[+] DNS queries:"
	print "----------------"
	info['dns'] = DnsQuery(info['domain'], dnsserver)
	for key,value in info['dns'].iteritems():
		if(len(value) == 1):
			print key + " DNS record: " + value[0]
		else:
			print
			print key + " DNS record: "
			for val in value:
				print val
			print
	print

#######################################################

## IP Reverse DNS lookup report ##

	print "[+] Reverse DNS Lookup:"
	print "-----------------------"
	info['revdns'] = ReverseIPQuery(info['ip'], dnsserver)
	if info['revdns']:
		print info['ip'] + ":" + info['revdns']
	print

#######################################################

# Bing Virtual Hosts search results report ##

	print "[+] Bing Virtual Hosts:"
	print "-----------------------"
	info['bingvhosts'] = BingVHostsSearch(info['ip'], limit, uas, proxies, timeouts)
	print
	for host in info['bingvhosts']:
		print host
	print

#######################################################

## Google search ##

	print "[+] Searching in Google.."
	temp1, temp2 = GoogleSearch(info['domain'], limit, uas, proxies, timeouts)
	info['all_emails'].extend(temp1)
	info['all_hosts'].extend(temp2)
	TerminalReport(temp1, temp2)

#######################################################

## Bing search ##

	print "[+] Searching in Bing.."
	temp1, temp2 = BingSearch(info['domain'], limit, uas, proxies, timeouts)
	info['all_emails'].extend(temp1)
	info['all_hosts'].extend(temp2)
	TerminalReport(temp1, temp2)

#######################################################

## Yahoo search ##

	print "[+] Searching in Yahoo.."
	temp1, temp2 = YahooSearch(info['domain'], limit, uas, proxies, timeouts)
	info['all_emails'].extend(temp1)
	info['all_hosts'].extend(temp2)
	TerminalReport(temp1, temp2)

#######################################################

## ASK search ##

	print "[+] Searching in ASK.."
	temp1, temp2 = AskSearch(info['domain'], 5, uas, proxies, timeouts) #5 pages
	info['all_emails'].extend(temp1)
	info['all_hosts'].extend(temp2)
	TerminalReport(temp1, temp2)

#######################################################

## Dogpile search ##

	print "[+] Searching in Dogpile.."
	temp1, temp2 = DogpileSearch(info['domain'], limit, uas, proxies, timeouts)
	info['all_emails'].extend(temp1)
	info['all_hosts'].extend(temp2)
	TerminalReport(temp1, temp2)

#######################################################

## Yandex search ##

	print "[+] Searching in Yandex.."
	temp1, temp2 = YandexSearch(info['domain'], limit, uas, proxies, timeouts)
	info['all_emails'].extend(temp1)
	info['all_hosts'].extend(temp2)
	TerminalReport(temp1, temp2)

#######################################################

## LinkedIn search ##

	print "[+] Searching in LinkedIn.."
	temp1, temp2 = SiteSearch(info['domain'], 'linkedin.com', limit, uas, proxies, timeouts)
	info['all_emails'].extend(temp1)
	info['all_hosts'].extend(temp2)
	TerminalReport(temp1, temp2)

#######################################################

## Twitter search ##

	print "[+] Searching in Twitter.."
	temp1, temp2 = SiteSearch(info['domain'], "twitter.com", limit, uas, proxies, timeouts)
	info['all_emails'].extend(temp1)
	info['all_hosts'].extend(temp2)
	TerminalReport(temp1, temp2)

#######################################################

## Google+ search ##

	print "[+] Searching in Google+.."
	temp1, temp2 = SiteSearch(info['domain'], "plus.google.com", limit, uas, proxies, timeouts)
	info['all_emails'].extend(temp1)
	info['all_hosts'].extend(temp2)
	TerminalReport(temp1, temp2)

#######################################################

## Youtube search ##

	print "[+] Searching in Youtube.."
	temp1, temp2 = SiteSearch(info['domain'], "youtube.com", limit, uas, proxies, timeouts)
	info['all_emails'].extend(temp1)
	info['all_hosts'].extend(temp2)
	TerminalReport(temp1, temp2)

#######################################################

## Reddit search ##

	print "[+] Searching in Reddit.."
	temp1, temp2 = SiteSearch(info['domain'], "reddit.com", limit, uas, proxies, timeouts)
	info['all_emails'].extend(temp1)
	info['all_hosts'].extend(temp2)
	TerminalReport(temp1, temp2)

#######################################################

## Github search ##

	print "[+] Searching in Github.."
	temp1, temp2 = SiteSearch(info['domain'], "github.com", limit, uas, proxies, timeouts)
	info['all_emails'].extend(temp1)
	info['all_hosts'].extend(temp2)
	TerminalReport(temp1, temp2)

#######################################################

## Instagram search ##

	print "[+] Searching in Instagram.."
	temp1, temp2 = SiteSearch(info['domain'], "instagram.com", limit, uas, proxies, timeouts)
	info['all_emails'].extend(temp1)
	info['all_hosts'].extend(temp2)
	TerminalReport(temp1, temp2)

#######################################################

## Search Results Final Report ##

	print
	print "[+] Search engines results - Final Report:"
	print "------------------------------------------"
	info['all_emails'] = sorted(set(info['all_emails']))
	info['all_hosts'] = sorted(set(info['all_hosts']))
	TerminalReport(info['all_emails'], info['all_hosts'])

#######################################################

if __name__ == '__main__':

	try:
		MainFunc()
	except KeyboardInterrupt:
		print "Search interrupted by user.."
	except:
		sys.exit()

#######################################################
