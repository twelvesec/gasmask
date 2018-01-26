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
		output = output_basename + ".txt"
		with open(output, 'a') as outfile:
			outfile.write("[+] {} results\n".format(engine))
			outfile.write("-------------------------\n")
			outfile.write("\n")
			outfile.write("Emails:\n")
			for email in emails:
				outfile.write("{}\n".format(email))

			outfile.write("\n")
			outfile.write("Hostnames:\n")
			for host in hostnames:
				outfile.write("{}\n".format(host))
			outfile.write("\n")

#######################################################

## Hostnames Console report ##

def HostnamesReport(engine, hostnames, output_basename):

	print
	print "Hostnames:"
	for host in hostnames:
		print host
	print

	if output_basename:
		output = output_basename + ".txt"
		with open(output, 'a') as outfile:
			outfile.write("[+] {} results\n".format(engine))
			outfile.write("-------------------------\n")
			outfile.write("\n")
			outfile.write("Hostnames:\n")
			for host in hostnames:
				outfile.write("{}\n".format(host))
			outfile.write("\n")

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
		output = output_basename + ".txt"
		with open(output, 'w') as outfile:
			outfile.write("{}\n".format(message))
			outfile.write("[+] Information gathering: {}\n".format(mode))
			outfile.write("[+] Looking into first {} search engines results\n".format(limit))
			outfile.write("[+] Using DNS server: {}\n".format(dnsserver))
			if proxy:
				outfile.write("[+] Using Proxy server: {}\n".format(proxy))
			outfile.write("[+] Target: {}:{}\n".format(domain, ip))
			outfile.write("[+] User-agent strings: {}\n".format(uas))
			outfile.write("\n")

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
		output = output_basename + ".txt"
		with open(output, 'a') as outfile:
			outfile.write("[+] Whois lookup\n")
			outfile.write("----------------\n")
			for key,value in data.iteritems():
				if isinstance(value[0], list):
					outfile.write("\n")
					outfile.write("{}\n".format(value[1]))
					for val in value[0]:
						outfile.write("{}\n".format(val))
					outfile.write("\n")
				else:
					outfile.write("{} {}\n".format(value[1], value[0]))
			outfile.write("\n")

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
		output = output_basename + ".txt"
		with open(output, 'a') as outfile:
			outfile.write("[+] DNS queries\n")
			outfile.write("---------------\n")
			for key,value in data.iteritems():
				if(len(value) == 1):
					outfile.write("{} DNS record: {}\n".format(key, value[0]))
				else:
					outfile.write("\n")
					outfile.write("{} DNS record:\n".format(key))
					for val in value:
						outfile.write("{}\n".format(val))
					outfile.write("\n")
			outfile.write("\n")

#######################################################

## Reverse DNS Console report ##

def ReverseDNSReport(ip, data, output_basename):

	if data:
		print ip + ":" + data
	print

	if output_basename:
		output = output_basename + ".txt"
		with open(output, 'a') as outfile:
			outfile.write("[+] Reverse DNS Lookup\n")
			outfile.write("----------------------\n")
			if data:
				outfile.write("{}:{}\n".format( ip, data))
			outfile.write("\n")

#######################################################

## VHosts Console report ##

def VHostsReport(data, output_basename):

	for host in data:
		print host
	print

	if output_basename:
		output = output_basename + ".txt"
		with open(output, 'a') as outfile:
			outfile.write("[+] Bing Virtual Hosts\n")
			outfile.write("----------------------\n")
			for host in data:
				outfile.write("{}\n".format(host))
			outfile.write("\n")

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
		output = output_basename + ".txt"
		with open(output, 'a') as outfile:
			outfile.write("[+] Search engines results - Final Report\n")
			outfile.write("-----------------------------------------\n")
			outfile.write("\n")
			outfile.write("Emails:\n")
			for email in info['all_emails']:
				outfile.write("{}\n".format(email))

			outfile.write("\n")
			outfile.write("Hostnames:\n")
			for host in info['all_hosts']:
				outfile.write("{}\n".format(host))
			outfile.write("\n")

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

	modes = ['basic','whois', 'dns', 'revdns', 'vhosts', 'google', 'bing', 'yahoo',
		'ask', 'dogpile', 'yandex', 'linkedin', 'twitter', 'googleplus', 'youtube', 'reddit',
		'github', 'instagram', 'crt', 'pgp', 'netcraft', 'virustotal']

	parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter)

	parser.add_argument("-d", '--domain', action="store", metavar='DOMAIN', dest='domain',
		default=None, type=CheckDomain, help="Domain to search.", required=True)
	parser.add_argument("-s", '--server', action="store", metavar='NAMESERVER', dest='dnsserver',
		default='8.8.8.8', type=CheckDomainOrIP, help="DNS server to use.")
	parser.add_argument('-x', '--proxy', action="store", metavar='PROXY', dest='proxy',
		default=None, type=str, help="Use a proxy server when retrieving results from search engines (eg. '-x http://127.0.0.1:8080')")
	parser.add_argument("-l", '--limit', action="store", metavar='LIMIT', dest='limit',
		type=int, default=100, help="Limit the number of search engine results (default: 100).")
	parser.add_argument("-i", '--info', action="store", metavar='MODE', dest='mode',
		type=str, default='basic', help="Limit information gathering (" + ','.join(modes) + ").")
	parser.add_argument('-o', '--output', action='store', metavar='BASENAME', dest='basename',
		type=str, default=None, help='Output in the four major formats at once (markdown, txt, xml and html).')

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

if __name__ == '__main__':

	try:
		MainFunc()
	except KeyboardInterrupt:
		print "Search interrupted by user.."
	except:
		sys.exit()

#######################################################
