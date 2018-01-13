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
from dns import reversename, resolver
import requests
import lxml

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

def checkDomain(value):
    if not validators.domain(value) or not verifyHostname(value):
        raise argparse.ArgumentTypeError('Invalid {} domain.'.format(value))
    return value

def checkDomainOrIP(value):
	if not validators.domain(value) and not validators.ip_address.ipv4(value):
		raise argparse.ArgumentTypeError('Invalid domain or ip address ({}).'.format(value))
	return value

###

def verifyHostname(value):
    try:
        ip = socket.gethostbyname(value)
        return ip
    except Exception as e:
        return False

###

def whoisQuery(value):
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
                        whoisData[rec][0].append(val + ":" + verifyHostname(val))
                else:
                    whoisData[rec][0] = []
                    for val in domain[rec]:
                        whoisData[rec][0].append(val)
            else:
                whoisData[rec][0] = str(domain[rec])

    return whoisData

###

def dnsQuery(value, dnsserver):
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
					dnsData[rec].append(answer.to_text() + ":" + verifyHostname(answer.to_text()))
				elif rec is 'MX':
					domain_name = re.search(' (.*)\.', answer.to_text(), re.IGNORECASE).group(1)
					dnsData[rec].append(answer.to_text() + ":" + verifyHostname(domain_name))
				else:
					dnsData[rec].append(answer.to_text())
		except Exception as e:
			dnsData[rec].append('-')

	return dnsData

###

def tldQuery(value, dnsserver):
	tldData = []

	tlds = [
            "ac", "academy", "ad", "ae", "aero", "af", "ag", "ai", "al", "am", "an", "ao", "aq", "ar", "arpa", "as",
            "asia", "at", "au", "aw", "ax", "az", "ba", "bb", "bd", "be", "bf", "bg", "bh", "bi", "bike", "biz", "bj",
            "bm", "bn", "bo", "br", "bs", "bt", "builders", "buzz", "bv", "bw", "by", "bz", "ca", "cab", "camera",
            "camp", "careers", "cat", "cc", "cd", "center", "ceo", "cf", "cg", "ch", "ci", "ck", "cl", "clothing",
            "cm", "cn", "co", "codes", "coffee", "com", "company", "computer", "construction", "contractors", "coop",
            "cr", "cu", "cv", "cw", "cx", "cy", "cz", "de", "diamonds", "directory", "dj", "dk", "dm", "do",
            "domains", "dz", "ec", "edu", "education", "ee", "eg", "email", "enterprises", "equipment", "er", "es",
            "estate", "et", "eu", "farm", "fi", "fj", "fk", "florist", "fm", "fo", "fr", "ga", "gallery", "gb", "gd",
            "ge", "gf", "gg", "gh", "gi", "gl", "glass", "gm", "gn", "gov", "gp", "gq", "gr", "graphics", "gs", "gt",
            "gu", "guru", "gw", "gy", "hk", "hm", "hn", "holdings", "holiday", "house", "hr", "ht", "hu", "id", "ie",
            "il", "im", "immobilien", "in", "info", "institute", "int", "international", "io", "iq", "ir", "is", "it",
            "je", "jm", "jo", "jobs", "jp", "kaufen", "ke", "kg", "kh", "ki", "kitchen", "kiwi", "km", "kn", "kp",
            "kr", "kw", "ky", "kz", "la", "land", "lb", "lc", "li", "lighting", "limo", "lk", "lr", "ls", "lt", "lu",
            "lv", "ly", "ma", "management", "mc", "md", "me", "menu", "mg", "mh", "mil", "mk", "ml", "mm", "mn", "mo",
            "mobi", "mp", "mq", "mr", "ms", "mt", "mu", "museum", "mv", "mw", "mx", "my", "mz", "na", "name", "nc",
            "ne", "net", "nf", "ng", "ni", "ninja", "nl", "no", "np", "nr", "nu", "nz", "om", "onl", "org", "pa", "pe",
            "pf", "pg", "ph", "photography", "photos", "pk", "pl", "plumbing", "pm", "pn", "post", "pr", "pro", "ps",
            "pt", "pw", "py", "qa", "re", "recipes", "repair", "ro", "rs", "ru", "ruhr", "rw", "sa", "sb", "sc", "sd",
            "se", "sexy", "sg", "sh", "shoes", "si", "singles", "sj", "sk", "sl", "sm", "sn", "so", "solar",
            "solutions", "sr", "st", "su", "support", "sv", "sx", "sy", "systems", "sz", "tattoo", "tc", "td",
            "technology", "tel", "tf", "tg", "th", "tips", "tj", "tk", "tl", "tm", "tn", "to", "today", "tp", "tr",
            "training", "travel", "tt", "tv", "tw", "tz", "ua", "ug", "uk", "uno", "us", "uy", "uz", "va", "vc",
            "ve", "ventures", "vg", "vi", "viajes", "vn", "voyage", "vu", "wang", "wf", "wien", "ws", "xxx", "ye",
            "yt", "za", "zm", "zw"]

	myresolver = dns.resolver.Resolver()
	myresolver.nameservers = [dnsserver]

	for tld in tlds:
		try:
			hostname = value.split('.')[0] + '.' + tld
			answers = myresolver.query(hostname, 'A')
			for answer in answers:
				tldData.append(hostname + ":" + answer.to_text())
		except Exception as e:
			pass

	return tldData

###

def reverseIPQuery(value, dnsserver):
	try:
		revname = reversename.from_address(value)
		myresolver = dns.resolver.Resolver()
		myresolver.nameservers = [dnsserver]
		return str(myresolver.query(revname, 'PTR')[0]).rstrip('.')
	except Exception as e:
		print e
		return ''

###

def httpStatusQuery(value):

	r = requests.get('http://{}'.format(value), verify=False)
	title = ''
	if r.status_code == 200:
		title = re.search('(?<=<title>).+?(?=</title>)', r.text, re.DOTALL)
		if title:
			title = title.group().strip()
		else:
			title = ''
	return r.status_code, title

#######################################################

if __name__ == '__main__':
	print message
	info = {}

	parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter)
	parser.add_argument("-d", '--domain', action="store", metavar='DOMAIN', dest='domain',
                        default=None, type=checkDomain, help="Domain to search.")
	parser.add_argument("-s", '--server', action="store", metavar='NAMESERVER', dest='dnsserver',
                        default=None, type=checkDomainOrIP, help="DNS server to use.")
    #parser.add_argument('-o', '--output', action='store', metavar='BASENAME', dest='basename',
    #                    type=str, default=None, help='Output in the four major formats at once.')

	if len(sys.argv) is 1:
		parser.print_help()
		sys.exit()

	args = parser.parse_args()

	info['domain'] = args.domain

#######################################################

	dnsserver = args.dnsserver
	if not dnsserver:
		dnsserver = '8.8.8.8'
	print "[+] Using DNS server: " + dnsserver
	print

#######################################################

	print "[+] Target:"
	print "-----------"
	info['ip'] = verifyHostname(info['domain'])
	print info['domain'] + ":" + info['ip'] + "\n"

#######################################################

	print "[+] Whois:"
	print "----------"
	info['whois'] = whoisQuery(info['domain'])
	for key,value in info['whois'].iteritems():
		if isinstance(value[0], list):
			print
			print value[1]
			for val in value[0]:
				print val
			print
		else:
			print value[1] + " " + value[0]

#######################################################

	print "[+] DNS:"
	print "--------"
	info['dns'] = dnsQuery(info['domain'], dnsserver)
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

	print "[+] DNS TLD expansion:"
	print "----------------------"
	info['tld'] = tldQuery(info['domain'], dnsserver)
	for val in info['tld']:
		status_code, title = httpStatusQuery(val.split(':')[0])
		if status_code == 200:
			print val + ":" + "HTTP Status " + str(status_code) + ":" + "Title \"" + title + "\""
		else:
			print val + ":" + "HTTP Status " + str(status_code)
	print

#######################################################

	print "[+] Reverse DNS Lookup:"
	print "-----------------------"
	info['revdns'] = reverseIPQuery(info['ip'], dnsserver)
	if info['revdns']:
		print info['ip'] + ":" + info['revdns']
	print

#######################################################
