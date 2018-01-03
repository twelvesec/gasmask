#!/usr/bin/env python2
# encoding: UTF-8

"""
    This file is part of GasMasK
    Copyright (C) 2018 @maldevel

    TwelveSec Research
    https://github.com/twelvesec/gasmask

    GasMasK - All in one Information gathering tool - OSINT.

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
__copyright__ = "Copyright (c) 2018 @maldevel"
__credits__ = ["maldevel"]
__license__ = "GPLv3"
__version__ = "1.0"
__maintainer__ = "maldevel"

#######################################################

import argparse
from argparse import RawTextHelpFormatter
import validators
import sys
import socket
import whois
import dns.resolver
import collections

#######################################################

message = """
   ______           __  ___           __ __
  / ____/___ ______/  |/  /___ ______/ //_/
 / / __/ __ `/ ___/ /|_/ / __ `/ ___/ ,<
/ /_/ / /_/ (__  ) /  / / /_/ (__  ) /| |
\____/\__,_/____/_/  /_/\__,_/____/_/ |_|

GasMasK Ver. {}
Information Gathering Tool - OSINT
@maldevel
TwelveSec Research
""".format(__version__)

#######################################################

def checkDomain(value):
    if not validators.domain(value) or not verifyHostname(value):
        raise argparse.ArgumentTypeError('Invalid {} domain.'.format(value))
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

def dnsQuery(value):
    dnsData = {
        "A":[],
        "CNAME":[],
        "HINFO":[],
        "MX":[],
        "NS":[],
        "PTR":[],
        "SOA":[],
        "TXT":[],
        "SPF":[]
    }

    for rec in dnsData:
        try:
            answers = dns.resolver.query(value, rec)
            for answer in answers:
                dnsData[rec].append(answer.to_text())
        except Exception as e:
            dnsData[rec].append('-')

    return dnsData

#######################################################

if __name__ == '__main__':
    print message
    info = {}

    parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter)
    parser.add_argument("-d", '--domain', action="store", metavar='DOMAIN', dest='domain', 
                        default=None, type=checkDomain, help="Domain to search.")
    #parser.add_argument('-o', '--output', action='store', metavar='BASENAME', dest='basename', 
    #                    type=str, default=None, help='Output in the three major formats at once')

    if len(sys.argv) is 1:
        parser.print_help()
        sys.exit()

    args = parser.parse_args()

    info['domain'] = args.domain

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
    info['dns'] = dnsQuery(info['domain'])
    for key,value in info['dns'].iteritems():
        print key + " DNS record: "
        for val in value:
            print val
        print

#######################################################
