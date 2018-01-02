#!/usr/bin/env python2
# encoding: UTF-8

"""
    This file is part of GasMasK
    Copyright (C) 2018 @maldevel

    TwelveSec Research
    https://github.com/twelvesec/gasmask

    GasMasK - A Information gathering tool - OSINT.

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

def verifyHostname(value):
    try:
        ip = socket.gethostbyname(value)
        return ip
    except Exception as e:
        return False

def whoisQuery(value):
    whoisData = {}
    domain = whois.whois(value)
    whoisData['updated_date'] = domain['updated_date']
    whoisData['name'] = domain['name']
    whoisData['expiration_date'] = domain['expiration_date']
    whoisData['registrar'] = domain['registrar']
    whoisData['name_servers'] = domain['name_servers']
    whoisData['org'] = domain['org']
    whoisData['creation_date'] = domain['creation_date']

    return whoisData

#######################################################

if __name__ == '__main__':
    print message
    info = {}

    parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter)
    parser.add_argument("-d", '--domain', action="store", metavar='DOMAIN', dest='domain', 
                        default=None, type=checkDomain, help="Domain to search.")
    parser.add_argument('-o', '--output', action='store', metavar='BASENAME', dest='basename', 
                        type=str, default=None, help='Output in the three major formats at once')

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

    print "[+] Whois:"
    print "----------"
    info['whois'] = whoisQuery(info['domain'])
    print "Name: " + info['whois']['name']
    print "Organization: " + info['whois']['org']
    print "Registrar: " + info['whois']['registrar']
    info['whois']['name_servers_ips'] = []
    info['whois']['name_servers_ips'].append(verifyHostname(info['whois']['name_servers'][0]))
    info['whois']['name_servers_ips'].append(verifyHostname(info['whois']['name_servers'][1]))
    print "Name Servers: " + info['whois']['name_servers'][0] + ":" + info['whois']['name_servers_ips'][0] + ", " + info['whois']['name_servers'][1] + ":" + info['whois']['name_servers_ips'][1]
    print "Creation Date: " + str(info['whois']['creation_date'])
    print "Updated Date: " + str(info['whois']['updated_date'])
    print "Expiration Date: " + str(info['whois']['expiration_date']) + "\n"

    
    