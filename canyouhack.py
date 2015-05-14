#!/usr/bin/env python
# Name: seccheck
# Purpose: Check an IP against Nessus Security Center for Known Exploitable Vulnerabilities
# By:       Jerry Gamblin
# Date:     13.05.15
# Modified  13.05.15
# Rev Level 0.1
# Run 'pip install pysecuritycenter' for library
# -----------------------------------------------

import os
import sys
import json
import urllib
import urllib2
import hashlib
import argparse
import re
import socket
import ssl
import socket
import getopt
from urllib2 import urlopen
from securitycenter import SecurityCenter

# Provide the login info & security center address here:
username = ''
password = ''
host = ''

def color(text, color_code):
    if sys.platform == "win32" and os.getenv("TERM") != "xterm":
        return text

    return '\x1b[%dm%s\x1b[0m' % (color_code, text)


def red(text):
    return color(text, 31)


def blink(text):
    return color(text, 5)


def green(text):
    return color(text, 32)


def blue(text):
    return color(text, 34)

#Get IP To SCAN
if len(sys.argv) != 2:
    print("Error: specify an IP to connect to!")
    exit(0)

ip = sys.argv[1]

checkip = sys.argv[1]


#Ignore TLS Cert Error
if hasattr(ssl, '_create_unverified_context'):
	ssl._create_default_https_context = ssl._create_unverified_context



# Instantiate a Security Center instance and login with the credentials provided
sc = SecurityCenter(host, username, password)

#
vulns = sc.query('vulndetails', exploitAvailable='true', pluginType='active', severity='3,4', ip=checkip)

# Set IP Address:
ips ={}
if not vulns:
    print '\nYou Probably Cant Hack %s. Congrats!  : ) \n' % ip
else:
    for vuln in vulns:
        if vuln['ip'] not in ips:
            ips[vuln['ip']] = []
        ips[vuln['ip']].append(vuln)

# Now to print the output to the screen.  This could easily be rewritten to
# output to a file as well, or even parse it into a CSV file if needed.
for ip in ips:
    print 'Yep, you can hack %s. \nHere is how:' %ip
    print '\n'
    for vuln in ips[ip]:
	print '%s' % vuln['pluginName']
	print 'Base CVS Score: %s' % vuln['baseScore']
	print 'Severity: %s' % vuln['severity']
	print ((red('Synopsis:')) +'%s') % vuln['synopsis']
	print ((red('CVE:')) +'%s') % vuln['cve']
	print '\n'
