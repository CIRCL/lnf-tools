#!/usr/bin/python
#
# nfdump-tools - Inspecting the output of nfdump
#
# Copyright (C) 2011 CIRCL Computer Incident Response Center Luxembourg (smile gie)
# Copyright (C) 2011 Gerard Wagener
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.


import getopt
import sys
import redis

def usage(exitcode):
    print """nfdump-mip [-i] [-h] [-t] [-c] [-r] [-d] [-a]

Adds an IP address in the monitoring queue. These IP addresses are polled by
the netflow dispatcher daemon which looks for these IP addresses in the indexed
netflow and moves the matched flows to the case directory identified by the case
number (-c switch)

OPTIONS

    -h Displays this screen
    -t Specify a timestamp when this IP address should be monitored. If no
       timestamp is specified all the data is processed.
    -i Specify the IP address
    -c Specify the case number. If not specified the the dispatcher daemon puts
       the corresponding flows in the case with the number 0
    -r Reset all the monitored IP addresses
    -d Remove the specified IP address from the monitoring queue instead of
       adding it
    -a If the alert flag is set an alert is sent if the specified IP address is
       observed

AUTHOR
Gerard Wagener

LICENSE
GPLv3
"""
    sys.exit(exitcode)


#Used keys by this program
#m:ipaddress => {"casenumber:timestamp:alertflag"}
#value is a set of casenumber:timestamp tuples:alertflag

def add_address(re, ipaddress, timestamp, casenumber, alertflag):
    try:
        k = "m:"+ipaddress
        v = str(casenumber) + ":" + str(timestamp)+":"+str(alertflag)
        re.sadd(k,v)
    except redis.exceptions.ConnectionError,e:
        sys.stderr.write('Could not store address. Error='+str(e)+'\n')
        sys.exit(1)
# Command line parameters
shouldReset = False
shouldRemove = False
timestamp = 0
ipaddress = None
casenumber = 0
alertflag=0

#Parse command line options
try:
    opts, args = getopt.getopt(sys.argv[1:], "ht:i:c:rda")
except getopt.GetoptError, err:
    sys.stderr.write(str(err)+'\n')
    usage(1)

for o, a in opts:
    if o == "-h":
        usage(0)
    elif o == "-t":
        timestamp = a
    elif o == '-i':
        ipaddress = a
    elif o == '-c':
        casenumber = a
    elif o == '-r':
        shouldReset = True
    elif o == '-d':
        shouldRemove = True
    elif o == '-a':
        alertflag == 1
    else:
        sys.stderr.write("Invalid command line option\n")

#Check mandatory parameters
if (ipaddress == None):
    sys.stderr.write('At least an IP address must be specified\n')
    sys.exit(1)

re = redis.Redis()
if (shouldRemove == False):
    add_address(re, ipaddress, timestamp, casenumber, alertflag)

