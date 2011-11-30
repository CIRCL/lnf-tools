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

import klookupd
import getopt
import sys

def usage (exitcode):
    print """
klookup-cli - A client to interact with klookupd

USAGE

    klookupd-cli [-h] [-t] [-s style -f ipaddress in a pcap filter]  [-q] [-r]
                 [-e]

DESCRIPTION

    klookupd-cli asks the klookup daemon klookupd for doing a query about
    an IP address. klookupd-cli is asynchronous because the lookup of
    IP addresses can take some time The daemon returns an identifier for the
    job. After a  while klookup-cli can check the state of the launched job.

OPTIONS

    -h Shows this screen
    -t Specify the start time stamp. It is advised to set one because
       the less records need to be searched the less will be the
       execution time. Day format: YYYY-MM-DD
    -c Specify the kindexer config file
    -q uuid Query the state of a job. The job is identified with an uuid that
       was delivered with the i switch
    -r uuid Query the results for a job identified with uuid. The results are
       printed on standard output
    -f Specify a pcap filter that can be applied on the nfcapd files
    -l List all the registered jobs with their state
    -e Specify end time which is the latest date where the serach such be done

If no start state end end date is specified, the entire databases are searched
which may take some time

AUTHOR
    Gerard Wagener


LICENSE
    GPLv3

"""
    sys.exit(exitcode)

try:
    configFile = None
    timestamp = None
    style = None
    filtr = None
    ticket = None
    results = None
    shouldList = False
    endtime = None
    #Parse command line arguments
    opts, args = getopt.getopt(sys.argv[1:],'lr:q:s:f:ht:c:e:')
    for o,a in opts:
        if o == '-h':
            usage(0)
        elif o == '-c':
            configFile = a
        elif o == '-s':
            style = a
        elif o == '-f':
            filtr = a
        elif o == '-t':
            timestamp = a
        elif o == '-q':
            ticket = a
        elif o == '-r':
            results = a
        elif o == '-l':
            shouldList  = True
        elif o == '-e':
            endtime = a

    if configFile == None:
        sys.stderr.write('A config must be specified\n')
        sys.exit(0)

    kl = klookupd.KlookupIPC(configFile)

    #Handling of the various options
    #Job listing
    if shouldList == True:
        jobs = kl.list_jobs()
        if len(jobs.keys()) == 0:
            print "There are no jobs"
        else:
            print "#Ticket number, state"
            for i in jobs.keys():
                print i,',',jobs[i]
        sys.exit(0)
    #Query the state for a given ticket
    if ticket != None:
        state = kl.get_status(ticket)
        if state != None:
            print state
            sys.exit(0)
        #There has been an error
        sys.stderr.write('No state was found for ' + ticket + '\n')
        sys.exit(1)

    #Query the result for a given ticket
    if results != None:
        res = kl.get_query_result(results)
        if len(res) > 1:
            for line in res:
                print line
            sys.exit(0)
        #There has been an error
        sys.stderr.write('Could not get the results for the job for ticket ' + results +'\n')

    #If there is an IP address set I assume that it is for getting a ticket
    if filtr != None:
        ticket = kl.query(filtr, style, timestamp, endtime)
        if ticket != None:
            print "Got a ticket "+ ticket
            sys.exit(0)
        sys.stderr.write('Job could not be processed\n')
        sys.exit(1)

except getopt.GetoptError,e:
    sys.stderr.write(str(e)+ '\n')
    sys.exit(1)

except klookupd.KlookupException,e:
    sys.stderr.write(str(e) + '\n')
