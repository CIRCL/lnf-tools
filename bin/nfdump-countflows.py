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


import kindcommon
import klookupd
import getopt
import sys
import os
import subprocess
#TODO base this program on kindexer.cfg to search automatically distributed
#directories



def usage(exitcode):
    print """
Count flows included in a set of nfdump files

nfdump-countflows -d flowdir

OPTIONS
    -h Shows this screen
    -d Specify the directory including the flows

OUTPUT

#filename num_flows num_bytes
nfcapd.201108300152 4570136 237654352

WHERE

    - filename corresponds to the file created by nfcapd
    - num_flows corresponds to the number of flows
    - num_bytes correspond to the number of bytes

AUTHOR
    Gerard Wagener

LICENSE
    GPLv3

"""
    sys.exit(0)

def process_file(filename, rootdir):
    if rootdir.endswith('/'):
        rootdir = rootdir[:-1]
    afile = rootdir + os.sep + filename
    cmd = [ '/usr/bin/nfdump', '-r'+afile, 'ip 0.0.0.0']

    process = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=None)
    #From nfdump expect something like this
    #Total flows processed: 4570136, Blocks skipped: 0, Bytes read: 237654352
    for line in process.stdout:
        if line.startswith('Total flows processed'):
            line = line.replace('\n','')
            t = line.split(' ')
            nflows = t[3].replace(',','')
            nbytes = t[9].replace(',','')
            print filename + ' ' +  nflows + ' '+nbytes

try:
    configfile = None
    rootdir = None
    opts,args = getopt.getopt(sys.argv[1:], 'hd:')
    for o,a in opts:
        if o == '-h':
            usage(0)
        elif o == '-d':
            rootdir = a

    if (rootdir == None):
        sys.stderr.write('A root directory must be specified\n')
        usage(1)

    #Get all files from the directory
    files = os.listdir(rootdir)
    #Focus only on nfcapd files
    nfiles = []
    for f in files:
        if f.startswith('nfcapd'):
            nfiles.append(f)

    #sort them to have them according timestamps
    nfiles.sort()
    print "#filename num_flows num_bytes"
    #Go through each file and do the accounting
    for f in nfiles:
        process_file(f, rootdir)
except getopt.GetoptError, err:
    sys.stderr.write(str(err) + '\n')
    usage(1)
