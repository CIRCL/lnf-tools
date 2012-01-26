#!/usr/bin/python
#
# nfdump-tools - Inspecting the output of nfdump
#
# Copyright (C) 2012 CIRCL Computer Incident Response Center Luxembourg (smile gie)
# Copyright (C) 2012 Gerard Wagener
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
import os
import redis
import time

def usage(exitcode):
    print """
Single process to index a recently transferred file by nfdump-replicator

USAGE
    kindexer-helper [-h] [-x] -d <dbroot> -n <nfroot>

OPTIONS
    -h --help     Shows this screen
    -n --nfroot   Specifies the nfcapd files root directory
    -d --dbroot   Specifies the database root directory
    -x --execute  Specifies the local indexer program

DESCRIPTION

In pull mode nfdump-replicator put the recently transferred file in a queue
called toindex. This queue is then fetched by kindexer-helper and the recently
fetched file is indexed.

FILE NAMING SCHEME

The queue toindex contains relative nfdump filenames such as
nfcapd.201201240002. This filename is dissected as follows:
2012 -> year
01   -> month
24   -> day
00   -> hour
02   -> minute

It is assumed that the nfcapd file was transferred to
/<nfroot>/<year>/<month>/<day>.

The index is created at the location /<dbroot>/<year>/<month>/<day>.kch

AUTHOR
    Gerard Wagener

LICENSE
    GPLv3

"""
    sys.exit(exitcode)

def dbg(msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    sys.stderr.write('[DBG ' + ts+'] '+ msg + ' \n' )


def err(msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    sys.stderr.write('[ERR '+ ts+'] ' + msg + '\n' )

def get_next_file(r):
    filename = r.lpop("toindex")
    if filename!=None:
        filename= filename.replace('\n','')
        filename = os.path.basename(filename)
    return filename

def daemon(nfroot, dbroot, prg, pidfile):
    while True:
        dojob(nfroot, dbroot, prg, pidfile)

def get_absolute_file(nfroot,filename):
    f = filename
    filename = filename.replace('nfcapd.','')
    year = filename[0:4]
    month = filename[4:6]
    day = filename[6:8]
    filename = f
    g = nfroot + os.sep + year + os.sep + month + os.sep + day + os.sep \
               + filename

    if os.path.exists(g) == False:
        err('Could not find nfcapd file ' + g)
        return None
    return g

def get_database_file(dbroot,filename):
    filename = filename.replace('nfcapd.','')
    year = filename[0:4]
    month = filename[4:6]
    day = filename[6:8]
    g = dbroot + os.sep + year
    #Create the directory structure if it does not exist
    if os.path.isdir(g) == False:
        os.mkdir(g)
    g = g + os.sep + month
    if os.path.isdir(g) == False:
        os.mkdir(g)

    g =  g + os.sep + day +".kch"
    return g


def dojob(nfroot, dbroot, prg, pidfile):
    r = redis.Redis()
    f = get_next_file(r)
    if f == None:
        dbg("No filename was available")
        time.sleep(10)
    else:
        dbg("Got file "+f)
        afile = get_absolute_file(nfroot,f)
        if afile != None:
            dbg("nfcapd file to index = "+afile + "\n")
            adb = get_database_file(dbroot,f)
            dbg("Database selected = "+adb +"\n")
            cmd = prg + " -r " + afile + " -p " + pidfile + " -d "+ adb
            dbg("Executing " +cmd)
            r = os.system(cmd)
            dbg("knfreader returned " + str(r)+"\n")
            if r != 0:
                err("Bad exit code was returned")
                sys.exit(1)

try:
    nfroot=None
    dbroot=None
    prg="knfreader"
    pidfile="/tmp/knfreader.pid"

    opts, args = getopt.getopt(sys.argv[1:], "hn:d:x:",['help=','nfroot=', \
                                             'dbroot=','execute='])
    for o, a in opts:
        if o == "-h" or o == '--help':
            usage(0)
        elif o == "-n" or o == '--nfroot':
            nfroot = a
        elif o == '-d' or o == '--dbroot':
            dbroot = a
        elif o =='-x' or o == '--execute':
            prg = a
        else:
            sys.stderr.write("Invalid command line option\n")
            usage(1)

    if nfroot == None:
        sys.stderr.write('No netflow root directory was specified\n')
        sys.exit(1)

    if dbroot == None:
        sys.stderr.write('No database root directory was specified\n')
        sys.exit(1)

    if os.path.isdir(nfroot)== False:
        sys.stderr.write('Nfroot='+nfroot+' does not exist\n')
        sys.exit(1)

    if os.path.isdir(dbroot) == False:
        sys.stderr.write('Dbroot='+dbroot+' does not exist\n')
        sys.exit(1)


    daemon(nfroot, dbroot, prg, pidfile)
except getopt.GetoptError, err:
    sys.stderr.write(str(err)+'\n')
    usage(1)
except KeyboardInterrupt,e:
    sys.stderr.write('User stopped daemon\n')
    sys.exit(1)
