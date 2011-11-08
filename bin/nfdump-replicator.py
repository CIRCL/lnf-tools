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
import ConfigParser
import sys
import time
import os
import syslog

def usage(exitcode):
    print """nfdump-replicator

If nfcapd is configured to push the recent created file in a redis queue
denoted toprocess, then this program polls the filenames and transfers them
to another host via ssh. If the file transfer was successful then the filename
is put in another queue denoted todelete

If the transfer fails the file is pushed back to the toprocess queue and this
program stops

OPTIONS

    -h Displays this screen
    -c Specify the configuration file. Default filename /etc/nfdump-replicator


CONFIGURATION FILE

[redis]
address=127.0.0.1         #IP address where the Redis server is running
port=6379                 #The port where the Redis server is running
pollinterval=10           #The time elapsed until the the next poll is done

[target]
address=10.0.0.1          #The IP address where the netflow files are
                          #transferred
port=22                   #The port where the SSH server is running on the
                          #target host
bwlimit=512               #The bandwidth can be limited (i.e. 512 KB/s)
directory=/data/netflow   #The directory on the remote target where the files
                          #are copied too
connecttimeout=20         #Timeout for scp until it aborts the connection
                          #attempt

[flowdirs]                #The directories listed here contain netflow records
root_1=/data/netflow
root_2=/var/netflow


AUTHOR
Gerard Wagener

LICENSE
GPLv3
"""
    sys.exit(exitcode)

configfile="/etc/nfdump-replicator"

def getfilename(filename, flowdirs,re):
    for d in flowdirs:
        f  = d  + '/' + filename
        if (os.path.exists(f) == True):
            return f
        #Serious error, filename not found, abort
        syslog.syslog('Could not find file (' + filename + ')')
        print '[ERROR] Could not find file (' + filename + ')'
        print "[ERROR] Pushback into queue", filename
        re.lpush("toprocess",filename)
        sys.exit(1)


def transfer_file(a, re):
    try:
        cmd="scp -o ConnectTimeout=" + str(connecttimeout) +\
        " -l " + str(bwlimit) +" " + a + " " + target_address +\
         ":"+target_dir
        print "[DBG] cmd ",cmd;
        ret = os.system(cmd)
        if (ret != 0):
            raise OSError('Command failed, bad exit code')
        r.rpush("todelete",a)
    except OSError,e:
        sys.stderr.write('OS error'+str(e)+'\n')
        f = os.path.basename(a)
        print "[DBG] Push back into toprocess queue " + f
        r.lpush("toprocess",f)
        sys.stderr.write('Stop transfer process\n')
        sys.exit(1)

def read_flow_dirs(config):
    flowdirs=[]
    i=0
    try:
        while True:
            i=i+1
            k = 'root_' + str(i)
            dr = config.get('flowdirs',k)
            if dr.endswith('/'):
                dr = dr[0:-1]
            flowdirs.append(dr)
            if (os.path.isdir(dr) == False):
                syslog.syslog('Flow entry ' + dr  +' is not a directory')
                sys.exit(1)
    except ConfigParser.NoOptionError,e:
            pass

    return flowdirs

try:
    opts, args = getopt.getopt(sys.argv[1:], "hc:")
except getopt.GetoptError, err:
    sys.stderr.write(str(err)+'\n')
    usage(1)

for o, a in opts:
    if o == "-h":
        usage(0)
    elif o == "-c":
        configfile = a
    else:
        sys.stderr.write("Invalid command line option\n")
        sys.exit(1)

pollinterval = 10
#Load config file access all fields to test if they are set
try:
    config = ConfigParser.ConfigParser()
    config.readfp(open(configfile))
    redis_address  = config.get('redis','address')
    redis_port     = config.getint('redis','port')
    target_address = config.get('target','address')
    target_port    = config.get('target','port')
    bwlimit        = config.getint('target','bwlimit')
    target_dir     = config.get('target', 'directory')
    pollinterval   = config.getint("redis","pollinterval")
    flowdirs       = read_flow_dirs(config)
    connecttimeout = config.get('target', 'connecttimeout')
    #FIXME Does not work on other ports
    #Connect to redis

    r = redis.Redis(redis_address, redis_port)
    while True:
        #Poll queue
        filename = r.lpop("toprocess")
        if (filename == None):
            print "[DBG] No filename is ready go to sleep for "+\
                  str(pollinterval) +" seconds"
            time.sleep(pollinterval)
            print "[DBG] Wake up"
        else:
            print "[DBG] Got filename: ",filename
            a = getfilename(filename, flowdirs,r)
            print "[DBG] Absolue filename: ",a
            transfer_file(a, r)

except ConfigParser.NoOptionError,e:
    sys.stderr.write("Config Error: "+str(e) + '\n')
    sys.exit(1)
except ValueError,v:
    sys.stderr.write("Config Error: "+str(v) + '\n')
    sys.exit(1)
except IOError,w:
    sys.stderr.write("Could not load config file "+ str(w)+"\n")
    sys.exit(1)
except redis.exceptions.ConnectionError,e:
    sys.stderr.write("Could not access redis server " + str(e) + "\n")
    sys.exit(1)
except KeyboardInterrupt,e:
    sys.stderr.write('User stopped the process\n')
    sys.exit(1)
sys.exit(0)
