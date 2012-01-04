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
import subprocess

import socket
import fcntl
import struct


ipaddress = None

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

    PUSH MODE OPTIONS

    -c Specify the configuration file. Default filename /etc/nfdump-replicator

    PULL MODE OPTIONS

    -f Query the full path of an nfcapd file. The results is displayed on
       stdout and 0 is returned as exit code on stdout

    -n Pop the toprocess queue and display the result on stdout

    -p Push back an nfcapd file in the toprocess queue  in case of
       transfer errors

    -i Specify the SSH identity filename used for the transfer
    -u Specify the SSH login name used for the transfer


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


def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

def dbg(msg):
    sys.stderr.write('[DBG '+str(ipaddress)+'] '+ msg + ' \n' )


def err(msg):
    sys.stderr.write('[ERR '+str(ipaddress)+'] ' + msg + '\n' )

def getfilename(filename, flowdirs,re):
    filename=filename.replace('./','')
    for d in flowdirs:
        f  = d  + '/' + filename
        if os.path.exists(f) == True:
            dbg('Found file at ' + f)
            return f
    #Serious error, filename not found, abort
    syslog.syslog('Could not find file (' + filename + ')')
    err('Could not find file (' + filename + ')')
    err('Looked up in '+str(flowdirs))
    err('Pushback into queue ' +  filename)
    #Check if in PULL or PUSH mode
    if (re == None):
        push_back(filename)
    else:
        re.lpush("toprocess",filename)
    #A different exit code is returned than the default error code 1
    sys.exit(2)


def get_next_file():
    cmd = ['ssh',target_address,'redis-cli' ,'lpop','toprocess']
    process = subprocess.Popen(cmd,shell=False,stdout=subprocess.PIPE,
                               stderr=None)
    buf = []
    for f in process.stdout:
        buf.append(f)
    process.wait()
    f = buf[0]
    if f == '(nil)\n':
        dbg('No file name is available' )
        f=None

    dbg('Subprocess exit code ' + str(process.returncode))
    if process.returncode != 0:
        err('Acquisition of next file failed ')
        #Here it is not sure if the item was poped or not
        #Normally not, but it depends on redis-cli
        sys.exit(1)
    dbg('get next file returned ' +str(f))
    return f

def transfer_file(a, r):
    try:
        cmd="scp -o ConnectTimeout=" + str(connecttimeout) +\
        " -l " + str(bwlimit) +" " + a + " " + target_address +\
         ":"+target_dir
        dbg('cmd '+cmd)
        ret = os.system(cmd)
        if (ret != 0):
            raise OSError('Command failed, bad exit code')
        r.rpush("todelete",a)
    except OSError,e:
        sys.stderr.write('OS error'+str(e)+'\n')
        f = os.path.basename(a)
        dbg('Push back into toprocess queue ' + f + '\n')
        r.lpush("toprocess",f)
        sys.stderr.write('Stop transfer process\n')
        sys.exit(1)

def transfer_remote_file(a):
    tf = target_dir + os.sep + os.path.basename(a)
    try:
        if os.path.exists(tf):
            err("The file " + tf + " already exists on the target system, shutdown")
            push_back(os.path.basename(a))
            sys.exit(1)
        cmd = 'scp -o ConnectTimeout=' + str(connecttimeout) +\
              ' -l ' +str(bwlimit) + ' ' + target_address \
               + ':'+a + ' ' + target_dir
        dbg("cmd = "+cmd)
        #Spawn a new shell to catch different exit code if CTRL+C
        #is hit
        r= os.system(cmd)
        if (r != 0):
            raise OSError('Command failed, bad exit code')

        #Put the file in the delete queue
        enqueue_todelete(os.path.basename(a))

    except OSError,e:
        sys.stderr.write('OS error'+str(e)+'\n')
        push_back(os.path.basename(a))
        #Remove partial file
        dbg("Removing partial written file "+tf)
        os.remove(tf)
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

def push_back(filename):
    try:
        cmd = ['ssh',target_address, 'redis-cli','lpush','toprocess',filename]
        dbg('Executing ' + str(cmd))
        process = subprocess.Popen(cmd,shell=False,stdout=subprocess.PIPE, \
                                   stderr=None)
        #Consume and discard stdout of pushback
        for i in process.stdout:
            pass
        process.wait()

        if (process.returncode !=0):
            raise OSError('Bad exitcode')
    except OSError,e:
        err('Pushback failed, the filename '+filename + ' must be processed\
manually err='+str(e))
        sys.exit(1)

def enqueue_todelete(filename):
    try:
        cmd = ['ssh',target_address, 'redis-cli','lpush','todelete',filename]
        dbg('Executing ' + str(cmd))
        process = subprocess.Popen(cmd,shell=False,stdout=subprocess.PIPE, \
                                   stderr=None)
        #Consume and discard stdout of pushback
        for i in process.stdout:
            pass
        process.wait()

        if (process.returncode !=0):
            raise OSError('Bad exitcode')
    except OSError,e:
        err('Could not put file ' + filename +' in delete queue')
        sys.exit(1)



def get_remote_file(name):
    try:
        cmd = ['ssh', target_address,'nfdump-replicator.py','-f',name]
        dbg('Executing ' + str(cmd))
        process = subprocess.Popen(cmd,shell=False,stdout=subprocess.PIPE,
                                   stderr=None)
        buf = []
        for f in process.stdout:
            buf.append(f)
        process.wait()
        if process.returncode != 0 and process.returncode != 2:
            raise OSError('Bad exit code')
        if len(buf) == 0:
            return None
        else:
            return buf[0].replace('\n','')
    except OSError,e:
        err('get_remote_file failed ' +str(e)  )
        sys.exit(1)

def push_mode(config):
    redis_address  = config.get('redis','address')
    redis_port     = config.getint('redis','port')
    target_address = config.get('target','address')
    target_port    = config.get('target','port')
    bwlimit        = config.getint('target','bwlimit')
    target_dir     = config.get('target', 'directory')
    pollinterval   = config.getint("redis","pollinterval")
    flowdirs       = read_flow_dirs(config)
    connecttimeout = config.get('target', 'connecttimeout')

    #Connect to redis
    r = redis.Redis(redis_address, redis_port)
    while True:
        #Poll queue
        filename = r.lpop("toprocess")
        if (filename == None):
            dbg("No filename is ready go to sleep for "+\
                  str(pollinterval) +" seconds")
            time.sleep(pollinterval)
            dbg("Wake up")
        else:
            dbg("Got filename: "+filename)
            a = getfilename(filename, flowdirs,r)
            dbg("Absolue filename: "+a)
            transfer_file(a, r)

try:
    opts, args = getopt.getopt(sys.argv[1:], "hc:f:")
except getopt.GetoptError, err:
    sys.stderr.write(str(err)+'\n')
    usage(1)

def pull_mode():
    while True:
        filename = get_next_file()
        if (filename == None):
            dbg("<Pull> No filename is ready go to sleep for "+\
                  str(pollinterval) +" seconds")
            time.sleep(pollinterval)
            dbg("<Pull> Wake up")
        else:
            dbg("<Pull> Got filename: "+filename)
            afile = get_remote_file(filename)
            if afile == None:
                dbg("The file was not found, push it back and stop")
                push_back(filename)
                sys.exit(1)
            transfer_remote_file(afile)

queryFullPath = None
for o, a in opts:
    if o == "-h":
        usage(0)
    elif o == "-c":
        configfile = a
    elif o == '-f':
        queryFullPath = a
    else:
        sys.stderr.write("Invalid command line option\n")
        sys.exit(1)

ipaddress = get_ip_address("eth0")
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

    #Handle pull options server side
    if (queryFullPath):
        r = getfilename(queryFullPath, flowdirs,None)
        print r
        sys.stdout.flush()
        sys.exit(0)

    #push_mode(config)
    pull_mode()

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
