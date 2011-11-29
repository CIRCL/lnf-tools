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


#REDIS_STRUCTURE
#
#The bot writes an IP address in dotted notaion (i.e. 10.0.0.1 or 01:dead:beef::1)
#
#Protocol between a bot and the kindexer process
#
#1 BOT>  GET ticket    (uuid is a queue containing a fixed number of UUIDS
#2 BOT>  SET br:uid    format: <FORMAT>
#2 KL>   SET bs:uid <STATUS> (i.e. PENDING)
#3 BOT>  GET bs:uid (polls) (i.e. PROCESSING)
#4 KL>   RPUSH bc:uuid record 1
#5 KL>   RPUSH bc:uuid record 2
#6 KL>   RPUSH bc:uuid record N
#7 KL>   SET bs:uid <STATUS>
#8 BOT>  GET bs:uid <STATUS> (i.e. COMPLETED)
#
#KL does the cleanup
#
#NOTATION
#
#bc: bot content
#bs: bot status
#br: bot request
#
#
#STATUS
#
#- PENDING
#- PROCESSING:nn%
#- COMPLETED
#- TRUNCATED
#in the queue denoted botorders.
#
#The klookup process polls these events and returns an list
#
#PUBLIC EXPOSED FUNCTIONS
#query(pcap_filter, format, [timestamp])

#TODO sort list the most recent first in case of truncated
#TODO test timeout of nfdump -> endless loop
#TODO check validity of tickets
import redis
import kindcommon
import ConfigParser
import uuid
import time
import klookup
import os
import shlex
import subprocess
import signal
import unittest
import sys
import getopt

class KlookupException(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return self.value

class KlookupIPC(object):

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    STARTED = "STARTED"
    TRUNCATED = "TRUNCATED"
    INVALID_FORMAT = "INVALID_FORMAT"
    NFDUMP_FAILURE = "NFDUMP_FAILURE"
    INTERRUPTED_JOB = "INTERRUPTED_JOB"
    COMPLETED = "COMPLETED"

    def __init__(self, configFile):
        self.configFile  = configFile
        self.config  = ConfigParser.ConfigParser()
        self.config.readfp(open(configFile))
        self.kco = kindcommon.KindCommon(self.config)
        self.maxSlots = int(self.config.get('daemon', 'maxSlots'))
        #Connect to redis
        redishost = self.config.get('redis','host')
        redisport = int(self.config.get('redis', 'port'))
        self.rd = redis.Redis(redishost, redisport)
        self.rd.select(int(self.config.get('daemon','dbnum')))
        self.sleeptime = int(self.config.get('daemon','sleeptime'))
        self.klu = klookup.Klookup(configFile)
        self.klu.load()
        self.maxlines = int(self.config.get('daemon', 'maxlines'))
        self.expire = int(self.config.get('daemon','expire'))


        self.prg = self.config.get("nfdump","prg")
        self.prgargs = self.config.get("nfdump", "args")
        self.dbdir = self.config.get('indexer','dbdir')

        self.linecounter = 0

    def create_ticket(self):
        u = uuid.uuid4()
        self.kco.dbg("Created ticket "+str(u))
        self.rd.rpush("tickets",str(u))

    def get_job_num(self):
        k = len(self.rd.keys('bs:*'))
        self.kco.dbg('Currently there are '+ str(k) + ' jobs')
        return k

    def update_availability_slots(self):
        #Get the number of available slots
        u = self.rd.llen("tickets")
        self.kco.dbg("Number of available tickets "+str(u))
        k = self.get_job_num()
        r =  self.maxSlots - u - k
        if r<=0:
            self.kco.dbg('No jobs such be created k='+str(k))
            return
        self.kco.dbg("Going to add " + str(r) + " tickets")
        #Fill the remaining slots
        for i in xrange(0,r):
            self.create_ticket()

    def check_style(self, style):
        #Valid style list
        styles = ['print_relative', 'print_absolute', 'print_full']
        if style in styles:
            return True
        # By default an error is assumed
        return False


    def update_status(self, uuid, status):
        if uuid == None:
            return None
        self.rd.set("bs:" + uuid, status)
        self.rd.expire("bs:" + uuid, self.expire)

    def get_status(self,uuid):
        a = 'bs:'+uuid
        return self.rd.get(a)


    def list_jobs(self):
        jobs = dict()
        #keys does return an empty array in case there are no keys
        for i in self.rd.keys('bs:*'):
            state = self.rd.get(i)
            i = i.replace('bs:', '')
            jobs[i] = state
        return jobs


    #Set a job to query data
    #TODO implement start date
    #date format YYYY-mm-dd
    def query(self, pcapfilter, style, startDate=None):
        uuid = None
        if self.check_style(style) == False:
            raise KlookupException("Wrong format for the data style")

        if self.kco.isValidFilter(pcapfilter)==False:
            raise KlookupException("Invlid filter")
        ipaddresses = self.kco.get_ipaddress_from_filter(pcapfilter)
        x = self.rd.lpop("tickets")
        if x ==None:
            self.kco.dbg('No free ticket is available')
            return None
        self.kco.dbg("Got ticket uuid: "+x)
        #Create a request for the daemon
        a = '['+ ','.join(ipaddresses) + ']'
        self.rd.rpush("btoprocess","br:" +x+ "+"+ a + "+"+ pcapfilter+ "+"+ style)
        #Update status to PENDING
        self.update_status(x,KlookupIPC.PENDING)
        return x

    def parse_job(self, jobstr):
        try:
            if jobstr == None:
                raise KlookupException("Empty job description")

            t = jobstr.split('+')
            #Expects something like ['br:4a1d5124-6867-474e-9494-98edaecc5e07'+'[10.0.0.1]', 'print_relative']
            #Parse uuid
            if t[0].startswith('br:') == False:
                raise KlookupException("Invalid job string " + jobstr)
            a = t[0].split(':')
            uuid = a[1]
            #Parse IP address
            addrraw = t[1]
            addrraw = addrraw.replace('[','')
            addrraw = addrraw.replace(']','')
            addr = addrraw.split(',')
            #Go through and copy valid addresses
            addrv = []
            for a in addr:
                if self.kco.check_ip_v4_address(a) == True:
                    self.kco.dbg("Found IPv4 address "+a)
                    addrv.append(a)

                if self.kco.check_ipv_6_address(a) == True:
                    self.kco.dbg("Found IPv6 address " +a)
                    addrv.append(a)

            if len(addrv) == 0:
                self.kco.dbg('No valid IP address found in the filter, raise exception ')
                raise KlookupException("No address found in filter")
            #Get pcap filter
            if self.kco.check_pcap_alph(t[2]) == True:
                pcap_filter=t[2]

            if self.check_style(t[3]):
                style = t[3]

            else:
                raise KlookupException("Invalid style " + t[3])
            return [uuid, addrv, pcap_filter, style]
        except IndexError,e:
            self.kco.dbg("Index error in parse_job "+str(e))
            raise KlookupException("Buggy job description "+jobstr)

    def store_file_array(self,files,uuid, flg):
        i = 0
        qname='bc:' + uuid
        for file in files:
            i = i + 1
            if i > self.maxlines:
                self.kco.dbg('Maximal number of lines for the result queue is reached. The result is truncated.')
                self.rd.expire(qname,self.expire)
                return KlookupIPC.TRUNCATED
            if flg == True:
                self.rd.lpush(qname, os.path.basename(file))
            else:
                self.rd.lpush(qname, file)
        self.rd.expire(qname,self.expire)
        return KlookupIPC.COMPLETED

    #Seg fault is tested
    def popen_to_redis(self, cmd, queue):
        try:
            self.kco.dbg("Executing " + str(cmd))
            process = subprocess.Popen(cmd, shell=False,stdout=subprocess.PIPE,stderr=None)
            self.kco.dbg('The nfdump process got the PID ' + str(process.pid))
            for line in process.stdout:
                self.linecounter = self.linecounter + 1
                line = line.replace('\n', '')
                if self.linecounter > self.maxlines:
                    self.kco.dbg('Max lines exeeded, stop nfdump')
                    process.send_signal(signal.SIGTERM)
                    return KlookupIPC.TRUNCATED
                #Store the output of nfdump in the redis
                self.rd.rpush(queue, line)
            process.poll()
            self.kco.dbg("nfdump exit code "+str(process.returncode))
            if process.returncode != 0:
                return KlookupIPC.NFDUMP_FAILURE
            #Assume that the job was successfull
            return KlookupIPC.COMPLETED
        except OSError,e: #tested
            self.kco.dbg("OSError for nfdump "+str(e))
            return KlookupIPC.NFDUMP_FAILURE
        except ValueError,w: #tested
            self.kco.dbg("ValueError "+str(w))
            return KlookupIPC.NFDUMP_FAILURE
        #Default should not be executed
        return KlookupIPC.NFDUMP_FAILURE

    def update_progress_status(self, uuid, cnt, ndb):
        self.kco.dbg('There are ' + str(ndb) + ' databases to process')
        progress = int(cnt / ndb * 100.0)
        self.kco.dbg('Progress value '+ str(progress))
        self.rd.set('bs:'+uuid, KlookupIPC.RUNNING + ':' + str(progress))


    def getfull_flowsDup(self, ipaddress, uuid, pcap_filter):
        databases = self.klu.open_databases() #TODO update this function to get a sorted list and according to a timestamp
        ndb = len(databases)
        ky = self.kco.build_key(ipaddress)
        i = 0.0
        status = KlookupIPC.TRUNCATED
        for db in databases:
            i = i +1
            self.update_progress_status(uuid,i, ndb)
            y=db.get(ky)
            if y != None:
                indexes =  self.kco.parse_index_value(y)
                for i in indexes:
                    fn=self.klu.get_filename(db,i)
                    afn  = self.klu.probe_file(fn)
                    cmd = []
                    cmd.append( self.prg )
                    #Adds the static arguments
                    #FIXME Dirty hack for fixing the invalid argument bug
                    self.prgargs =self.prgargs.replace(' ','')
                    cmd.append(self.prgargs)
                    cmd.append("-r"  + afn)
                    cmd.append(pcap_filter)
                    queue = "bc:" + uuid
                    status = self.popen_to_redis(cmd,queue)
                    #The results expire whatever the user does
                    self.rd.expire(queue,self.expire)
                    if status == KlookupIPC.TRUNCATED:
                        self.kco.dbg("The result queue in redis is already full do not go through the other databases")
                        return KlookupIPC.TRUNCATED
        return status

    def dispatch_format(self, files, addr, uuid, pcap_filter, style):
        #Counter is gloabal for this particular instance spawning over all the files
        self.linecounter = 0
        if style.startswith('print_relative'):
            self.kco.dbg('Store relative filenames containing the ip address ' + addr)
            return self.store_file_array(files,uuid, True)

        if style.startswith('print_absolute'):
            self.kco.dbg('Store absolute filenames containing the ip address '+ addr)
            return self.store_file_array(files,uuid, False)

        if style.startswith('print_full'):
            self.kco.dbg('Store full netflow records related to the ip address ' + addr)
            return self.getfull_flowsDup(addr, uuid, pcap_filter)

    def do_job(self, uuid,addr,pcap_filter, style):
        self.update_status(uuid,KlookupIPC.STARTED)
        startdate = time.time()
        self.kco.dbg("Processing Job "+  uuid)
        #FIXME Take only the first IP address the OR clause of nfdump does not work yet
        self.klu.ipaddress = addr[0]
        files = self.klu.get_filenames()
        enddate = time.time()
        d = enddate - startdate
        self.kco.dbg("Processing time " + str(d))

        status = self.dispatch_format(files,addr[0], uuid, pcap_filter, style)
        self.kco.dbg("The job returned status " + status)
        self.update_status(uuid, status)


    def daemon_run(self):
        self.kco.dbg("Start to process btoprocess queue")
        uuid = None
        job = None
        try:
            while True:
                job = self.rd.lpop("btoprocess")
                if job!= None:
                    self.kco.dbg("Got Job "+job)
                    try:
                        [uuid, [addr], pcap_filter, style] = self.parse_job(job)
                        self.do_job(uuid,[addr], pcap_filter, style)
                    except KlookupException,ke:
                        self.kco.dbg('Job Error '+str(ke))
                        #There was an invalid format in the database
                        self.update_status(uuid,KlookupIPC.INVALID_FORMAT) #Tested
                else:
                    job = None
                    self.kco.dbg("There is time to do some cleanup")
                    self.cleanup_old_jobs()
                    self.kco.dbg("There is no Job go to sleep") #Tested
                    time.sleep(self.sleeptime)
        except KeyboardInterrupt,e: #tested this routine
            self.kco.dbg('User termination request')
            if job != None:
                self.kco.dbg("Push back the started job in the processing queue")
                self.rd.lpush("btoprocess",job)
                [uuid, [addr], style] = self.parse_job(job)
                self.update_status(uuid, KlookupIPC.INTERRUPTED_JOB) #tested
                #TODO Check the state of a running nfdump process
            else:
                self.kco.dbg('It seems that there was no active job, so no push back') #tested
        except redis.exceptions.ConnectionError,e:
            self.kco.dbg("There was a redis error  and without redis I cannot do something usefull abort")
            #FIXME Check the state of a running nfdump process
            sys.exit(1)

    def get_query_result(self, uuid):
        line="a"
        buf=[]
        #TODO raise an exception if the results are queried for a pending or
        #running, started  job
        while line != None:
            line = self.rd.lpop('bc:'+uuid)
            if line != None:
                buf.append(line)
        return buf

        #The daemon checks  for empty bc keys llen = 0. If such a queue is
        #observed it knows that the queue is empty
        #If the result is fetched a new ticket is created. If user does not
        #fetch the results with a given timeframe the result is deleted
        #If the queues are full no new requests are done


    def decompose_status(self, qname):
        qname = qname.replace('bs:','')
        return qname

    def cleanup_old_jobs(self):
        #FIXME keys is a time consumming operation. It is assumed that only a few data is there
        #This method can through an ValueError when llen does not return a string
        for r in self.rd.keys("bs*"):
            #self.kco.dbg('Checking the status '+r)
            uuid = self.decompose_status(r)
            n = int(self.rd.llen('bc:'+uuid))
            if n == 0:
                self.kco.dbg("The queue " + r + "looks empty, remove the related entries")
                #Remove the status. Even when there is a buggy entry i.e. bs:foobar then this
                #entry is removed
                k = "bs:"+uuid
                status = self.rd.get(k)
                self.kco.dbg('The corresponding status is ' + status)
                if status == None or status == KlookupIPC.TRUNCATED or status == KlookupIPC.COMPLETED:
                    if self.rd.delete("bs:"+uuid)==True:  #tested
                        self.kco.dbg("Deleted entry "+ k)
                    #Create new tickets  such that we do not run out of tickets
                    self.create_ticket()
                else:
                    self.kco.dbg('Do not remove the entry it might be usefull')
                #TODO remove the corresponding ticket in the non existant ticket set
                #to validate the correct tickets

class TestDaemon(unittest.TestCase):
    def testParsers(self):
        ki = KlookupIPC('kindexer.cfg')
        [uuid,addrlst, pcapfilter, style] =  ki.parse_job("br:208a7374-2703-42a1-bfa0-03eb9e340cb9+[10.0.0.1]+ip 10.0.0.1 and port 80+print_full")
        self.assertEqual(uuid,"208a7374-2703-42a1-bfa0-03eb9e340cb9")
        self.assertEqual(pcapfilter, "ip 10.0.0.1 and port 80")
        self.assertEqual(style,'print_full')
        self.assertEqual(addrlst[0],'10.0.0.1')

        self.assertRaises(KlookupException, ki.parse_job, "br::208a7374-2703-42a1-bfa0-03eb9e340cb9")
        self.assertRaises(KlookupException, ki.parse_job, None)
        self.assertRaises(KlookupException, ki.parse_job, "br:208a7374-2703-42a1-bfa0-03eb9e340cb9+[10.a.0.1]+print_full")

        [uuid,addrlst, pcapfilter, style] =  ki.parse_job("br:208a7374-2703-42a1-bfa0-03eb9e340cb9+[dead::beef]+ip dead::beef+print_full")
        self.assertEqual(addrlst[0], 'dead::beef')
        self.assertEqual(pcapfilter, 'ip dead::beef')
        self.assertRaises(KlookupException, ki.parse_job, "br:208a7374-2703-42a1-bfa0-03eb9e340cb9+[dead::bzeef]+ip dead::bzeef+print_full")
        self.assertRaises(KlookupException, ki.parse_job,  "br:208a7374-2703-42a1-bfa0-03eb9e340cb9+[dead::beef]+ip dead::beef+foobar")

if __name__ == '__main__':
    #unittest.main()
    #sys.exit(0)

    def usage(exitcode):
        print """
klookupd - A daemon to coordinate netflow lookups

USAGE

    klookupd [-h] -c config file

OPTIONS
    -h Shows this screen
    -c Specify a kindexer.cfg config file

DESCRIPTION

Klookupd is meant to be started in a GNU screen session. Klookupd handles
requests for IP lookups generated by clients. Klookupd uses redis as
backend. A client can get a ticket corresponding to an identifier.
Klookupd processes the queue of tickets and performs the lookups.
The client can poll the state of its query.

AUTHOR
    Gerard Wagener

LICENSE
    GPLv3
"""
        sys.exit(exitcode)

    try:
        configFile = None
        opts,args = getopt.getopt(sys.argv[1:], 'hc:')
        for o,a in opts:
            if o == '-h':
                usage(0)
            elif o == '-c':
                configFile = a

        if configFile == None:
            sys.stderr.write('A config file must be specified\n')
            usage(1)

        if os.path.exists(configFile) == False:
            sys.stderr.write('The config file ' +  configFile  + ' was not found\n')
            sys.exit(1)
        ki = KlookupIPC(configFile)
        ki.update_availability_slots()
        ki.daemon_run()
    except getopt.GetoptError, err:
        sys.stderr.write(str(err)+"\n")
        sys.exit(1)
    except ConfigParser.NoOptionError,e:
        sys.stderr.write('Invalid configuration file '+ str(e) +'\n')
        sys.exit(1)
    except ConfigParser.MissingSectionHeaderError,e:
        sys.stderr.write('Invalid configuration file '+ str(e) +'\n')
        sys.exit(1)
    except ConfigParser.NoSectionError,e:
        sys.stderr.write('Invalid configuration file '+ str(e) +'\n')
        sys.exit(1)

