#!/usr/bin/python
#nfdump-tools - Inspecting the output of nfdump
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
#
# Daemon to start nfreader

import redis
import sys
import os
import ConfigParser
import time
import signal
from screenutils import list_screens, Screen;
from syslog import *

class RedixIndexerCore(object):
    def __init__(self, configFile='/etc/nfindexer.cfg'):
        self.configFile = configFile
        self.load_config()

    def dbg(self, msg):
        print "[DBG] ", msg

    def search_ridx_screen(self):
        for sc in list_screens():
            self.dbg("Found screen: "+ sc.name)
            if (sc.name == self.cfg_idx_scr_name):
                self.dbg("Indexer Screen found")
                return sc
        syslog("RedisIndexerScreen was not found")
        sys.exit(1)


    def exec_indexer(self):
        sc = self.search_ridx_screen()
        os.system("screen -r "+self.cfg_idx_scr_name + " -X screen top")

    def read_flow_dirs(self, config):
        self.cfg_flowdirs=[]
        i=0
        try:
            while True:
                i=i+1
                k = 'root_' + str(i)
                dr = config.get('flowdirs',k)
                if dr.endswith('/'):
                    dr = dr[0:-1]
                self.cfg_flowdirs.append(dr)
                if (os.path.isdir(dr) == False):
                    syslog('Flow entry ' + dr  +
                                     ' is not a directory')
                    sys.exit(1)

        except ConfigParser.NoOptionError,e:
            pass

    def load_config(self):
        try:
            self.load_config_int()
        except ConfigParser.NoOptionError,e:
            syslog('ConfigError: '+str(e))
            sys.exit(1)
        except ConfigParser.NoSectionError,f:
            syslog('ConfigError: '+str(f))
            sys.exit(1)
        except IOError,i:
            syslog('ConfigError: '+str(i))
            sys.exit(1)
        except ValueError,v:
            syslog('ConfigError: '+str(v))
            sys.exit(1)

    def load_config_int(self):
        config = ConfigParser.ConfigParser()
        config.readfp(open(self.configFile))
        self.cfg_redis_server = config.get('redis','server')
        self.cfg_redis_port = config.getint('redis','port')
        self.cfg_prg  = config.get('nfreader','prg')
        self.cfg_poll = config.getint('nfreader','pollinterval')
        if (os.path.exists(self.cfg_prg) == False):
            syslog('nfreader.prg does not exists ('+ self.cfg_prg + \
                             ')')
            sys.exit(1)

        if (os.access(self.cfg_prg,os.X_OK) == False):
            syslog('nfreader is not executable ('+self.cfg_prg + ')')
            sys.exit(1)
        self.cfg_timeout = config.getint('nfreader','timeout')

        self.cfg_idx_scr_name = config.get('nfreader','screenname')
        self.cfg_localcache = config.getint('nfreader','localcache')

        self.read_flow_dirs(config)


    #Sometimes files are distributed in different directories over the
    #file system. These directories have to be specified in the config
    #file and a lookup is done in each directory
    def getfilename(self,filename):
        for d in self.cfg_flowdirs:
            f  = d  + '/' + filename
            if (os.path.exists(f) == True):
                return f
        #Serious error, filename not found, abort
        syslog('Could not find file (' + filename + ')')
        sys.exit(1)

    def launch_nfreader(self, filename):
        cmd="screen -S " + self.cfg_idx_scr_name +  ' -X screen -t nfreader '
        cmd=cmd + self.cfg_prg + " -s " + self.cfg_redis_server  + " -p " +\
             str(self.cfg_redis_port) + " -r " + filename

        if (self.cfg_localcache == 0):
            cmd = cmd + " -c"
        #Launch the job in gnu screen
        self.dbg("Executing "+ cmd)
        os.system(cmd)

    def getjobstate(self, redis):
        pid =redis.get('nfpid')
        if (pid == None):
            return 0
        else:
            return int(pid)

    def polljob(self, redis):
        #The number of poll requests is computed by the timeout
        #If the job is not done it is killed
        n = self.cfg_timeout / self.cfg_poll
        self.dbg("Number of polls = "+ str(n))
        for i in range(0,n):
            self.dbg("Pull number "+str(i) + " go to sleep: "+str(self.cfg_poll))
            time.sleep(self.cfg_poll)
            self.dbg("Wake up")
            pid = self.getjobstate(redis)
            if (pid == 0):
                self.dbg("Job with PID is done")
                return True
        #The job is still running
        self.dbg("The job "+str(pid) + " is still running going to kill it")
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError,e:
            syslog(str(e))
        #Even if the job crashed and did not manage to remove the PID
        #key from redis it is removed by the daemon
        redis.delete("nfpid")
        syslog("Job with pid="+ str(pid) + " was killed and PID was removed")
        return False

    #There mightbe some jobs running that such be terminated aswell when the
    #daemon stops
    #FIXME common code with previous tested function
    def cleanup(self):
        pid=self.getjobstate(self.redis)
        if (pid > 0):
            syslog("There is a remaining job killing it "+str(pid))
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError,e:
            syslog(str(e))
        self.redis.delete("nfpid")
        syslog("Job with pid="+ str(pid) + " was killed and PID was removed during the cleanup")


    def run(self):
        r = redis.Redis()
        #Set redis as attribute such that it is accessible
        self.redis = r
        self.search_ridx_screen()
        while True:
            filename = r.lpop("toprocess")
            if (filename == None):
                self.dbg("No nfcapd file ready, go to sleep for "
                         +str(self.cfg_timeout) + " seconds")
                time.sleep(self.cfg_timeout)
            else:
                filename = os.path.basename(filename)
                f = self.getfilename(filename)
                self.dbg("Processing "+f)
                #Launch the job in non blocking mode
                self.launch_nfreader(f)
                self.polljob(r)

if __name__ == '__main__':
    # Set up log facility
    #FIXME Log level seems to not work in python wrapper?
    lg = openlog(sys.argv[0], LOG_PERROR | LOG_PID, LOG_DAEMON)
    syslog("Nfdump Indexer started")
    x=None
    try:
        x = RedixIndexerCore()
        x.run()
    except Exception,e:
        syslog(str(e))
    except KeyboardInterrupt,e:
        if (x != None):
            x.cleanup()
        syslog("Nfdump indexer was manually stopped")
exit(0)
