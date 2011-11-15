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



import ConfigParser
import sys
import os
import redis
import time
import unittest

class KindCommon(object):

    def __init__(self,configObj):
        self.config = configObj
        #A status of False means that the configuration file is incomplete
        #A status of True means that the configuration file is complete
        self.status = False
        self.error  = None
        #Check mandatory parameters and update status
        self.checkParameters()
        if self.status:
            #Parameters from the config file
            self.dbdir = self.config.get('indexer','dbdir')
            self.dbdir = self.config.get('indexer','tmpdir')
            self.indexer = self.config.get('indexer','name')

    def checkParameters(self):
        #Access all the needed configuration fields and check for exceptions
        try:
            p = self.config.get("indexer","dbdir")
            #Check if mandatory directories exist
            if os.path.exists(p)==False:
                raise IOError("dbdir="+ p +" does not exists ")
            if os.path.exists(self.config.get("indexer", "tmpdir")) == False:
                raise IOError("tmpfs mount point does not exists")
            self.config.get("indexer","name")
            int(self.config.get('indexer','redis_database'))
            #All the parameters are there
            self.status = True
        except ConfigParser.NoOptionError,e:
            self.status = False
            self.error = str(e)
        except ValueError,v:
            self.status = False
            self.error = str(v)
        except IOError,w:
            self.status = False
            self.error = str(w)

    def dbg(self, msg):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        sys.stdout.write("["+ts+"] "+msg + '\n')
        sys.stdout.flush()

    #Returns the directories containing the files created by nfcapd or that
    #were transferred via other channels
    def read_flow_dirs(self):
        flowdirs=[]
        i=0
        try:
            while True:
                i=i+1
                k = 'root_' + str(i)
                dr = self.config.get('flowdirs',k)
                if dr.endswith('/'):
                    dr = dr[0:-1]
                if (os.path.isdir(dr) == False):
                    self.dbg('Flow entry ' + dr  +' is not a directory')
                else:
                    flowdirs.append(dr)
        except ConfigParser.NoOptionError,e:
            pass

        return flowdirs


    #From a nfcapdfile name strip the hours and minutes and just keep the
    #year, month and day as key name for the queue
    def get_queue_name(self,nffile):
        f = os.path.basename(nffile)
        f = f[:-4]
        f = f.replace('nfcapd.','')
        k = "dq:"+f
        return k

    def check_filename(self,filename):
        if (len(filename) != 12):
            self.dbg('Invalid file name length for '+ filename)
            return None
        try:
            int(filename)
            return filename
        except ValueError,e:
            self.dbg('Invalid filename '+filename)
            return None


    def get_databasefile(self,filename):
        if filename == None:
            return None
        f = os.path.basename(filename)
        f = f.replace('nfcapd.','')
        if self.check_filename(f) == None:
            return None

        year = f[0:4]
        month = f[4:6]
        day = f[6:8]
        hour = f[8:10]
        mn = f[10:12]
        dbfile=self.config.get('indexer','dbdir') + os.sep + year + \
                          os.sep + month + os.sep+day+".kch"

        #Check if the directory structure exists
        #If it does not exist create it, the db files are not created because
        #kyoto cabinet does not like empty files
        p = self.config.get('indexer','dbdir')+os.sep + year
        if (os.path.exists(p) == False):
            os.mkdir(p)
        p = self.config.get('indexer','dbdir') + os.sep + year + os.sep + month
        if (os.path.exists(p) == False):
            os.mkdir(p)
        return dbfile

    #This routine returns almost the same path except that the filename is
    #a hidden file. If concurrent daemons serach the databases only
    #complete filenames are present assuming that the move operation within
    #a disk is attomic
    def get_temp_databasefile(self,filename):
        if filename == None:
            return None
        f = os.path.basename(filename)
        f = f.replace('nfcapd.','')
        if self.check_filename(f) == None:
            return None

        year = f[0:4]
        month = f[4:6]
        day = f[6:8]
        hour = f[8:10]
        mn = f[10:12]
        dbfile=self.config.get('indexer','dbdir') + os.sep + year + \
                          os.sep + month + os.sep+"."+day+".kch"

        #Check if the directory structure exists
        #If it does not exist create it, the db files are not created because
        #kyoto cabinet does not like empty files
        p = self.config.get('indexer','dbdir')+os.sep + year
        if (os.path.exists(p) == False):
            os.mkdir(p)
        p = self.config.get('indexer','dbdir') + os.sep + year + os.sep + month
        if (os.path.exists(p) == False):
            os.mkdir(p)
        return dbfile

    #Values are stored as a string. This string is a comma separated list
    #of indices. This list can have empty values, and duplicated values
    #because during the indexing no checks are done in order to reduce the
    #number of operations to the kyoto database.
    #Therefore, this routine undoes these artifacts
    #
    #Input a raw value string
    #Returns a clean list of values
    def parse_index_value(self, value):
        if (value == None):
            return []
        #Remove heading comma
        if value.startswith(','):
            value = value[1:]
        l = value.split(',')
        #Copy elements from the list to a dict too remove duplicates
        buf = dict()
        for i in l:
            try:
                buf[int(i)] = 1
            except ValueError,e:
                self.dbg('Could not parse ' + str(e) + ' skip it')
        k = buf.keys()
        k.sort()
        return k

    #Builds the key out of an IP address
    #Takes an IP address as input and builds a string
    #IPv4 address encoding n4:10.0.0.1
    #Ipv6 adress encoding n6:dead:beef::1
    def build_key(self, addr):
        if addr.find(':') != -1:
            return "n6:" + addr
        else:
            return "n4:" + addr

class TestKindCommon(unittest.TestCase):
    def test_all(self):
        filename="../t/kindexer/kindexer.cfg"
        f = open(filename,'r')
        config = ConfigParser.ConfigParser()
        config.readfp(f)
        f.close()
        kco = KindCommon(config)
        #Test constructor
        self.assertEqual(kco.status,True)
        #Test readflowdirs
        d = kco.read_flow_dirs()
        self.assertEqual(d[0], "../t/kindexer/flowdirs")
        self.assertEqual( kco.get_queue_name("../../nfcapd.201111081512"),
                         "dq:20111108")

        self.assertEqual(kco.get_databasefile("../../nfcapd.201111081512"),
        "../t/kindexer/databases/2011/11/08.kch")
        self.assertEqual(kco.get_databasefile('aaa'), None)
        self.assertEqual(kco.get_databasefile(None), None)

    def test_parsers(self):
        filename="../t/kindexer/kindexer.cfg"
        f = open(filename,'r')
        config = ConfigParser.ConfigParser()
        config.readfp(f)
        f.close()
        kco = KindCommon(config)
        t=kco.parse_index_value(',1,2,3')
        self.assertEqual(t,[1,2,3])

        #Test None objs
        t = kco.parse_index_value(None)
        self.assertEqual(t,[])

        t = kco.parse_index_value("1,2")
        self.assertEqual(t,[1,2])

        t = kco.parse_index_value('1,')
        self.assertEqual(t,[1])

        t = kco.parse_index_value('1,a,2')
        self.assertEqual(t,[1,2])

        t = kco.build_key("10.0.0.1")
        self.assertEqual(t,"n4:10.0.0.1")

        t = kco.build_key("dead:beef::23")
        self.assertEqual(t, "n6:dead:beef::23")

if __name__=='__main__':
    unittest.main()
