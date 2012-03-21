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
#
#TODO Add sorting option i.e. reverse sorting
#TODO implement pcap filter here aswell
#TODO There should not be any missing databases. Maybe the closed database could be searched
import os
import sys
from kyotocabinet import *
import getopt
import time
import kindcommon
import ConfigParser
import unittest
import pprint

class Klookup(object):

    def __init__(self,configFile=None):
        self.configFile = configFile
        self.ipaddress = None

    def  load(self):
        try:
            self.config = ConfigParser.ConfigParser()
            if (self.configFile == None):
                raise IOError('No config file was specified')
            self.config.readfp(open(self.configFile))
            self.kco = kindcommon.KindCommon(self.config)
            p = self.config.get("indexer","dbdir")
            #Check if mandatory directories exist
            if os.path.exists(p) == False:
                raise IOError("dbdir="+ p +" does not exists ")
            self.flowdirs  = self.kco.read_flow_dirs_struct()
        except ConfigParser.NoOptionError,e:
            sys.stderr.write("Config Error: "+str(e) + '\n')
            sys.exit(1)
        except ValueError,v:
            sys.stderr.write("Config Error: "+str(v) + '\n')
            sys.exit(1)
        except IOError,w:
            sys.stderr.write("Could not load config file "+ str(w)+"\n")
            sys.exit(1)

    def usage(self,exitcode):
        print """
Query an IP address in the collection of kyoto cabinet files

klookup [-h] -d database_directory -i IP address

OPTIONS
    -h Show this screen
    -i The IP adderss that is queries
    -c Specify the kindexer config file in order to find the absolute filenames
    -f FORMAT OPTION
    -l Loop. Klookup runs as a blocking process dedicated to run in a GNU screen
             on the system containing the databases. This process can then be queried
             via a bot for  instance an XMPP bot. The interaction is done
             via redis. (see REDIS_STRUCTURE)

The list of nfcapd files is returned corersponing to the queried IP address


FORMAT OPTIONS
    "print absolute"     Prints abolute filenames containing the IP address
    "print relative"     Print relative filenames
    check                Returns result as exit code
                            0 means that the IP addresses is known
                            1 means that the IP address is not known
    "full nfdump -r %f"  Does a full nfdump of the found occurences. After the
                         word full the nfdump tool with its argument needs to
                         be specified. %f is substituted by the filename
                         identified in the index

    "print full"         Executes nfdump on each nfcapd file. The nfdump program
                         can be specified in the config file using the prg key.
                         Generic arguments can be put with the key "args"

The default format is the format "print absolute". Note the format must be enclosed by
quotation marks.


"""
        sys.exit(exitcode)

    def get_file_position(self, files, date, default):
        if date == None:
            #No date was specified return default value
            return default
        if self.check_date_str(date) == False:
            self.kco.dbg('Invalid date string was provided '+ date + ' reset to None')
            return default
        date = date.replace('-','/')
        date = date + '.kch'
        self.kco.dbg('Converted date string: ' + date)
        #Go through all elements and search the date
        i = 0
        for f in files:
            if f == date:
                self.kco.dbg('Found date '+ date + 'at position '+ str(i))
                return i
            i = i + 1
        self.kco.dbg('The index of the file ' + date + 'was not found returning ' + str(default) )
        return default


    def check_date_str(self,datestr):
        try:
            (year, month, day)  = datestr.split('-')
            int(year)
            int(month)
            int(day)
            if len(year) != 4:
                return False
            if len(month) != 2:
                return False
            if len(day) != 2:
                return False

            #If still alive here it should be good
            return True
        except ValueError,e:
            self.kco.dbg('check_date_str value error '+ str(e))
            return False
        #This should never be executed
        return False

    #If date strings are not valid the entire database is selected
    def get_relevant_files(self, files,startdate, enddate):
        #Strip the root prefix
        dbdir = self.config.get('indexer','dbdir')
        if dbdir.endswith('/')==False:
            dbdir = dbdir + '/'
        sfiles = []
        for f in files:
            f = f.replace(dbdir,'')
            if f.startswith('/'):
                f = f[1:]
            sfiles.append(f)
        #The ascii sort should sort it accordingly time
        #The year is first hence the lowest year should be first
        #The month is next hence after the sorting of year the months
        #are sorted
        #idem for the days
        sfiles.sort()
        fl = len(sfiles)
        self.kco.dbg("Searching in " +str(sfiles))
        if fl == 0:
            return []
        startpos = self.get_file_position(sfiles, startdate, 0)
        endpos = self.get_file_position(sfiles, enddate, fl)
        self.kco.dbg('get_relevant_files: startdate ' + str(startdate))
        self.kco.dbg('get_relevant_files: enddate ' + str(enddate))
        self.kco.dbg('get_relevant_files: fl ' + str(fl) + '\n')
        self.kco.dbg('get_relevant_files: startpos=' +  str(startpos))
        self.kco.dbg('get_relevant_files: endpos=' +  str(endpos))
        #The : notation should not throw an exception
        stfiles = sfiles[startpos:endpos+1]
        self.kco.dbg("Reduced index set "+str(stfiles))
        #Add prefix to the files
        files= []
        for f in stfiles:
            #The slash has already be added to dbdir
            files.append(dbdir + f)
        return files

    def get_databases_list(self, startdate=None, enddate=None):
        self.kco.dbg("Started get_databases_list")
        d  = self.config.get('indexer','dbdir')
        files = []
        try:
            for yearstr in os.listdir(d):
                year = int(yearstr)
                for monthstr in os.listdir(d+os.sep+yearstr):
                    month = int(monthstr)
                    for daystr in os.listdir(d+os.sep+yearstr+os.sep+monthstr):
                        files.append(d + os.sep + yearstr + os.sep + monthstr+os.sep+daystr)

        except ConfigParser.NoOptionError,e:
            pass #FIXME Need to do additional stuff

        except ValueError,e:
            self.dbg("Expected numeric entry  "+str(e)+"\n")
        self.kco.dbg("Identified " +str(len(files)) + " kch files")

        rfiles = self.get_relevant_files(files, startdate, enddate)
        self.kco.dbg("End get_databases_list")
        return rfiles


    def open_databases(self, startdate=None,enddate=None):
        self.kco.dbg("Started open_databases")
        self.dbobjs = []
        for i in self.get_databases_list(startdate, enddate):
            db = DB()
            if not db.open(i, DB.OREADER ):
                print >>sys.stderr, "open error: " + str(db.error())
                sys.exit(1)
            self.dbobjs.append(db)
        self.kco.dbg("End open_databases")
        return self.dbobjs

    def probe_file(self,fn):
        for f in self.flowdirs:
            g = f + os.sep + fn
            if os.path.exists(g):
                return g
        return None

    def get_filename(self, db, idx):
        k = "d:"+str(idx)
        return db.get(k)



    #TODO Individual nfdump files must be sorted aswell
    #Otherwise the 5 minutes intervals do not match anymore
    def get_filenames(self,startdate, enddate):
        dbdir = self.config.get('indexer','dbdir')
        self.open_databases(startdate, enddate)
        files = []
        ky = self.kco.build_key_binary(self.ipaddress)
        for db in self.dbobjs:
            y=db.get(ky)
            if y != None:
                indexes =  self.kco.parse_index_value(y)
                for i in indexes:
                    fn=self.get_filename(db,i)
                    afn  = self.probe_file(fn)
                    files.append(afn)
        n = len(files)
        self.kco.dbg("The IP address " + self.ipaddress + " was found in "+str(n) +" kch files")
        return files

    def print_filenames(self, startdate, enddate):
        files = self.get_filenames(startdate, enddate)
        for f in files:
            print self.ipaddress," ",f

    def print_rel_filenames (self, startdate, enddate):
        files = self.get_filenames(startdate, enddate)
        for f in files:
            print self.ipaddress," ",os.path.basename(f)

    def getfull_flows(self, startdate, enddate):
        try:
            prg = self.config.get("nfdump","prg")
            args = self.config.get("nfdump", "args")
            dbdir = self.config.get('indexer','dbdir')
        except ConfigParser.NoSectionError,e:
            sys.stderr.write(str(e)+ "\n")
            sys.exit(1)
        self.open_databases(startdate, enddate)

        ky = self.kco.build_key(self.ipaddress)
        for db in self.dbobjs:
            y=db.get(ky)
            if y != None:
                indexes =  self.kco.parse_index_value(y)
                for i in indexes:
                    fn=self.get_filename(db,i)
                    afn  = self.probe_file(fn)
                    cmd = prg + " " + args +" -r " + afn  + " \"ip "+self.ipaddress + "\""
                    print "#"+ cmd
                    r = os.system(cmd)
                    if r != 0:
                        self.kco.dbg("nfdump failed exitcode = "+  str(r) + "\n")
                        sys.exit(1)


    #Returns False if the ipaddress is not found
    #Returns True if the ipaddress is found
    def check_address(self):
        dbdir = self.config.get('indexer', 'dbdir')
        self.open_databases()
        ky = self.kco.build_key(self.ipaddress)
        for db in self.dbobjs:
            y = db.get(ky)
            if y == None:
                return False
            else:
                return True

def main_function():
    ipaddress=None
    format=None
    startts = None
    endts   = None
    kl = Klookup()

    try:
        #Parse command line arguments
        opts, args = getopt.getopt(sys.argv[1:],'hf:i:c:s:e:')
        for o,a in opts:
            if o == '-h':
                kl.usage(0)
            elif o == '-i':
                ipaddress = a
            elif o == '-c':
                kl.configFile = a
            elif o =='-f':
                format = a
            elif o == '-s':
                startts = a
            elif o == '-e':
                endts = a

        if ipaddress == None:
            sys.stderr.write('An IP address or a list of IP addresses must be specified\n')
            sys.exit(1)

        kl.load()
        kl.ipaddress = ipaddress

        if (format != None):
            if format.startswith('check'):
                if kl.check_address():
                    sys.exit(0)
                else:
                    sys.exit(1)

            if format.startswith('print relative'):
                kl.print_rel_filenames(startts, endts);
                sys.exit(0)

            if format.startswith('print full'):
                kl.getfull_flows(startts, endts)
                sys.exit(0)

        #Here some printing is done
        print "#Database directory ", kl.config.get('indexer', 'dbdir')
        print "#IP address ", ipaddress
        print "#Configfile", kl.configFile

        #default format
        startdate=time.time()
        kl.print_filenames(startts,endts)
    except getopt.GetoptError,e:
        sys.stderr.write(str(e)+ '\n')
        sys.exit(1)
    endtime=time.time()
    d = endtime-startdate
    print "#Processing time: ",d
    sys.exit(0)

class TestDatabases(unittest.TestCase):
    def testFiles(self):
        kl = Klookup()
        kl.configFile = '../t/klookup/kindexer.cfg'
        kl.load()
        #Test simple case
        lst = kl.get_databases_list('2011-10-05', '2011-10-07')
        self.assertEqual(lst, ['../t/klookup/databases/2011/10/05.kch', '../t/klookup/databases/2011/10/06.kch', '../t/klookup/databases/2011/10/07.kch'])

        #Test month flip
        lst = kl.get_databases_list('2011-10-30','2011-11-01')
        self.assertEqual(lst, ['../t/klookup/databases/2011/10/30.kch', '../t/klookup/databases/2011/10/31.kch', '../t/klookup/databases/2011/11/01.kch'])

        #Test unknown start date
        lst = kl.get_databases_list(None,'2011-10-02')
        self.assertEqual(lst, ['../t/klookup/databases/2011/10/01.kch', '../t/klookup/databases/2011/10/02.kch'])

        #Test unknown end date
        lst = kl.get_databases_list('2011-11-29',None)
        self.assertEqual(lst, ['../t/klookup/databases/2011/11/29.kch', '../t/klookup/databases/2011/11/30.kch', '../t/klookup/databases/2011/11/31.kch'])

        #Test start date not found
        lst = kl.get_databases_list('aaa')
        res = ['../t/klookup/databases/2011/10/01.kch', '../t/klookup/databases/2011/10/02.kch', '../t/klookup/databases/2011/10/03.kch', '../t/klookup/databases/2011/10/04.kch', '../t/klookup/databases/2011/10/05.kch', '../t/klookup/databases/2011/10/06.kch', '../t/klookup/databases/2011/10/07.kch', '../t/klookup/databases/2011/10/08.kch', '../t/klookup/databases/2011/10/09.kch', '../t/klookup/databases/2011/10/10.kch', '../t/klookup/databases/2011/10/11.kch', '../t/klookup/databases/2011/10/12.kch', '../t/klookup/databases/2011/10/13.kch', '../t/klookup/databases/2011/10/14.kch', '../t/klookup/databases/2011/10/15.kch', '../t/klookup/databases/2011/10/16.kch', '../t/klookup/databases/2011/10/17.kch', '../t/klookup/databases/2011/10/18.kch', '../t/klookup/databases/2011/10/19.kch', '../t/klookup/databases/2011/10/20.kch', '../t/klookup/databases/2011/10/21.kch', '../t/klookup/databases/2011/10/22.kch', '../t/klookup/databases/2011/10/23.kch', '../t/klookup/databases/2011/10/24.kch', '../t/klookup/databases/2011/10/25.kch', '../t/klookup/databases/2011/10/26.kch', '../t/klookup/databases/2011/10/27.kch', '../t/klookup/databases/2011/10/28.kch', '../t/klookup/databases/2011/10/29.kch', '../t/klookup/databases/2011/10/30.kch', '../t/klookup/databases/2011/10/31.kch', '../t/klookup/databases/2011/11/01.kch', '../t/klookup/databases/2011/11/02.kch', '../t/klookup/databases/2011/11/03.kch', '../t/klookup/databases/2011/11/04.kch', '../t/klookup/databases/2011/11/05.kch', '../t/klookup/databases/2011/11/06.kch', '../t/klookup/databases/2011/11/07.kch', '../t/klookup/databases/2011/11/08.kch', '../t/klookup/databases/2011/11/09.kch', '../t/klookup/databases/2011/11/10.kch', '../t/klookup/databases/2011/11/11.kch', '../t/klookup/databases/2011/11/12.kch', '../t/klookup/databases/2011/11/13.kch', '../t/klookup/databases/2011/11/14.kch', '../t/klookup/databases/2011/11/15.kch', '../t/klookup/databases/2011/11/16.kch', '../t/klookup/databases/2011/11/17.kch', '../t/klookup/databases/2011/11/18.kch', '../t/klookup/databases/2011/11/19.kch', '../t/klookup/databases/2011/11/20.kch', '../t/klookup/databases/2011/11/21.kch', '../t/klookup/databases/2011/11/22.kch', '../t/klookup/databases/2011/11/23.kch', '../t/klookup/databases/2011/11/24.kch', '../t/klookup/databases/2011/11/25.kch', '../t/klookup/databases/2011/11/26.kch', '../t/klookup/databases/2011/11/27.kch', '../t/klookup/databases/2011/11/28.kch', '../t/klookup/databases/2011/11/29.kch', '../t/klookup/databases/2011/11/30.kch', '../t/klookup/databases/2011/11/31.kch']
        self.assertEqual(lst,res)

        #Test no time stamps
        lst = kl.get_databases_list(None, None)
        self.assertEqual(lst, res)


if __name__ == '__main__':
    #unittest.main()
    main_function()

