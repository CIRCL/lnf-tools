#!/usr/bin/perl
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

use nfdump;
use Test::Simple tests => 16;
use strict;
use Data::Dumper;

my $t0=<<END;
2011-08-30 11:17:56.344     3.136 TCP                            10.128.123.101:3403  ->                         192.168.123.101:80    ......   0       20     1948        6     4969     97     1
END

my $parser=nfdump->new;
my $fields=$parser->parse_line($t0);
ok($fields->{'bytes'} eq '1948', "IPv4TCP0: Test number of bytes");
ok($fields->{'proto'} eq 'TCP', "IPv4TCP0: Test protocol");
ok($fields->{'flags'} eq '......', "IPv4TCP0: Test flags");
ok($fields->{'pps'} eq '6', "IPv4TCP0: Test PPS");
ok($fields->{'packets'} eq '20', "IPv4TCP0: Test packets");
ok($fields->{'duration'} eq '3.136', "IPv4TCP0: Test duration");
ok($fields->{'dstport'} eq '80', "IPv4TCP0: Test dstport");
ok($fields->{'tos'} eq '0', "IPv4TCP0: Test tos");
ok($fields->{'srcaddr'} eq '10.128.123.101', "IPv4TCP0: Test srcaddr");
ok($fields->{'bps'} eq '4969', "IPv4TCP0: Test bps");
ok($fields->{'dstaddr'} eq '192.168.123.101', "IPv4TCP0: Test dstaddr");
ok($fields->{'flows'} eq '1', "IPv4TCP0: Test flows");
ok($fields->{'startDate'}->{'epoch'} eq '1314695876', "IPv4TCP0: Test epoch");
ok($fields->{'startDate'}->{'milliseconds'} eq '344', "IPv4TCP0: Test milliseconds");
ok($fields->{'srcport'} eq 3403, "IPv4TCP0: Test srcport");
ok($fields->{'bpp'} eq '97',"IPv4TCP0: Test bpp");

#This line breaks the parser
#TODO fix it
#my $t1=<<END;
#2011-08-30 12:33:02.522     0.000 UDP           1234:12a:beef:0:216:3aff:fe0d:6.40774 ->                     abc1:e43:a23e::1:33.53    ......   0        1       90        0        0     90     1
#END
#
#$fields=$parser->parse_line($t1);
#print Dumper($fields);
