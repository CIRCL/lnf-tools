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
use Test::Simple tests => 60;
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

my $t1=<<END;
2011-08-30 12:33:02.522     0.000 UDP           1234:12a:beef:0:216:3aff:fe0d:6.40774 ->                     abc1:e43:a23e::1:33.53    ......   1        2       33        4        5     66     7
END

$fields=$parser->parse_line($t1);
ok($fields->{'flows'} eq '7', 'UDPv6: Test flows');
ok($fields->{'bpp'}  eq '66','UDPv6: Test bpp');
ok($fields->{'bps'} eq '5', 'UDPv6: Test bps');
ok($fields->{'pps'} eq '4', 'UDPv6: Test pps');
ok($fields->{'bytes'} eq '33', 'UDPv6: Test bytes');
ok($fields->{'packets'} eq '2','UDPv6: Test packets');
ok($fields->{'tos'} eq '1','UDPv6: Test TOS');
ok($fields->{'startDate'}->{'epoch'} eq '1314700382', "UDPv6: Test epoch timestamp");
ok($fields->{'startDate'}->{'milliseconds'} eq '522', "UDPv6: Test milliseconds");
ok($fields->{'duration'} eq '0.000', "UDPv6: Test duration");
ok($fields->{'srcaddr'} eq '1234:12a:beef:0:216:3aff:fe0d:6','UDPv6: Test srcaddr');
ok($fields->{'srcport'} eq '40774', "UDPv6: Test src port");
ok($fields->{'dstaddr'} eq 'abc1:e43:a23e::1:33', 'UDPv6: Test dstaddr');
ok($fields->{'dstport'} eq '53', 'UDPv6: Test dstport');

my $t=<<END;
2011-08-31 08:38:15.786     0.000 ICMP6                  abc1:be0:1:1::1234:b24.0     ->                 1234:3456:77::3321:1234.4.129 ......   0        1      104        4        6    104     2
END

$fields=$parser->parse_line($t);
ok($fields->{'flows'} eq '2',"ICMP6: Test flows");
ok($fields->{'bpp'} eq '104',"ICMP6: Test bpp");
ok($fields->{'bps'} eq '6', "ICMP6: Test pps");
ok($fields->{'pps'} eq '4',"ICMP6: Test pps");
ok($fields->{'bytes'} eq '104',"ICMP6: Test bytes");
ok($fields->{'packets'} eq '1', "ICMP6: Test packets");
ok($fields->{'tos'} eq '0',"ICMP6: Test tos");
ok($fields->{'flags'} eq '......',"ICMP6: test flags");
#TODO add in doc that the ICMP code is stored in the port field
ok($fields->{'dstport'} eq '4.129',"ICMP6: Test dstport");
ok($fields->{'dstaddr'} eq '1234:3456:77::3321:1234', "ICMP6: Test dstaddr");
ok($fields->{'srcport'} eq '0',"ICMP6: Test srcport");
ok($fields->{'srcaddr'} eq 'abc1:be0:1:1::1234:b24',"ICMP6: Test srcaddr");
ok($fields->{'duration'} eq '0.000', 'ICMPv6: Test duration');
ok($fields->{'startDate'}->{'milliseconds'} eq '786', "ICMP6: Test milliseconds");
ok($fields->{'startDate'}->{'epoch'} eq '1314772695', "ICMP6: Test epoch");

my $t=<<END;
2011-08-30 01:52:32.922    66.816 GRE                              10.11.12.13:0     ->                          13.12.11.10:0     ......   0     1221    1.7 M       18   205420   1405     1
END

$fields=$parser->parse_line($t);
ok($fields->{'startDate'}->{'epoch'} eq '1314661952',"GRE test timestamp");
ok($fields->{'startDate'}->{'milliseconds'} eq '922',"GRE test milli");
ok($fields->{'duration'} eq '66.816',"GRE test duration");
ok($fields->{'proto'} eq 'GRE');
ok($fields->{'srcaddr'} eq '10.11.12.13', "GRE test srcaddr");
ok($fields->{'srcport'} eq '0', "GRE test src port");
ok($fields->{'dstaddr'} eq '13.12.11.10', "GRE dstaddr");
ok($fields->{'dstport'} eq '0',"GRE test dst port");
ok($fields->{'tos'} eq '0','GRE test tos');
ok($fields->{'packets'} eq '1221', "GRE test packets");
ok($fields->{'bytes'} eq '1700000',"GRE test bytes");
ok($fields->{'pps'} eq '18',"GRE test pps");
ok($fields->{'bps'} eq '205420', "GRE test bps");
ok($fields->{'bpp'} eq '1405', "GRE test bpp");
ok($fields->{'flows'} eq '1','GRE test flows');
