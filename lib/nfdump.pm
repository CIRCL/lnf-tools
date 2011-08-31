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

package nfdump;
use strict;
use POSIX;
use Data::Dumper;
use IO::Handle;

sub new{
    my ($type, $processor) = @_;
    my $self={};
    $self->{'header'}="Date flow start          Duration Proto      Src IP Addr:Port          Dst IP Addr:Port   Flags Tos  Packets    Bytes      pps      bps    Bpp Flows";
    $self->{'endreached'} = 0;
    $self->{'processor'} = $processor;
    bless $self, $type;
    return $self;
}



#Undo the effect of format_number in nfdump
sub fix_number{
    my ($self,$n) = @_;
    if ($n=~/M/){
        $n=~s/M//g;
        $n=$n*1000*1000;
        return $n;
    }
    if ($n=~/K/){
        $n=~s/K//g;
        $n=$n*1000;
        return $n;
    }

    if ($n=~/G/){
        $n=~s/K//g;
        $n=$n*1000*1000*1000;
        return $n;
    }
    return $n;
}

sub convert_timestamp{
    #50% faster than UnixDate from Date::Manip; ibdate-manip-perl in Ubuntu
    my ($self,$datestring, $stime) = @_;
    my ($year, $mon, $day) = split('-',$datestring);
    my ($hour,$min,$sec) = split(':',$stime);
    $year-=1900;
    $mon--;
    my $wday=0;
    my $yday=0;
    return mktime ($sec, $min, $hour, $day, $mon, $year, $wday, $yday)."";
}

sub parse_addr
{
    my ($self,$str) = @_;
    my $cnt = ($str =~ tr/://);
    if ($cnt > 1){
        #Got more than  1 ':' hence it might be an IPv6 address
        return split('\.', $str,2);
    }
    #If it is not IPv6 address it should be an Ipv4 address
    return  split(':',$str);
}
sub parse_line{
    my ($self,$line,$cnt)=@_;
    if ($line=~/^Summary/){
        $self->{'endreached'} = 1;
        print "End reached\n";
        return {};
    }
    chomp($line);
    if ($cnt==1){
        if ($line ne $self->{'header'}){
            print "Header does not match, abort\n";
            return {};
        }
    }else{
        #FIXME dirty hack for fixing the alignment
        $line=~s/ M/M/g;
        $line=~s/ K/K/g;
        $line=~s/ G/G/g;
        $line=~s/\s+/ /g;
        my ($startDate, $stime, $duration, $proto, $src, $dir, $dst, $flags, $tos, $packets,$bytes, $pps, $bps,$bpp, $flows) = split(' ',$line);
        my ($time,$ms) = split('\.',$stime);
        my $entry = {};
        $entry->{'startDate'} = {};
        $entry->{'startDate'}->{'epoch'} = $self->convert_timestamp($startDate, $stime);
        $entry->{'startDate'}->{'milliseconds'} = $ms;
        $entry->{'duration'}  = $duration;
        $entry->{'proto'}     = $proto;
        my ($addr, $port) = $self->parse_addr($src);
        $entry->{'srcaddr'} = $addr;
        $entry->{'srcport'} = $port;
        my ($addr, $port) = $self->parse_addr($dst);
        $entry->{'dstaddr'} = $addr;
        $entry->{'dstport'} = $port;
        $entry->{'flags'} = $flags;
        $entry->{'tos'} = $tos;
        $entry->{'packets'} = $packets;
        $entry->{'bytes'} = $self->fix_number($bytes);
        $entry->{'pps'} = $pps;
        $entry->{'bps'} = $bps;
        $entry->{'bpp'} = $bpp;
        $entry->{'flows'} = $flows;
        return $entry;
    }
    return {};
}


sub parse{
    my $self= shift;
    my $cnt=0;
    my $io = IO::Handle->new();
    $io->fdopen(fileno(STDIN),"r");
    while (my $line=$io->getline()){
        $cnt++;
        my $fields = $self->parse_line($line,$cnt);
        $self->{'processor'}->process($fields);
        if ($self->{'endreached'} == 1){
            last;
        }
    }
    $io->close();
}

1;
