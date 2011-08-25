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


use strict;
package nfdumphandler;
use Data::Dumper;

sub new{
    my ($type, $address) = @_;
    my $self={};
    $self->{'firstseen'} = 0;
    $self->{'hosts'} = {};
    $self->{'address'} = $address;
    bless $self, $type;
    return $self;

}

sub process {
    my ($self,$fields) = @_;
    if (length(keys %{$fields}) == 0){
        print "Got empty hash\n";
    }
    if ($self->{'firstseen'} == 0){
        $self->{'firstseen'} =  $fields->{'startDate'}->{'epoch'};
    }
    my $relts = $fields->{'startDate'}->{'epoch'} - $self->{'firstseen'};

    #Determine the third party different than the specified address
    my $addr = undef;

    if ($fields->{'srcaddr'} eq $self->{'address'}){
        $addr = $fields->{'dstaddr'}; # assume that the destination is the
                                      # third party
    }
    if ($fields->{'dstaddr'} eq $self->{'address'}){
        $addr = $fields->{'srcaddr'}; # assume that the source is the
                                      # third party
    }

    #Do accounting on the exhanged bytes
    if (defined($addr)){
        $self->{'hosts'}->{$addr}+=$fields->{'bytes'};
    }
}

sub print_top_talkers{
    my ($self) = @_;
    print "#Rank Hostname numberofbytes\n";
    my @kz=sort {$self->{'hosts'}->{$b} <=> $self->{'hosts'}->{$a} } keys %{$self->{'hosts'}};
    my $rank = 0;
    foreach my $k (@kz){
        $rank++;
        print "$rank $k $self->{hosts}->{$k}\n";
    }
}
1;
