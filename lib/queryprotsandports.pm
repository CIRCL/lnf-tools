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
package queryprotsandports;
use Data::Dumper;

sub new{
    my ($type, $address) = @_;
    my $self={};
    $self->{'firstseen'} = 0;
    $self->{'prots'} = {};
    $self->{'ports'} = {};
    $self->{'address'} = $address;
    bless $self, $type;
    return $self;

}

sub process {
    my ($self,$fields) = @_;
    if (length(keys %{$fields}) == 0){
        print "Got empty hash\n";
    }
    if ($fields->{'srcaddr'} eq $self->{'address'} or $fields->{'dstaddr'}
        eq $self->{'address'}){
        $self->{'prots'}->{$fields->{'proto'}}+=1;
        $self->{'ports'}->{$fields->{'srcport'}}+=1;
        $self->{'ports'}->{$fields->{'dstport'}}+1;
    }
}

sub print_used_protocols{
    my ($self) = @_;
    print "#Rank Protocol numberofflows\n";
    my @kz=sort {$self->{'prots'}->{$b} <=> $self->{'prots'}->{$a} } keys %{$self->{'prots'}};
    my $rank = 0;
    foreach my $k (@kz){
        $rank++;
        print "$rank $k $self->{'prots'}->{$k}\n";
    }
}

sub print_used_ports{
    my ($self) = @_;
    print "#Rank Portnumber  numberofflows\n";
    my @kz=sort {$self->{'ports'}->{$b} <=> $self->{'ports'}->{$a} } keys %{$self->{'ports'}};
    my $rank = 0;
    foreach my $k (@kz){
        $rank++;
        print "$rank $k $self->{'ports'}->{$k}\n";
    }
}
1;
