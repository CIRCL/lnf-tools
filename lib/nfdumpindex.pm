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

package nfdumpindex;

use strict;
use Data::Dumper;
use Net::IP;

sub new{
    my ($type, $redis, $sourceIndex) = @_;
    my $self={};
    $self->{'redis'} = $redis;
    $self->{'sourceIndex'} = $sourceIndex;
    bless $self, $type;
    return $self;

}

sub process {
    my ($self,$fields) = @_;
    if (length(keys %{$fields}) == 0){
        print "Got empty hash\n";
    }
    if ($fields->{'srcaddr'} ne ""){
        $self->{ 'redis'}->sadd("i:$fields->{'srcaddr'}", $self->{'sourceIndex'});
    }
    if ($fields->{'dstaddr'} ne ""){
        $self->{'redis'}->sadd("i:$fields->{'dstaddr'}",$self->{'sourceIndex'});
    }
}

1;
