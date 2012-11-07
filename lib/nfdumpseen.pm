#!/usr/bin/perl
#
# nfdump-tools - Inspecting the output of nfdump
#
# Copyright (C) 2012 CIRCL Computer Incident Response Center Luxembourg (smile gie)
# Copyright (C) 2012 Gerard Wagener
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

package nfdumpseen;

use strict;
use Data::Dumper;


sub new{
    my ($type,$source) = @_;
    my $self={};
    $self->{'lastseen'}=0;
    $self->{'firstseen'} = 1999999999;
    #FIXME Store the unparsed date instead of emerging into date parsing issues
    $self->{'firstseenline'}= undef;
    $self->{'lastseenline'} = undef;
    $self->{'source'} = $source;
    bless $self, $type;
    return $self;
}


sub process {
    my ($self,$fields) = @_;
    #Focus on the source
    if (($fields->{'srcaddr'} eq $self->{'source'}) or ($fields->{'dstaddr'} eq $self->{'source'})){
        #Update first seen
            my $epoch = $fields->{'startDate'}->{'epoch'};
            if ($epoch < $self->{'firstseen'}){
                $self->{'firstseen'}=$epoch;
                $self->{'firstseenline'}=$fields->{'line'};
            }
            if ($epoch>$self->{'lastseen'}){
                $self->{'lastseen'} = $epoch;
                $self->{'lastseenline'} = $fields->{'line'};
            } 
        }
}

sub get_firstseen {
    my ($self) = @_;
    my $out="";
    if (defined($self->{'firstseenline'})){
        my @t = split(' ',$self->{'firstseenline'});
        $out = @t[0]." ".@t[1];
    }
    return $out;
}

sub get_lastseen {
    my ($self) = @_;
    my $out ="";
    if (defined($self->{'lastseenline'})){
        my @t = split(' ',$self->{'lastseenline'});
        $out = @t[0]." ".@t[1];
    }
    return $out;
}

1;
