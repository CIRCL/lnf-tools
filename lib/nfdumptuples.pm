#!/usr/bin/perl
#
# nfdump-tools - Inspecting the output of nfdump
#
# Copyright (C) 2012 CIRCL Computer Incident Response Center Luxembourg (SMILE GIE)
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


use strict;
package nfdumptuples;

sub new{
    my ($type) = @_;
    my $self={};
    bless $self, $type;
    return $self;

}

sub process {
    my ($self,$fields) = @_;
    if (length(keys %{$fields}) == 0){
        #Hash is empty
        return 0;
    }
    if (exists($fields->{'srcaddr'}) and exists($fields->{'dstaddr'})){
        print $fields->{'srcaddr'},",",$fields->{'dstaddr'},"\n";
    }
}

1;
