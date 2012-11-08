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
use Data::Dumper;
sub new{
    my ($type,$isVolume,$threshold,$showline) = @_;
    my $self={};
    $self->{'isVolume'} = $isVolume;
    $self->{'threshold'} = $threshold;
    $self->{'showline'} = $showline;
    bless $self, $type;
    $self->{'data'} = {};
    return $self;


}

sub process {
    my ($self,$fields) = @_;
    if (length(keys %{$fields}) == 0){
        #Hash is empty
        return 0;
    }
    if (exists($fields->{'srcaddr'}) and exists($fields->{'dstaddr'})){
        my $srcaddr = $fields->{'srcaddr'};
        my $dstaddr = $fields->{'dstaddr'};
        if (!exists($self->{'data'}->{$srcaddr})){
            $self->{'data'}->{$srcaddr} = {};
        }
        if (!exists($self->{'data'}->{$srcaddr}->{$dstaddr})){
            $self->{'$data'}->{$dstaddr}->{$srcaddr} = 0;
        }
        $self->{'data'}->{$srcaddr}->{$dstaddr}+=$fields->{'bytes'};
        if ($self->{'showline'} == 1){
            print "$srcaddr\n$dstaddr\n";
            return;
        }
        if (!defined($self->{'isVolume'})){
            print $srcaddr,",",$dstaddr,"\n";
        }
    }
}

sub print_volume_flows{
    my ($self) = @_;
    #print Dumper($self->{'data'});
    my $buf = {};
    for my $sip (keys %{$self->{data}}){
        for my $dip (keys %{$self->{data}->{$sip}}){
            my $tup = "$sip,$dip";
            my $b = $self->{'data'}->{$sip}->{$dip};
            if ($b<$self->{'threshold'}){
                next;
            }
            if (!exists($buf->{$b})){
                $buf->{$b} =[];
            }
            push(@{$buf->{$b}},$tup);
        }
    }
    for my $vol (sort {$b <=> $a}keys%{$buf}){
        my $tup = $buf->{$vol};
        for my $t (@{$buf->{$vol}}){
            print "$vol $t\n";
        }
    }
}
1;
