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
package hourlyplots;
use Data::Dumper;

sub new
{
    my ($type, $address, $port, $plotfile, $datafile, $imagefile) = @_;
    my $self={};
    $self->{'firstseen'} = 0;
    $self->{'address'} = $address;
    $self->{'port'} = $port;
    $self->{'slots'} = [];
    $self->{'lastseendate'} = [];
    $self->{'plotfile'} = $plotfile;
    $self->{'datafile'} = $datafile;
    $self->{'imagefile'} = $imagefile;
    bless $self, $type;
    return $self;

}

sub process
{
    my ($self,$fields) = @_;
    if (length(keys %{$fields}) == 0){
        print "Got empty hash\n";
    }
    if ($self->{'firstseen'} == 0){
        $self->{'firstseen'} =  $fields->{'startDate'}->{'epoch'};
    }
    my $relts = $fields->{'startDate'}->{'epoch'} - $self->{'firstseen'};
    if ($fields->{'srcaddr'} eq $self->{'address'} or $fields->{'dstaddr'} eq $self->{'address'}){
        if ($fields->{'srcport'} eq $self->{'port'} or $fields->{'dstaddr'} eq $self->{'port'}){
            #Found the address and the port
                my $idx = int($relts / 3600);
                $self->{'slots'}[$idx]++;
                $self->{'lastseendate'}[$idx]=$fields->{'startDate'};
        }
    }
}

sub generate_data_file
{
    my ($self) = @_;
    open F,">$self->{'datafile'}" or die "$! (file=$self->{'datafile'})\n";
    print F "#hour frequency (host=$self->{'address'}, port=$self->{'port'})\n";
    for (my $i=0; $i<scalar(@{$self->{'slots'}});$i++){
        my $bins = @{$self->{'slots'}}[$i]*1;
        print F "$i $bins \n"; # keep the real date?
    }
    close F;
}


sub generate_plot_file
{
    my $self=shift;
    my $tmpl=<<END;
set terminal png
set output 'OUTFILE'
set title 'TITLE'
set xlabel "t (hours)"
set ylabel "frequency"
plot 'DATFILE'  w impulses
END

    #TODO format the initial date
    $tmpl=~s/OUTFILE/$self->{'imagefile'}/g;
    my $title="Traffic History (host=$self->{'address'}, port=$self->{'port'})";
    $tmpl=~s/TITLE/$title/g;
    $tmpl=~s/DATFILE/$self->{'datafile'}/g;
    open F, ">$self->{'plotfile'}" or die "$! (file=$self->{'plotfile'})\n";
    print F $tmpl;
    close F;
}
1;
