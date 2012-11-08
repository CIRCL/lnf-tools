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

package nfdumpports;

use strict;
use Data::Dumper;

sub new{
    my ($type, $source,$port,$maxport,$frame,$mincount) = @_;
    my $self={};
    $self->{'source'} = $source; 
    $self->{'port'} = $port*1;
    $self->{'maxport'} = $maxport*1;
    $self->{'frame'} = $frame*1;
    $self->{'mincount'} = $mincount*1;
    $self->{'lastseen'} = 0;
    $self->{'tcounter'} = 0;

    $self->{'shouldDebug'}=0;
    #Needed for the heuristic 2
    $self->{'buffer'}=[];
    $self->{'flowcounter'}=0;
    bless $self, $type;
    return $self;
        
}

sub debug {
    my $self = shift;
    my $msg = join('',@_);
    if ($self->{'shouldDebug'}){
        print STDERR "[packet=$self->{'flowcounter'}] $msg\n";
    }
}

#Returns -1 if the heuristic matched -> flow is rejected 
#Returns 1 the flow should be accepted
sub h1_heuristic{
    my ($self,$fields)=@_;
    my $srcport = $fields->{'srcport'}*1;
    my $dstport = $fields->{'dstport'}*1;
    $self->debug("Heuristic 1 is used");
    if ($srcport == $self->{'port'}){
        if ($dstport < $self->{'maxport'}){
            #The corresponding port is lower than the threshold therefore
            #it is assumed to be a source port
            $self->debug("H1:Destination port is too low");
            return -1; 
        }
    }
    if ($dstport == $self->{'port'}){
        if ($srcport < $self->{'maxport'}){
            $self->debug("H1:src port is too low");
            return -1;
        }
    }
    return 1;

}

sub h2_heuristic{
    my ($self,$fields) = @_;
    $self->debug("H2 Heuristic is triggered");
    #Update the counter of IP, port as we have here a tuple here
    $self->{'tcounter'}+=1;
    #Buffer all the lines related to the tuple IP address and port
    push(@{$self->{'buffer'}},$fields); 
    #If the time frame is full, the buffer is flushed
    my $ts = @{$self->{'buffer'}}[0]->{'startDate'}->{'epoch'}*1;
    my $delta = $self->{'lastseen'} - $ts;
    if ($delta >=$self->{'frame'}){
        $self->dump();
    }
}


#A wrong constallation is defined as
#an IP addresses that does *not* correspond to the IP address under inspection
#and which port corresponds to the port under inspection
sub discard_wrong_constallations{
    my ($self,$fields) = @_;
    
    #Check if the source ip address is linked with the source port
    #that is being inspected
    if ($fields->{'srcaddr'} eq $self->{'source'}){
        if ($fields->{'srcport'} ne $self->{'port'}){
            $self->debug("W1 Wrong constallation for (",$fields->{'line'},")");
            return 1;
        }
    }
    #Check if the destination ip address is linkled with the source
    #port that is being inspected
    if ($fields->{'dstaddr'} eq $self->{'source'}){
        if ($fields->{'dstport'} ne $self->{'port'}){
            $self->debug("W2 Wrong constallation for (",$fields->{'line'},")");
            return 1;
        }
    }
    #Default: the right IP address / port constallation is there
    return 0;
}

sub process {
    my ($self,$fields) = @_;
    my $srcport = $fields->{'srcport'}*1;
    my $dstport = $fields->{'dstport'}*1;
    $self->{'flowcounter'}+=1;
    #Update the encountered timestamp to build the time frame
    if (exists($fields->{'startDate'}->{'epoch'})){
        $self->{'lastseen'} = $fields->{'startDate'}->{'epoch'}*1;
        $self->debug('Lastseen=',$self->{'lastseen'}); 
    }

    #Focus only on related flows
    #Discard not related IP addresses 
    if ($fields->{'srcaddr'} != $self->{'source'}){
        if (($fields->{'dstaddr'} != $self->{'source'})){
            $self->debug("Neither src address nor the dst ip address matched so skip it (",$fields->{'line'},")");
            return;
        }
    }
    
    if ($self->discard_wrong_constallations($fields)){
        $self->debug('Constallation check discarded (',$fields->{'line'},")");
        return;
    }

    if (($srcport == $self->{'port'}) or ($dstport == $self->{'port'})){
        if ($self->{'frame'}>0){
            $self->h2_heuristic($fields);
        }
        
        if ($self->{'maxport'}>0){
            if ($self->h1_heuristic($fields) <0){
                $self->debug('H1 heuristic rejected the flow ',$fields->{'line'});
                return;
            }
        }
        #Default action: Don't filter the flow
        print $fields->{'line'};
    }
}

sub dump {
    my ($self)=@_;
    if ($self->{'tcounter'} < $self->{'mincount'}){
        for (my $i=0; $i<length(@{$self->{'buffer'}});$i++){
            #Discarding the flow
            shift(@{$self->{'buffer'}});
        }
    }else{
        $self->flush;
    }
    $self->{'tcounter'}=0;

}

#Dump the rest of the buffer even if the heuristic H2 could match
#but there is not enough of data to compare
sub flush {
    my ($self) = @_;
        for (my $i=0; $i<length(@{$self->{'buffer'}});$i++){
            my $fields = shift(@{$self->{'buffer'}});
            #Check if the H1 heuristic is used aswell
            if ($self->{'maxport'} > 0){
                if ($self->h1_heuristic($fields) < 0){
                    next;
                }
            }
            print $fields->{'line'};
        }
}
1;
