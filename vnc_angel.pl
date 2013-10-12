#!/usr/bin/env perl

=head1 NAME

    vnc_angel

=head1 VERSION

    0.01

=cut

our $VERSION = 0.01;

=head1 DESCRIPTION

  If you have a Linux server then it can recover from a reboot on its own.
  If you add dm-crypt to your file system then it can NOT.

  This script can connect over ssh via VNC to check on a server and if the server
  requires decrypting then it can enter that, (thanks to Leon Brocard and Adam Kennedy).

=head1 SYNOPSIS

./vnc_angel [-host $remote_hostname:$listening_vnc_porn] [-d] [-v]

=head1 DEPENDENCIES

Net::VNC
Imager::Search
( because `ssh -L $tunnel_opt` is flaky at best we should be using: )
Net::Openssh

and two comparison images:

=over 8

=item B</tmp/vnc_angel/centos_logo.png> (something to detect the login screen)

=item B</tmp/vnc_angel/logged_in.png>   (something to detect a logged in server - ugh, why would you leave that door open?)

=back

    (you can build these using GIMP from the PNG downloaded by this script - just grab a piece of the image.)

Right now it collects the server passphrase from a JSON::XS encoded string stored in

=over 8

=item B<~/.paswd/.vnc_angelrc>

=back

    in the form: 

=over 8

=item B<{"ns0":"dm-crypt_passphrase"}>

=back

Where ns0 is the name of the server and dm-crypt_passphrase is the passphrase to decode encoded filesystem
(though I expect that was obvious. You can have as many servers as you like in that stored hash.)


=head2 USES but does not depend upon

    JSON::XS
    Data::Dumper
    Quantum::Superpositions
    (i.e. you can easily strip them out or replace them. Maybe you want to store in CDB_File)

=head2 CRON

SHELL=/bin/bash

5 * * * * pushd /usr/local/bin/ 1>/dev/null; ./vnc_angel 2>&1 1>>/var/log/vnc_angel.log; popd 1>/dev/null

=cut

use strict;
$|=1;

=head1 OPTIONS

%opt stores the global variables
%ignore overrides %opt

=cut

my (%opt,%ignore);

=head2 ARGS

=over 8

=item B<-h> send for help (just spits out this POD by default, but we can chose something else if we like 

=item B<-host> name or IP of remote host

=item B<-d> increment debug level

=item B<-v> increment reporting level level

=back

=head3 other arguments and flags that are valid

null - falls back to hard coded defaults

=cut

# which user ssh user we are using
my $user = 'alexx';
# the far end of the SSH tunnel
my $gw = '192.0.2.2';
my $server = 'ns0';
# ssh known_hosts for security
my $known_hosts='~/.bigv/default/known_hosts';
if($known_hosts=~m/^~/){
    $known_hosts=~s/^~/$home/;
}

for(my $args=0;$args<=(@ARGV -1);$args++){
    if ($ARGV[$args]=~m/^-+h/i){ &help; }
    elsif ($ARGV[$args] eq '-d'){ $opt{D}++; }
    elsif ($ARGV[$args] eq '-v'){ $opt{verbose}++; }
    #elsif ($ARGV[$args]=~m/-+i(.+)/){ $ignore{$1}=1; }
    elsif ($ARGV[$args]=~m/-+host(.+)/){ $opt{host} = $1; }
    elsif ($ARGV[$args]=~m/-+host/){ $args++; $opt{host} = $ARGV[$args]; }
    elsif ($ARGV[$args]=~m/-+port(.+)/){ $opt{port} = $1; }
    elsif ($ARGV[$args]=~m/-+port/){ $args++; $opt{port} = $ARGV[$args]; }
    elsif ($ARGV[$args]=~m/-+user(.+)/){ $opt{user} = $1; }
    elsif ($ARGV[$args]=~m/-+user/){ $args++; $opt{user} = $ARGV[$args]; }
    else{ print "what is this $ARGV[$args] you talk of?\n"; &help; }
}

=head3 defaults

=item B<hostname> localhost:18865

=cut

if($opt{user}){ $user=$opt{user}; }
# the local end of the ssh tunnel to the gateway
my $local_port = 18865;
if($opt{local_port}){ $local_port=$opt{local_port}; }
my $home = `echo -n \$HOME`;
if($home!~m/home/){ $home = '/home/' . $user; }
# where we host the RSA PRIVATE key for the ssh tunnel
my $vnc_rsa = '~/.ssh/vnc_angel_rsa';
if($vnc_rsa=~m/^~/){
    $vnc_rsa=~s/^~/$home/;
}
# the VNC port at the other end
my $port = 5900;
if($opt{port}){ $port=$opt{port}; }
my $dm_crypt_passphrase = '';

# which machine is creating the ssh tunnel
my $host = 'localhost';
if($local_port){
    $host .= ':' . $local_port;
}
unless($opt{host}){
    $opt{host} = $host;
}
my $password = ''; # from before we moved to passphrases

=head1 METHODS

=head2 help

enable the  (-)-h(elp) option

=cut

sub help {
    print `perldoc $0`;
    exit(0);
}

=head2 collect_passphrase

    Obviously we don't store the dm-crypt passphrase here, so we have to collect it.

=cut

sub collect_passphrase {
    # {"ns0":"dm-crypt_passphrase"}

    use JSON::XS;
    my $location = '/home/' . $user . '/.paswd/.vnc_angelrc';
    my $wedlock = {};
    
    $wedlock = decode_json `cat $location`;
    $dm_crypt_passphrase = $wedlock->{$server};
}

#perl -MJSON::XS -e 'my $location = "~/.paswd/.vnc_angelrc"; $server="ns0sb"; my $wedlock = {}; $wedlock = decode_json `cat $location`; print $wedlock->{$server};"


##### code

use Data::Dumper;
use Net::VNC;
use Imager::Search ();
use Imager::Search::Image ();
use Quantum::Superpositions; #just because it is so cool
use DateTime;
my $zulu = DateTime->now( time_zone => 'UTC' )->strftime("%Y%m%dT%H%M%SZ");

sub send_pass {
    my ($self,$pass) = shift;
    $pass = $dm_crypt_passphrase unless $pass;
    print "sending $pass to " . $server . "\n" if $opt{D}>=1;
    if($pass ne ''){
        $|=1;
        #wake up VNC
        #foreach my $key ( map {ord} split //, "\r\n" ) {
        #    $self->send_key_event($key);
        #}
        #$self->send_key_event_string($pass);
        #$self->send_key_event_string("\n");

        $self->send_key_event(0xffe1); # wake up with Shift key
        #$self->send_key_event(10);             # This \n works
        #$self->send_key_event(map {ord} "\n"); # as does this

  #      print "once more with feeling\n";
        #my @string = split //, $pass;
        #foreach my $key ( map {ord} @string ) {
        foreach my $key ( map {ord} split //, "$pass\n" ) {
            $self->send_key_event($key); 
            $self->_send_key_event( 0, $key ); # check that key is lifted
            $self->send_key_event(10);  # not sure we need this, but is seems to help
            sleep(2);   # don't rush VNC, she's and old workhorse
        }
	# NTS (Note To Self)
	# if the dm_crypt challenge screen has :**** then we need to check
	# that is has as many * as characters that we 'think' that we have sent
	# and keep sending [0] a letter until we get a new * 
	# [0] we should tell someone if we have tried a few times and failed
	#
	# also we should have the ^W^W^W^Wsend_pass() ability
	# and a check for some sort of confirmation screen
	#
	# it can take the server a minute to finish DHCP and things like that
	# so we should wait for the challenge screen
        
        $self->send_key_event(0xff0d);
=pod
        #$self->send_key_event(map {ord} "\n");
        #$self->send_key_event(10);
        #$self->send_key_event(map {ord} "");
        #$self->send_key_event_string("\n");

        $self->send_key_event_string(" \n");
        foreach my $key (@string) {
            $self->send_key_event(map {ord} $key);
        }
        $self->send_key_event_string(" \n");

=cut

        print "lifting the keys\n" if $opt{verbose}>=1;

        # sometimes Net::VNC leaves a key down so...
        foreach my $key ( map {ord} split //, "$pass\n" ) {
            $self->_send_key_event( 0, $key );
        }
        return $self;
    }else{
        print STDERR "Can't send blank passphrase; or if you like - have sent blank passphrase.\n";
    }
}

# check for existing ssh tunnel (VNC isn't secure' enough!)

sub create_ssh_tunnel {
    unless ( -f "$vnc_rsa"){
         # extract the RSA PRIVATE KEY from ~/.bigv/$(cat ~/.bigv/profile)/bmcloudrc
        my $newly_extracted_RSA_key = `cat ~/.bigv/\$(cat ~/.bigv/profile)/bmcloudrc`;
        # we have to extract it from the binary
        # ssh-keygen -i -f newly_extracted_RSA_key > $vnc_rsa `;
        die "$vnc_rsa not found (and for now we have not written that part";
        if($newly_extracted_RSA_key){
            `echo $newly_extracted_RSA_key > $vnc_rsa && chmod 0700 $vnc_rsa`;
        }
    }

    # NTS check for a valid $vnc_rsa

    #system("ssh -oBatchMode=yes -q -N -L $local_port:[$gw]:$port -l $user -i $vnc_rsa -o UserKnownHostsFile=$known_hosts $gw");
    #`ssh -oBatchMode=yes -q -N -L $local_port:[$gw]:$port -l $user -i $vnc_rsa -o UserKnownHostsFile=$known_hosts $gw &`;
    print "what we want is:\n" if  $opt{D}>=3;
    print "ssh -oBatchMode=yes -q -N -L $local_port:[$gw]:$port -l $user -i $vnc_rsa -o UserKnownHostsFile=$known_hosts $gw\n" if  $opt{D}>=3;
    #my $dug = `ssh -F /etc/ssh/ssh_config -f -oBatchMode=yes -q -N -L 18865:[213.138.99.243]:5900 -l $user -i /home/$user/.ssh/vnc_angel_rsa -o UserKnownHostsFile=/home/$user/.bigv/default/known_hosts 213.138.99.243 \&`;
    print STDERR "$zulu Creating ssh tunnel from $local_port to $gw:$port for $user with $vnc_rsa\n" if $opt{verbose}>=0;
    ##my $dug = `ssh -F /etc/ssh/ssh_config -f -oBatchMode=yes -q -N -L $local_port:[$gw]:$port -l $user -i $vnc_rsa -o UserKnownHostsFile=$known_hosts $gw \&`;
    ##my $dug = `ssh -F /etc/ssh/ssh_config -f -oBatchMode=yes -q -N -L $local_port:[$gw]:$port -l $user -i $vnc_rsa -o UserKnownHostsFile=$known_hosts $gw &`;
    ##my $dug = `exec ssh -F /etc/ssh/ssh_config -f -oBatchMode=yes -q -N -L $local_port:[$gw]:$port -l $user -i $vnc_rsa -o UserKnownHostsFile=$known_hosts $gw \&`;
    my $dug=system("ssh -F /etc/ssh/ssh_config -f -oBatchMode=yes -q -N -L $local_port:[$gw]:$port -l $user -i $vnc_rsa -o UserKnownHostsFile=$known_hosts $gw \&");
    sleep(2); # give openSSH time to dig the tunnel
    print "DUG: $dug\n" if $opt{D}>=1;

    $opt{ssh_tunnel} = $dug ? 1 : 1;

=pod

    # We should probably be using Net::OpenSSH, but it wants to build a -W tunnel and I want a -L tunnel.

    use Net::OpenSSH;
    my %ssh_opts = (user => $user,
                    key_path => $vnc_rsa,
                    batch_mode => 1,
                    port => $port,
                    master_opts => [
                        -o => "UserKnownHostsFile=$known_hosts", 
                        -q => 1, 
                        -i => "/home/$user/.ssh/vnc_angel_rsa",
                        -N => 1, 
                        -F => '/etc/ssh/ssh_config',
                        -f => 1, 
                        -L => "$local_port:\[$gw\]:$port" 
                        ],
                    );

    print "host: $host\n";
    print "gw: $gw\n";
    print "port: $port\n";

    # ssh -F /etc/ssh/ssh_config -f -oBatchMode=yes -q -N -L 18865:[$gw]:5900 -l $user -i /home/$user/.ssh/vnc_angel_rsa -o UserKnownHostsFile=/home/$user/.bigv/default/known_hosts $gw

    # ssh -f -N -L 25901:127.0.0.1:5901 me@remote.example.org; vncviewer 127.0.0.1:18865:1
    # Auto-closing SSH tunnels using the "remote command replacing -N" trick 
    # ssh -f -L -C -c blowfish 25901:127.0.0.1:5901 me@remote.example.org sleep 10; vncviewer 127.0.0.1:18865:1

    my $gateway = $gw;
    $Net::OpenSSH::debug = -1; # this is really helpful.
    #push @{ $ssh_opts{master_opts} }, -L => "$local_port:\[$gw\]:$port";
    my $ssh_g = Net::OpenSSH->new($gw, port => $port) or die "no Net::OpenSSH for you $_: " . $_->error;
    $Net::OpenSSH::debug = -1; # this is really helpful.
    print $ssh_g->get_expand_vars;
   exit;
    #$opt{ssh_tunnel} = $ssh_g->open_tunnel($gw, \%ssh_opts) or die "unable to spawn tunnel process to $_: " . $ssh_g->error;
    #my $proxy_command = $ssh_g->make_remote_command({tunnel => 1}, );
    #my $proxy_command = $ssh_g->make_remote_command({tunnel => 1}, $host, $port);
    #$opt{ssh_tunnel} = Net::OpenSSH->new($host, master_opts => [-o => "ProxyCommand $proxy_command"]);

    print "########################################################################\n";
    print $opt{ssh_tunnel};
    print "\n########################################################################\n";
                    
    #my $ssh_g = Net::OpenSSH->new("$local_port:[$gw]:$port", %ssh_opts);
    #my $ssh_g = Net::OpenSSH->new("$gw", %ssh_opts);
    #$opt{ssh_tunnel} = $ssh_g->make_remote_command({tunnel => 1}, $gw, $port);
    #$ssh->system(\%opts, @cmd)

=cut

    print `ps auwxf|grep $local_port|grep -v grep` if $opt{D}>=2;
    #print `sudo netstat -pan|grep $local_port` if $opt{D}>=2;
    print `sudo netstat -pan|grep ssh` if $opt{D}>=2;

    return $opt{ssh_tunnel} ? 1 : 0;
    #return 1;

}

sub find_ssh_tunnel {

    #my $found = `sudo netstat -pan|grep ssh|grep $local_port`;
    my $found = `ps auwxf|grep ssh|grep -v grep |grep $local_port|| echo -n 0`;
    if($found ne 0){
        print "tunnel already established\n" if $opt{verbose}>=4;
    }else{
        print "$zulu no tunnel\n" if $opt{verbose}>=0;
        $opt{verbose} += create_ssh_tunnel;
        print "tunnel is dug\n" if $opt{verbose}>=1;
    }
}


find_ssh_tunnel; # or created it

my $vnc;
my $vncopt = {};

{
   # my ($host, $password) = @ARGV;
    my ($host, $password) = ($opt{host}, $opt{pass});
    my ($hostname, $port) = split ":", $host;
    $port ||= 5900;

    $vncopt = {
        hostname => $hostname,
        port => $port
    };

    $vncopt->{password} = $password if $password;
}

if($opt{D}){
    print Dumper(\$vncopt);
}

my $img_dir  = '/tmp/vnc_angel';
my $file = "$img_dir/${server}_${$}_screen.png";
if( ! -d "$img_dir" || ! -w "$img_dir"){ 
    my $made = `mkdir $img_dir 2>&1 1>/dev/null && echo 1`; 
    unless($made){
        while( ! -w $img_dir){
            $img_dir .= $$;
            `mkdir $img_dir`;
        }
    }
}
my $comparison = "out/centos_logo.png";

print "sending Net::VNC to collect $file\n" if $opt{D}>=10;

$vnc = Net::VNC->new($vncopt) or die Dumper(\$vncopt);
$vnc->hide_cursor(1);
$vnc->depth(24);
$vnc->login;
#mouse_move_to(right from the far left, down from the top); #i.e. 1,1 is top left
# mouse_move_to($vnc->width/2, $vnc->height/2); # is the middle of the screen
my $hour = `date +%H`; chomp($hour); $hour = ( $hour + 1 ) * 20;
$vnc->mouse_move_to(256, $hour); #wake if idle (trying to get a smaller image) than 308979
#$vnc->hide_cursor(1);
my $capture = $vnc->capture;
if($capture){
    my $old_caps = $file;
    $old_caps=~s/$$.*/*/;
    #print "removing old caps with rm $old_caps\n"; 
    `rm $old_caps 2>&1 1>/dev/null`; 
}
print $vnc->name . ": " . $vnc->width . ' x ' . $vnc->height . "\n" if $opt{verbose}>=3;
$capture->save($file);
my $screen = Imager::Search::Image->new(
    driver => "Imager::Search::Driver::HTML24",
    file => $file
    );

print "loading pattern ($comparison) to match withing $file\n" if $opt{verbose}>=1;

my $pattern = Imager::Search::Pattern->new(
        driver => "Imager::Search::Driver::HTML24",
        file => "$comparison"
    );

print "doing a pattern match\n" if $opt{verbose}>=1;
my @matches = $screen->find($pattern);

if (@matches) {
    if($opt{verbose}>=2){
        print "aaah! (sigh) found at: " . join(" ", map { "(" . $_->center_x . ", " . $_->center_y . ")" } @matches);
        print "so the server is up";
    }
    if($opt{D}>=100){
        collect_passphrase;
        print "If we _did_ have to enter the dm-crypt passphrase it would be $dm_crypt_passphrase for $server\n";
    }
}
else {
    if($vnc){

        #check that we aren't logged in
        my $pattern = Imager::Search::Pattern->new(
        driver => "Imager::Search::Driver::HTML24",
        file => "out/logged_in.png"
        );
	# we should probably store the two comparison images as Base64 strings and write them to disk for use.
        my @matches = $screen->find($pattern);
        if(@matches){
            print "Looks like you are already logged in\n" if $opt{verbose}>=1;
        }else{
            print STDOUT "oh dear it looks like we have to send the passphrase\n";
            collect_passphrase;
	    $vnc->mouse_move_to(256, 1); #wake if idle (trying to get a smaller image) than 308979
	    $vnc->mouse_click(); #to connect with the server
            $vnc = send_pass($vnc,$dm_crypt_passphrase);
            print STDOUT "$zulu passphrase sent to $server\n";
            exit(1);
        }
    }else{
        print "We can't tell if the server is down - probably a SSH tunnel issue - report anyway";
        print STDERR "vnc_angel on " . `hostname` . " from " . `ip a|grep inet` . " was unable to check $server ";
    }
}

    #$self->latest_screenshot($screen);


#open (CAP, "vnc_angel_cap.jpg");
#print CAP take_screenshot($vnc);
#close(CAP);


##### end of code

=head2 NTS

Note To Self

VNC can connect to the remote server via the local end of the ssh tunnel with:

vncviewer 127.0.0.1:18865:1
# OR
sh -c /usr/bin/xtightvncviewer -encodings "copyrect tight hextile zlib corre rre raw" localhost:18865
/usr/bin/xtightvncviewer -encodings copyrect tight hextile zlib corre rre raw localhost:18865

=head1 TODO

work out how to extract the SSH private key from a ruby string using

#!/usr/bin/env ruby

# ruby -e 'require "openssl";string=`sed 's/^[^ ].*//g' ~/.bigv/$(cat ~/.bigv/profile)/bmcloudrc|grep .|sed 's/^\s*//'`;print OpenSSL::PKey::RSA.new(string).to_pem'

require 'openssl'
string=`sed 's/^[^ ].*//g' ~/.bigv/$(cat ~/.bigv/profile)/bmcloudrc|grep .|sed 's/^\s*//'`

print OpenSSL::PKey::RSA.new( string ).to_pem

#/usr/lib/ruby/vendor_ruby/bigv/bmcloud/core/ssh_key.rb

and then implement that in perl, (so that we are not left with the ruby dep)

=head1 BUGS AND LIMITATIONS

There are no known problems with this module, (I'm using it right now).
It should check that the ssh key seems valid and that the tunnel is stable.
Also more checking as it enters the passphrase, (it should check that the
server boots and try again every few minutes, until it times out and lets
a sysadmin/nagios/munin/mon know.)

Please report any bugs or feature requests

=head1 SEE ALSO

#L<Notice>

=head1 MAINTAINER

is the AUTHOR

=head1 AUTHOR

C<Alexx Roche>, <alexx at cpan dot org>

=head1 LICENSE AND COPYRIGHT

Copyright 2013 Alexx Roche, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the terms of either: MIT license or Apache License 2.0.
See http://www.opensource.org/licenses/ for more information.

=cut

print "Done that\n" if $opt{verbose}>=1;
exit(0);
__END__

# __END__ is usally only used if we are going to have POD after the code
