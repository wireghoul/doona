#!/usr/bin/perl
#
# This program comes with ABSOLUTELY NO WARRANTY.
# This is free software, and you are welcome to redistribute it
# under certain conditions. See docs/GPL.txt for details.
#
# Doona is a BED fork maintained by wireghoul ( www.justanotherhacker.com )
# BED was written by mjm ( www.codito.de ) and snakebyte ( www.snake-basket.de )
use Getopt::Std;
use Socket;
#use strict;
#use warnings;
my $SOCKET = "";

$SIG{'INT'} = \&sigHandler;
$SIG{'TERM'} = \&sigHandler;

# which plugins do we support? insert your plugin ( dummy ) here...
my @plugins = ( "ftp", "smtp", "pop", "http", "irc", "imap", "pjl", "lpd", "finger", "socks4", "socks5", 'tftp', 'rtsp', 'whois');

# what we test...
# the hope is to overwrite a return pointer on the stack,
# making the server execute invalid code and crash
# the last two entries in the overflowstringsarray are a DoS attempt for ftp/http
my @overflowstrings = ("A" x 33, "A" x 254, "A" x 255, "A" x 1023, "A" x 1024, "A" x 2047, "A" x 2048, "A" x 5000, "A" x 10000, "\\" x 200, "/" x 200, " " x 9000);
my @formatstrings = ("%s" x 4, "%s" x 8, "%s" x 15, "%s" x 30, "%.1024d", "%.2048d", "%.4096d");

# three ansi overflows, two ansi format strings, two OEM Format Strings
my @unicodestrings = ("\0x99"x4, "\0x99"x512, "\0x99"x1024, "\0xCD"x10, "\0xCD"x40, "\0xCB"x10, "\0xCB"x40);
my @largenumbers = ("255", "256", "257", "65535", "65536", "65537", "16777215", "16777216", "16777217", "0xfffffff", "-1", "-268435455", "-20");
my @miscstrings = ("/", "%0xa", "+", "<", ">", "%". "-", "+", "*", ".", ":", "&", "%u000", "\r", "\r\n", "\n");
my $idx = 0;
my $prevfuzz = '';
print "\n Doona 0.6 by Wireghoul (www.justanotherhacker.com) based on BED my mjm and snakebyte\n\n";

# get the parameters we need for every test
getopts('s:t:o:p:r:u:v:w:x:d');
&usage unless($opt_s);
$opt_s = lc($opt_s);                         # convert it to lowercase

# load the specified module
my $module = undef;
foreach my $plug (@plugins){
    if ( $opt_s eq $plug ){
        eval("use bedmod::$plug;");
        $a = "bedmod::$plug";
        $module = new $a;
    }
}

&usage unless(defined $module);

my %special_cfg=(
    "t" => "$opt_t",                           # target
    "o" => "$opt_o",                           # timeOut
    "p" => "$opt_p",                           # port
    "r" => "$opt_r",                           # resume test case number
    'd' => "$opt_d",                           # Print fuzz case to screen and quit

    "u" => "$opt_u",                           # special parameters for the plugin...
    "v" => "$opt_v",
    "w" => "$opt_w",
    "x" => "$opt_x"
  );

$module->{proto}        = undef;
$module->{target}       = undef;
$module->{port}         = undef;
$module->{vrfy}         = "";
$module->{timeout}      = undef;
$module->{sport}        = 0;

if ($special_cfg{'t'} eq "") { $module->{target}='127.0.0.1'; }
else { $module->{target} = $special_cfg{'t'}; }
if ($special_cfg{'o'} eq "") { $module->{timeout}='2'; }
else { $module->{timeout} = $special_cfg{'o'}; }

$module->init(%special_cfg);

# test stuff that might happen during login
my @cmdArray = $module->getLoginarray;          # which login stuff do we test

if ( $cmdArray[0] ne "" ){
    print " + Buffer overflow testing\n";
    &testThis(@overflowstrings);
    print " + Formatstring testing\n";
    &testThis(@formatstrings);
}

# test the stuff that might happen during normal protocol events ( after login )
print "* Normal tests\n";
@cmdArray = $module->getCommandarray;
my @login = $module->getLogin;
print " + Buffer overflow testing\n";
&testThis(@overflowstrings);
print " + Formatstring testing\n";
&testThis(@formatstrings);
print " + Unicode testing:\n";
&testThis(@unicodestrings);
print " + random number testing\n";
&testThis(@largenumbers);

# make the module test all other stuff
print " + Other tests\n";
$module->testMisc();

# test different sizes
for (my $i = 1; $i < 20; $i++ ) {
    print " + testing misc strings $i\n";
    &testThis(@miscstrings);
    for (my $j = 0; $j < @miscstrings; $j++) {
        $miscstrings[$j] = $miscstrings[$j].$miscstrings[$j];
    }
}

print "* All tests done.\n";
exit(0);

# this function tests each of the two arrays ( buffer overflow and format string )
sub testThis(){
    my @testArray = @_;
    my $command;
    my $socktype;
    if ( $module->{proto} eq "udp" ){
        $socktype = SOCK_DGRAM;
    } else {
        $socktype = SOCK_STREAM;
    }
    $|=1; #Auto flush output for more timely screen updates
    my $count = 0;
    my $quit = $module->getQuit;
    my $total = scalar(@cmdArray);
    foreach my $cmd (@cmdArray){
        $count++;

        my $cmd2 = $cmd;
        $cmd2 =~ s/\n|\r|[\00-\33]//ig;                              # remove \r and \n for nice displaying
        $cmd2 = substr($cmd2, 0, 30);

        print "\t\ttesting: $count/$total\t$cmd2 ";
        foreach my $LS (@testArray){
            print ".";
            $idx++;
            if ($special_cfg{'r'} > $idx) { next; }
            $prevfuzz = $command;
            $command = $cmd;
            $command =~ s/XAXAX/$LS/ig;                   # prepare the string
            if ($special_cfg{'d'}) { print "\nFuzz case: --copy--\n$command\\r\\n\n--cut--\n"; exit; }
            my $iaddr = inet_aton($module->{target})             || die "Unknown host: $module->{target}\n";
            my $paddr = sockaddr_in($module->{port}, $iaddr)     || die "getprotobyname: $!\n";
            my $proto = getprotobyname($module->{proto})         || die "getprotobyname: $!\n";
            socket(SOCKET, PF_INET, $socktype, $proto)        || die "socket: $!\n";
            my $sockaddr = sockaddr_in($module->{sport}, INADDR_ANY);
            while ( !bind(SOCKET, $sockaddr) ) {}         # we need to bind for LPD for example
            connect(SOCKET, $paddr)                           || die "connection attempt failed: $!, previous command was: ($idx) $prevfuzz\n";

            # login ...
            foreach my $log (@login){
                if ( $log ne "" ){
                    send(SOCKET, $log, 0);
                    sleep(1);                     # some daemons need some time to reply
                }
            }
            send(SOCKET, $command, 0);                    # send the attack and verify that the server is still alive
            # Is there a possibility to check within connection?
            if ($module->{vrfy} ne "") {
                send(SOCKET, $module->{vrfy},0)               || die "Problem (1) occured with $cmd2 ($idx): $command\n";
                my $recvbuf = <SOCKET>                           || die "Problem (2) occured with $cmd2 ($idx): $command\n";
                send(SOCKET, $quit, 0);           # close the connection
                close SOCKET;
            } else {
                close SOCKET;
                $iaddr = inet_aton($module->{target})             || die "Unknown host: $module->{target}\n";
                $paddr = sockaddr_in($module->{port}, $iaddr)     || die "getprotobyname: $!\n";
                $proto = getprotobyname($module->{proto})         || die "getprotobyname: $!\n";
                socket(SOCKET, PF_INET, $socktype, $proto)        || die "socket: $!\n";
                connect(SOCKET, $paddr)                           || die "Problem (3) occured with $cmd2 ($idx): $command\n";
                close SOCKET;
            }

            sleep($module->{timeout});                                             # some servers would kick us for too fast logins
        }
        print " ($idx)\n";
    }
}

# how to use these scripts...
sub usage {
    print qq~
 Usage:

 $0 -s <plugin> -t <target> -p <port> -o <timeout> [ depends on the plugin ]

 <plugin>   = FTP/SMTP/POP/HTTP/IRC/IMAP/PJL/LPD/FINGER/SOCKS4/SOCKS5
 <target>   = Host to check (default: localhost)
 <port>     = Port to connect to (default: standard port)
 <timeout>  = seconds to wait after each test (default: 2 seconds)
 use "$0 -s <plugin> -h" to obtain the parameters you need for the plugin.
 
 Only -s is a mandatory switch.

~;
    exit(1);
}

sub sigHandler {
        print "\n\nSignal caught!";
        print " - current test case index: ($idx)" if $idx;
        print "\n";
        exit;
}
