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
use Config;

#use strict;
#use warnings;
my $SOCKET;
my $VERSION = '0.7';

$SIG{'INT'} = \&sigHandler;
$SIG{'TERM'} = \&sigHandler;
$SIG{'PIPE'} = \&sigHandler;

my @modules = map { s!bedmod/(.*)\.pm!$1!; $_ } glob("bedmod/*.pm");

# the hope is to overwrite a return pointer on the stack,
# making the server execute invalid code and crash
my @overflowstrings = ("A" x 33, "A" x 254, "A" x 255, "A" x 1023, "A" x 1024, "A" x 2047, "A" x 2048, "A" x 5000, "A" x 10000, "\\" x 200, "/" x 200, " " x 9000, "AA " x 200);
my @formatstrings = ("%s" x 4, "%s%p%x%d", "%s" x 8, "%s" x 15, "%s" x 30, "%.1024d", "%.2048d", "%.4096d", '%@' x 53, "%.16705u%2\$hn");

# three ansi overflows, two ansi format strings, two OEM Format Strings
my @unicodestrings = ("\0x99"x4, "\0x99"x512, "\0x99"x1024, "\0xCD"x10, "\0xCD"x40, "\0xCB"x10, "\0xCB"x40);
my @largenumbers = (
    "255", "256", "257",
    "65535", "65536", "65537",
    "16777215", "16777216", "16777217",
    "0xffffffff", "2147483647", "2147483648", "2147483649",
    "4294967295", "9223372036854775807", "18446744073709551615",
    "-1", "-268435455", "-20",
    "2.2250738585072011e-308",
  );
my @miscstrings = ("/", "\\", "%0xa", " ", "+", "<", ">", "<>", "%", "-", "+", "*", ".", ":", "&", "%u000", "\t", "\r", "\r\n", "\n");
my $idx = 0;
my $prevfuzz = '';
print "\n Doona $VERSION by Wireghoul (www.justanotherhacker.com) based on BED by mjm and snakebyte\n\n";

# get the parameters we need for every test
getopts('m:s:t:o:p:r:u:v:w:x:M:dh');
$opt_s = $opt_m if ($opt_m);
&usage unless($opt_s);
$opt_s = lc($opt_s);                         # convert it to lowercase

# load the specified module
my $module = undef;
if ( -f "bedmod/$opt_s.pm") {
    eval("use bedmod::$opt_s;");
    $a = "bedmod::$opt_s";
    $module = new $a;
}

&usage unless(defined $module);
&usage if ($opt_h);

my %special_cfg=(
    "t" => "$opt_t",                           # target
    "o" => "$opt_o",                           # timeOut
    "p" => "$opt_p",                           # port
    "r" => "$opt_r",                           # resume test case number
    'M' => "$opt_M",                           # Max requests to perform
    'd' => "$opt_d",                           # Print fuzz case to screen and quit
    "u" => "$opt_u",                           # special parameters for the module...
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

# $num_threads = 4; # Wishlist: Run with 4 threads by defaults

# test stuff that might happen during login
my @cmdArray = $module->getLoginarray;          # which login stuff do we test
my @login = ("");
if ( $cmdArray[0] ne "" ){
    print " + Buffer overflow testing\n";
    &testThis(@overflowstrings);
    print " + Formatstring testing\n";
    &testThis(@formatstrings);
}

# test the stuff that might happen during normal protocol events ( after login )
print "* Normal tests\n";
@cmdArray = $module->getCommandarray;
@login = $module->getLogin;
print " + Buffer overflow testing\n";
&testThis(@overflowstrings);
print " + Formatstring testing\n";
&testThis(@formatstrings);
print " + Unicode testing:\n";
&testThis(@unicodestrings);
print " + random number testing\n";
&testThis(@largenumbers);

# make the module test all other stuff
#print " + Other tests\n";
#$module->testMisc();

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
sub testThis() {
    my $count = 0;
    foreach my $log (@login) {
        my @testArray = @_;
        my $command;
        my $socktype;
        if ( $module->{proto} eq "udp" ) {i
            $socktype = SOCK_DGRAM;
        } else {
            $socktype = SOCK_STREAM;
        }
        $|=1; #Auto flush output for more timely screen updates
        # my $count = 0;
        my $quit = $module->getQuit;
        my $total = scalar(@cmdArray)*scalar(@login);
        foreach my $cmd (@cmdArray) {
            $count++;

            my $cmd2 = $cmd;
            $cmd2 =~ s/\n|\r|[\00-\33]//ig;                              # remove \r and \n for nice displaying
            $cmd2 = substr($cmd2, 0, 30);

            my $log2 = $log;
            $log2 =~ s/\n|\r|[\00-\33]//ig;
            $log2 = substr($log2, 0, 10);

            print "\ttesting: $count/$total\t$log2 [$cmd2] ";
            foreach my $LS (@testArray){
                print ".";
                $idx++;
                if ($special_cfg{'r'} > $idx) { next; }
                if ($opt_M) { $special_cfg{'M'}--; }
                if ($special_cfg{'M'} < 0) { print "\nMax requests ($opt_M) completed, index: ". ($idx - 1) ."\n"; exit }
                $prevfuzz = $command;
                $command = $cmd;
                $command =~ s/XAXAX/$LS/ig;                   # prepare the string
                if ($special_cfg{'d'}) {
                    print "\nFuzz case: --copy--\n";
                } else {
                    my $iaddr = inet_aton($module->{target})             || die "Unknown host: $module->{target}\n";
                    my $paddr = sockaddr_in($module->{port}, $iaddr)     || die "getprotobyname: $!\n";
                    my $proto = getprotobyname($module->{proto})         || die "getprotobyname: $!\n";
                    socket(SOCKET, PF_INET, $socktype, $proto)           || die "socket: $!\n";
                    my $sockaddr = sockaddr_in($module->{sport}, INADDR_ANY);
                    while ( !bind(SOCKET, $sockaddr) ) {}         # we need to bind for LPD for example
                    connect(SOCKET, $paddr)                             || die "connection attempt failed: $!, during $cmd2 ($idx)\n";
                }

                # login
                if ( $log ne "" ) {
                    if ($special_cfg{'d'}) {
                        print "$log";
                    } else {
                        send(SOCKET, $log, 0);
                        sleep(1);                     # some daemons need some time to reply
                    }
                }

                #}
                if ($special_cfg{'d'}) { print "$command\\r\\n\n--cut--\n"; exit; }
                send(SOCKET, $command, 0);                    # send the attack and verify that the server is still alive
                # Is there a possibility to check within connection?
                if ($module->{vrfy} ne "") {
                    send(SOCKET, $module->{vrfy},0)                  || die "Problem (1) occured with $cmd2 ($idx)\n";
                    my $recvbuf = <SOCKET>                           || die "Problem (2) occured with $cmd2 ($idx)\n";
                    send(SOCKET, $quit, 0);           # close the connection
                    close SOCKET;
                } else {
                    close SOCKET;
                    my $iaddr = inet_aton($module->{target})            || die "Unknown host: $module->{target}\n";
                    my $paddr = sockaddr_in($module->{port}, $iaddr)    || die "getprotobyname: $!\n";
                    my $proto = getprotobyname($module->{proto})        || die "getprotobyname: $!\n";
                    socket(SOCKET, PF_INET, $socktype, $proto)       || die "socket: $!\n";
                    connect(SOCKET, $paddr)                          || die "Problem (3) occured with $cmd2 ($idx)\n";
                    close SOCKET;
                }

                sleep($module->{timeout});                                             # some servers would kick us for too fast rogins
            }
            print " ($idx)\n";
        }
    }
}

# how to use these scripts...
sub usage {
    print qq~Usage:

 $0 -m [module] <options>

 -m <module>   = ~ . join('/', map(uc, @modules)). qq~
 -t <target>   = Host to check (default: localhost)
 -p <port>     = Port to connect to (default: module specific standard port)
 -o <timeout>  = seconds to wait after each test (default: 2 seconds)
 -r <index>    = Resumes fuzzing at test case index
 -d            = Dump test case to stdout (use in combination with -r)
 -M <num>      = Exit after executing <num> number of fuzz cases
 -h            = Help (this text)
 use "$0 -m [module] -h" for module specific option.

 Only -m is a mandatory switch.

~;
    if ($opt_h) {
        $module->usage() if $module;
    }
    exit(1);
}

sub sigHandler {
    print "\n\nSignal INT/TERM/PIPE caught!";
    print " - current test case index: ($idx)" if $idx;
    print "\n";
    exit;
}
