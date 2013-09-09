package bedmod::ftp;
use Socket;

# This package is an extension to bed, to check
# for ftp server vulnerabilities.

sub new{
	my $this = {};
	$this->{username}     = 'anonymous'; # specific for just this
	$this->{password}     = 'user@this.bed'; # module
	bless $this;
	return $this;
}

sub init{
	my $this = shift;
	%special_cfg=@_;

    # Specify protocol to use
    $this->{proto}="tcp";

    # check for missing args, set target and host

    if ($special_cfg{'p'} eq "") { $this->{port}='21'; }
      else { $this->{port} = $special_cfg{'p'}; }

	# get info nessecairy for FTP
	$this->{username} = $special_cfg{'u'} if $special_cfg{'u'};
	$this->{password} = $special_cfg{'v'} if $special_cfg{'v'};
	$this->{vrfy} = "PWD\r\n";

	# let's see if we got a correct login (skip if dump mode is set)
  if ($special_cfg{'d'}) { return; }
 	$iaddr = inet_aton($this->{target})             || die "Unknown host: $host\n";
	$paddr = sockaddr_in($this->{port}, $iaddr)     || die "getprotobyname: $!\n";
 	$proto = getprotobyname('tcp')                  || die "getprotobyname: $!\n";
 	socket(SOCKET, PF_INET, SOCK_STREAM, $proto)    || die "socket: $!\n";
 	connect(SOCKET, $paddr)				|| die "connection attempt failed: $!\n";
 	send(SOCKET, "USER $this->{username}\r\n", 0)   || die "USER failed: $!\n";
 	$recvbuf = <SOCKET>;
 	sleep(1);	# some ftp's need some time to reply
 	send(SOCKET, "PASS $this->{password}\r\n", 0)   || die "PASS failed: $!\n";
	do {
		$recvbuf = <SOCKET>;
		#print ($recvbuf);
		if ( $recvbuf =~ "530" ){
			print ("Username or Password incorrect, can't login\n");
			exit(1);
		}
		sleep(0.2);
	} until ( $recvbuf =~ "230" );
	send(SOCKET, "QUIT\r\n", 0);
	close(SOCKET);

}

sub getQuit{
	return("QUIT\r\n");
}

sub getLoginarray {
 my $this = shift;
 @Loginarray = (
  "XAXAX\r\n",
  "USER XAXAX\r\n",
  "USER XAXAX\r\nPASS password\r\n",
  "USER anonymous\r\nPASS XAXAX\r\n",
  "USER $this->{username}\r\nPASS XAXAX\r\n",
  "PASS XAXAX\r\n"
 );
 return (@Loginarray);
}

sub getCommandarray {
	my $this = shift;
	# the XAXAX will be replaced with the buffer overflow / format string
	# just comment them out if you don't like them..
	@cmdArray = (
    "XAXAX\r\n",
    "XAXAX 123\r\n",
    "ABOR XAXAX\r\n",
    "ACCL XAXAX\r\n",
		"ACCT XAXAX\r\n",
    "ALLO XAXAX\r\n",
		"APPE XAXAX\r\n",
    "CDUP XAXAX\r\n",
		"CWD XAXAX\r\n",
		"CEL XAXAX\r\n",
		"DELE XAXAX\r\n",
    "EPRT XAXAX\r\n",
    "EPRT |XAXAX|127.0.0.1|6275|\r\n",
    "EPRT |1|XAXAX|6275|\r\n",
    "EPRT |1|127.0.0.1|XAXAX|\r\n",
    "EPSV XAXAX\r\n",
    "FEAT XAXAX\r\n",
		"HELP XAXAX\r\n",
    "LIST XAXAX\r\n",
    "LOCK XAXAX\r\n",
    "LOCK / XAXAX\r\n",
		"MDTM XAXAX\r\n",
    "MDTM XAXAX file.txt\r\n",
    "MDTM 19990929043300 XAXAX\r\n",
    "MLST XAXAX\r\n",
		"MODE XAXAX\r\n",
		"MKD XAXAX\r\n",
		"MKD XAXAX\r\nCWD XAXAX\r\n",
		"MKD XAXAX\r\nDELE XAXAX\r\n",
		"MKD XAXAX\r\nRMD XAXAX\r\n",
		"MKD XAXAX\r\nXRMD XAXAX\r\n",
		"NLST XAXAX\r\n",
    "NOOP XAXAX\r\n",
    "OPTS XAXAX\r\n",
    "PASS XAXAX\r\n",
    "PASV XAXAX\r\n",
    "PORT XAXAX\r\n",
    "PWD XAXAX\r\n",
    "REIN XAXAX\r\n",
		"REST XAXAX\r\n",
		"RETR XAXAX\r\n",
    "RMD XAXAX\r\n",
		"RNFR XAXAX\r\n",
		"RNTO XAXAX\r\n",
		"RNFR XAXAX\r\nRNTO XAXAX\r\n",
		"SITE XAXAX\r\n",
		"SITE EXEC XAXAX\r\n",
		"SITE GROUPS XAXAX\r\n",
		"SITE CDPATH XAXAX\r\n",
		"SITE ALIAS XAXAX\r\n",
		"SITE INDEX XAXAX\r\n",
		"SITE MINFO 20001010101010 XAXAX\r\n",
		"SITE NEWER 20001010101010 XAXAX\r\n",
		"SITE GPASS XAXAX\r\n",
		"SITE GROUP XAXAX\r\n",
		"SITE HELP XAXAX\r\n",
		"SITE IDLE XAXAX\r\n",
		"SITE CHMOD XAXAX\r\n",
    "SITE CHMOD 777 XAXAX\r\n",
		"SITE UMASK XAXAX\r\n",
    "SIZE XAXAX\r\n",
    "SMNT XAXAX\r\n",
    "STOU XAXAX\r\n",
    "STRU XAXAX\r\n",
    "STOR XAXAX\r\n",
    "STAT XAXAX\r\n",
		"SYST XAXAX\r\n",
		"TYPE XAXAX\r\n",
    "USER XAXAX\r\n",
    "UNLOCK XAXAX\r\n",
    "UNLOCK / XAXAX\r\n",
    "XCUP XAXAX\r\n",
    "XCWD XAXAX\r\n",
    "XMKD XAXAX\r\n",
    "XPWD XAXAX\r\n",
		"XRMD XAXAX\r\n",
	);
	return(@cmdArray);
}

sub getLogin{ 		# login procedure
	my $this = shift;
	@login = ("USER $this->{username}\r\nPASS $this->{password}\r\n");
	return(@login);
}

sub testMisc{
	my $this = shift;
  return; # Directory traversal code is buggy an not really what I want
	# test for bof in login / user ?
	# test for the availability to abuse this host for portscanning ?

	# test for possible directory traversal bugs...
	print ("*Directory traversal\n");

	@traversal = ("...", "%5c..%5c", ,"%5c%2e%2e%5c", "/././..", "/...", "/......", "\\...", "...\\", "....", "*", "\\*", "\\....", "*\\\\.....", "/..../", "/../../../", "\\..\\..\\..\\", "\@/..\@/..");
	foreach $Directory (@traversal){
	 	$iaddr = inet_aton($this->{target})             || die "Unknown host: $host\n";
 		$paddr = sockaddr_in($this->{port}, $iaddr)       || die "getprotobyname: $!\n";
	 	$proto = getprotobyname('tcp')                  || die "getprotobyname: $!\n";
	 	socket(SOCKET, PF_INET, SOCK_STREAM, $proto)    || die "socket: $!\n";
	 	connect(SOCKET, $paddr)						 	|| die "connection attempt failed: $!\n";
	 	send(SOCKET, "USER $this->{username}\r\n", 0)   || die "USER failed: $!\n";
    sleep(2); # some ftp's need some time to reply  
	 	$recvbuf = <SOCKET>;
	 	send(SOCKET, "PASS $this->{password}\r\n", 0)   || die "PASS failed: $!\n";
    sleep(2); # some ftp's need some time to reply  
		$recvbuf = <SOCKET> 						    || die "Login failed $!\n";
	    send(SOCKET, "PWD\r\n", 0);                 # get old directory
      sleep(1);
	    $curDir = <SOCKET>;
    	send(SOCKET, "CWD $Directory\r\n", 0);	    # send the traversal string
    	# clear the buffer, by waiting for :
	    # 501 550 250 553
	    do { $recvbuf = <SOCKET>; } while( ($recvbuf !~ /550/) && ($recvbuf !~ /250/) && ($recvbuf !~ /553/) && ($recvbuf !~ /501/));	# receive answer
	    send(SOCKET, "PWD\r\n", 0);                 # get new directory
    	$newDir = <SOCKET>;
    	# compare the directories, and report a problem if they are not equal
    	if ( $curDir ne $newDir ){ print ("Directory Traversal ($curDir => $newDir) possible with $Directory \n"); }
    	send(SOCKET,"QUIT\r\n", 0);					# logout
    	close (SOCKET);							# close connection
	}
	return();
}

sub usage {
  print qq~ FTP Module specific options:
 -u <username> = Username to use for authentication (default: anonymous)
 -v <password> = Password to use for authentication (default: user\@this.bed)

~;
}

1;
