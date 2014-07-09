package bedmod::dict;
use Socket;

# This package is an extension to BED, to check
# for DICT server vulnerabilities.

# Authentication is not implemented for this module.
# There's a bunch of placeholders which will help
# should you wish to implement authentication.
# For more information, review:
# - RFC 2229 (DICT) - section 3.11 - The AUTH Command
# - RFC 1939 (POP) - section 4 - The AUTHORIZATION State

sub new {
    my $this = {};
    # Authentication is not implemented for this module.
    # These default values are used to fuzz auth verbs:
    $this->{username} = 'anonymous';
    $this->{password} = 'password';
    bless $this;
    return $this;
}

sub init {
    my $this = shift;
    %special_cfg=@_;

    $this->{proto}="tcp";

    if ($special_cfg{'p'} eq "") { $this->{port}='2628'; }
    else { $this->{port} = $special_cfg{'p'}; }
    $this->{vrfy} = "HELP\r\n";

    # Authentication is not implemented for this module.
    # This is a placeholder
    $this->{username} = $special_cfg{'u'} if $special_cfg{'u'};
    $this->{password} = $special_cfg{'v'} if $special_cfg{'v'};

    # Test connection to target (skip if dump mode is set)
    if ($special_cfg{'d'}) { return; }
    $iaddr = inet_aton($this->{target})          || die "Unknown host: $this->{target}\n";
    $paddr = sockaddr_in($this->{port}, $iaddr)  || die "getprotobyname: $!\n";
    $proto = getprotobyname('tcp')               || die "getprotobyname: $!\n";
    socket(SOCKET, PF_INET, SOCK_STREAM, $proto) || die "socket: $!\n";
    connect(SOCKET, $paddr)                      || die "connection attempt failed: $!\n";
    # Authentication is not implemented for this module.
    # so we grab the banner instead
    send(SOCKET, "\r\n", 0);
    $recvbuf = <SOCKET>;
    print ($recvbuf);

    # The psuedo-code below checks if the server requires authentication.
    #send(SOCKET, "AUTH $this->{username} md5(<timestamp@host>$this->{password})\r\n", 0) || die "Authentication failed: $!\n";
    #do {
    #    $recvbuf = <SOCKET>;
    #    print ($recvbuf);
    #    if ( $recvbuf =~ "530" ) {
    #        print ("Access is denied, can't login\n");
    #        exit(1);
    #    }
    #    if ( $recvbuf =~ "531" ) {
    #        print ("Username or password incorrect, can't login\n");
    #        exit(1);
    #    }
    #    sleep(0.2);
    ## 230 Authentication successful
    #} until ( $recvbuf =~ "230" );
    #send(SOCKET, "QUIT\r\n", 0);
    close(SOCKET);
}

sub getQuit {
    return("QUIT\r\n");
}

sub getLoginarray {
    my $this = shift;
    # Authentication is not implemented for this module.
    # so we return an empty string
    return ("");
    # This is a placeholder
    @Loginarray = (
        "XAXAX\r\n",
        "AUTH XAXAX\r\n",
        "AUTH XAXAX XAXAX\r\n",
        "AUTH $this->{username} XAXAX\r\n",
        "SASLAUTH XAXAX\r\nSASLRESP XAXAX\r\n",
        "SASLAUTH XAXAX XAXAX\r\nSASLRESP XAXAX\r\n"
      );
    return (@Loginarray);
}

sub getCommandarray {
    my $this = shift;

    # the XAXAX will be replaced with the buffer overflow / format string
    # just comment them out if you don't like them.
    @cmdArray = (
        "XAXAX\r\n",
        "AUTH XAXAX\r\n",
        "AUTH XAXAX XAXAX\r\n",
        "AUTH $this->{username} XAXAX\r\n",
        "SASLAUTH XAXAX\r\nSASLRESP XAXAX\r\n",
        "SASLAUTH XAXAX XAXAX\r\nSASLRESP XAXAX\r\n",
        "DEFINE ! XAXAX\r\n",
        "DEFINE XAXAX XAXAX\r\n",
        "MATCH ! XAXAX XAXAX\r\n",
        "MATCH XAXAX XAXAX XAXAX\r\n",
        "SHOW XAXAX\r\n",
        "SHOW INFO XAXAX\r\n",
        "CLIENT XAXAX\r\n",
        "OPTION XAXAX\r\n"
      );
    return(@cmdArray);
}

sub getLogin {
    my $this = shift;
    # Authentication is not implemented for this module.
    # so we return an empty string
    @login = "";
    return(@login);
    # This is a placeholder
    @login = ("AUTH $this->{username} $this->{password}\r\n");
    return(@login);
}

sub testMisc {
    return();
}

sub usage {
    print qq~ DICT module specific options:
 -u <username> = Username to use for authentication (default: anonymous)
 -v <password> = Password to use for authentication (default: password)

~;
}

1;
