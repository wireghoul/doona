package bedmod::nntp;
use Socket;

# This package is an extension to bed, to check
# for NNTP server vulnerabilities.

sub new {
    my $this = {};
    $this->{username} = 'anonymous'; # specific for just this
    $this->{password} = 'password';  # module
    bless $this;
    return $this;
}

sub init {
    my $this = shift;
    %special_cfg=@_;

    $this->{proto}="tcp";

    if ($special_cfg{'p'} eq "") { $this->{port}='119'; }
    else { $this->{port} = $special_cfg{'p'}; }
    $this->{vrfy} = "HELP\r\n";

    $this->{username} = $special_cfg{'u'} if $special_cfg{'u'};
    $this->{password} = $special_cfg{'v'} if $special_cfg{'v'};

    # let's see if we got a correct login (skip if dump mode is set)
    if ($special_cfg{'d'}) { return; }
    $iaddr = inet_aton($this->{target})             || die "Unknown host: $this->{target}\n";
    $paddr = sockaddr_in($this->{port}, $iaddr)     || die "getprotobyname: $!\n";
    $proto = getprotobyname('tcp')                  || die "getprotobyname: $!\n";
    socket(SOCKET, PF_INET, SOCK_STREAM, $proto)    || die "socket: $!\n";
    connect(SOCKET, $paddr)                         || die "connection attempt failed: $!\n";
    send(SOCKET, "authinfo user $this->{username}\r\n", 0) || die "Username failed: $!\n";
    $recvbuf = <SOCKET>;
    sleep(1);
    send(SOCKET, "authinfo pass $this->{password}\r\n", 0) || die "Password failed: $!\n";
    do {
        $recvbuf = <SOCKET>;
        print ($recvbuf);
        if ( $recvbuf =~ "452" ) {
            print ("Username or password incorrect, can't login\n");
            exit(1);
        }
        sleep(0.2);
    # 281 Authorization accepted
    } until ( $recvbuf =~ "281" );
    send(SOCKET, "QUIT\r\n", 0);
    close(SOCKET);
}

sub getQuit {
    return("QUIT\r\n");
}

sub getLoginarray {
    my $this = shift;
    @Loginarray = (
        "XAXAX\r\n",
        "authinfo XAXAX\r\n",
        "authinfo XAXAX XAXAX\r\n",
        "authinfo user XAXAX\r\nXAXAX\r\n",
        "authinfo user XAXAX\r\nauthinfo pass XAXAX\r\n",
        "authinfo user $this->{username}\r\nauthinfo pass XAXAX\r\n",
        "authinfo pass XAXAX\r\n",
        "authinfo simple XAXAX\r\n",
        "authinfo simple\r\nXAXAX XAXAX\r\n",
        "authinfo simple\r\n$this->{username} XAXAX\r\n",
        "authinfo generic XAXAX\r\n",
        "authinfo generic XAXAX XAXAX\r\n"
      );
    return (@Loginarray);
}

sub getCommandarray {
    my $this = shift;

    # the XAXAX will be replaced with the buffer overflow / format string
    # just comment them out if you don't like them..
    @cmdArray = (
        "XAXAX\r\n",
        "authinfo XAXAX\r\n",
        "authinfo XAXAX XAXAX\r\n",
        "authinfo user XAXAX\r\nXAXAX\r\n",
        "authinfo user XAXAX\r\nauthinfo pass XAXAX\r\n",
        "authinfo user $this->{username}\r\nauthinfo pass XAXAX\r\n",
        "authinfo pass XAXAX\r\n",
        "authinfo simple XAXAX\r\n",
        "authinfo simple\r\nXAXAX XAXAX\r\n",
        "authinfo simple\r\n$this->{username} XAXAX\r\n",
        "authinfo generic XAXAX\r\n",
        "authinfo generic XAXAX XAXAX\r\n",
        "article XAXAX\r\n",
        "body XAXAX\r\n",
        "charset XAXAX\r\n",
        "check XAXAX\r\n",
        "group XAXAX\r\n",
        "head XAXAX\r\n",
        "help XAXAX\r\n",
        "ihave XAXAX\r\n",
        "list XAXAX\r\n",
        "list active XAXAX\r\n",
        "list newsgroups XAXAX\r\n",
        "listgroup XAXAX\r\n",
        "mode XAXAX\r\n",
        "mode stream XAXAX\r\n",
        "mode reader XAXAX\r\n",
        "newgroups XAXAX XAXAX XAXAX XAXAX\r\n",
        "newnews XAXAX XAXAX XAXAX XAXAX XAXAX\r\n",
        "stat XAXAX\r\n",
        "takethis XAXAX\r\n",
        "xgtitle XAXAX\r\n",
        "xhdr XAXAX\r\n",
        "xhdr header XAXAX\r\n",
        "xindex XAXAX\r\n",
        "xover XAXAX\r\n",
        "xover XAXAX\r\n",
        "xpat XAXAX XAXAX XAXAX XAXAX\r\n",
        "xpath XAXAX\r\n",
        "xreplic XAXAX\r\n",
        "xthread XAXAX\r\n",
        "xgtitle\r\n"
      );
    return(@cmdArray);
}

sub getLogin {       # login procedure
    my $this = shift;
    @login = ("authinfo user $this->{username}\r\nauthinfo pass $this->{password}\r\n");
    return(@login);
}

sub testMisc {
    return();
}

sub usage {
    print qq~ NNTP module specific options:
 -u <username> = Username to use for authentication (default: anonymous)
 -v <password> = Password to use for authentication (default: password)

~;
}

1;
