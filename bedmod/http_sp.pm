package bedmod::http_sp;
use Socket;

# This package is an extension to doona, to check
# for http server vulnerabilities.  Works as an extension to BED too
#
# Tests for request methods and request fields specific to SharePoint
#
# The displayed output may not show particularly long commands but 
# the right stuff is being sent
#
# Might want to mod, depending on desired results.  For example, do a GET on an existing resource
#
# Written by Grid

sub new {
    my $this = {};
    bless $this;
    return $this;
}

sub init {
    my $this = shift;
    %special_cfg=@_;

    $this->{proto}="tcp";

    if ($special_cfg{'p'} eq "") {
        $this->{port}='80';
    } else {
        $this->{port} = $special_cfg{'p'};
    }

    if ($special_cfg{'d'}) { return; }
    $iaddr = inet_aton($this->{target})             || die "Unknown host: $host\n";
    $paddr = sockaddr_in($this->{port}, $iaddr)     || die "getprotobyname: $!\n";
    $proto = getprotobyname('tcp')                  || die "getprotobyname: $!\n";
    socket(SOCKET, PF_INET, SOCK_STREAM, $proto)    || die "socket: $!\n";
    connect(SOCKET, $paddr)                         || die "connection attempt failed: $!\n";
    send(SOCKET, "HEAD / HTTP/1.0\r\n\r\n", 0)      || die "HTTP request failed: $!\n";
}

sub health_check {
    my $this = shift;
    $iaddr = inet_aton($this->{target})             || die "Unknown host: $this->{target}\n";
    $paddr = sockaddr_in($this->{port}, $iaddr)     || die "getprotobyname: $!\n";
    $proto = getprotobyname('tcp')                  || die "getprotobyname: $!\n";
    socket(SOCKET, PF_INET, SOCK_STREAM, $proto)    || die "socket: $!\n";
    connect(SOCKET, $paddr)                         || die "connection attempt failed: $!\n";
    send(SOCKET, "HEAD / HTTP/1.0\r\n\r\n", 0)      || die "HTTP request failed: $!\n";
    my $resp = <SOCKET>;
    if (!$this->{healthy}) {
          if ($resp =~ /HTTP/) {
              $this->{healthy}=$resp;
          }
          # print "Set healthy: $resp";
    }
    return $resp =~ m/^$this->{healthy}$/;
}

sub getQuit {
    return("\r\n\r\n");
}

sub getLoginarray {
    my $this = shift;
    @Loginarray = (
        "GET /default.XAXAX HTTP/1.1\r\nHost: 192.168.43.128\r\n\r\n",
        "GET /XAXAX.html HTTP/1.1\r\nHost: 192.168.43.128\r\n\r\n",
      );
    return (@Loginarray);
}

sub getCommandarray {
    my $this = shift;

    @cmdArray = (
        "x-virus-infected: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "x-irm-cantdecrypt: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "x-irm-rejected: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "x-irm-notowner: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "x-irm-timeout: XAXAX\r\nHost: 192.168.43.128\r\n",
        "x-irm-crashed: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "x-irm-unknown-failure: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "SharePointError: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-RequestDigest: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-Forms_Based_Auth_Required: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-Forms_Based_Auth_Return_Url: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",       
        "X-MS-File-Checked-Out: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-RequestToken: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "SPRequestGuid: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-UseWebLanguage: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-RequestForceAuthentication: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-SharePointHealthScore: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-MS-InvokeApp: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
      );
    return(@cmdArray);
}

sub getLogin {
    my $this = shift;
    @login = (
        "GET / HTTP/1.1\r\n",
      );
    return(@login);
}

sub testMisc {         #Put your corner case tests here
    my $this = shift;
    @cmdArray = (
        "GET / HTTP/1.1\r\nHost: 192.168.43.128\r\n\r\n" . "Lotsofheaders: XAXAX\r\n" x 1024 . "\r\n",
      );
    return(@cmdArray);
}

sub usage {
}

1;
