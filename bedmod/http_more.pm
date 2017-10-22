package bedmod::http_more;
use Socket;

# This package is an extension to doona, to check
# for http server vulnerabilities.
#
# Tests for request methods and request fields not tested in the standard http module

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
        "CONNECT XAXAX:80 HTTP/1.1\r\n\r\n",
        "CONNECT 192.168.43.128/home:XAXAX HTTP/1.1\r\n\r\n",
        "PATCH /XAXAX HTTP/1.1\r\nHost: 192.168.43.128\r\n\r\n",          
      );
    return (@Loginarray);
}

sub getCommandarray {
    my $this = shift;

    @cmdArray = (
        "Accept-Datetime: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "Cache-Control: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "Content-MD5: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "Content-Type: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "Date: XAXAX\r\n\r\n",
        "Forwarded: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "Origin: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "Via: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "Warning: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-Requested-With: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "DNT: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",       
        "X-Forwarded-For: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-Forwarded-Host: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-Forwarded-Proto: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "Front-End-Https: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-Http-Method-Override: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-Att-Deviceid: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-Wap-Profile: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "Proxy-Connection: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-UIDH: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-Csrf-Token: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",        
      );
    return(@cmdArray);
}

sub getLogin {
    my $this = shift;
    @login = (        
        "CONNECT 192.168.43.128:80 HTTP/1.1\r\n",
        "PATCH /default.html HTTP/1.1\r\n",
      );
    return(@login);
}

sub testMisc {         #Put your corner case tests here
    my $this = shift;
    @cmdArray = (      
        "CONNECT 192.168.43.128:80 HTTP/1.1\r\n" . "Lotsofheaders: XAXAX\r\n" x 1024 . "\r\n",
        "PATCH / HTTP/1.1\r\nHost: 192.168.43.128\r\n\r\n" . "Lotsofheaders: XAXAX\r\n" x 1024 . "\r\n",
      );
    return(@cmdArray);
}

sub usage {
}

1;
