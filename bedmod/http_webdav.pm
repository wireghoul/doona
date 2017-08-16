package bedmod::http_webdav;
use Socket;

# This package is an extension to doona, to check
# for http server vulnerabilities.  Works as an extension to BED too
#
# Tests for WebDAV-specific request methods and request fields
# These aren't tested in the standard HTTP module.
#
# Modify as needed: might want to ensure the BCOPY requests a resource that exists
#
# The displayed output may not show particularly long commands (e.g. BPROPFIND /webpage.aspx) but 
# the right stuff is being sent
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
        "BCOPY /XAXAX/ HTTP/1.1\r\nHost: myserver.com\r\n\r\n",   
        "BDELETE /XAXAX/ HTTP/1.1\r\nHost: myserver.com\r\n\r\n",                 
        "BMOVE /XAXAX/ HTTP/1.1\r\nHost: myserver.com\r\n\r\n",          
        "BPROPFIND /XAXAX/ HTTP/1.1\r\nHost: myserver.com\r\n\r\n",      
        "BPROPPATCH /XAXAX/ HTTP/1.1\r\nHost: myserver.com\r\n\r\n",     
        "COPY /XAXAX.XAXAX HTTP/1.1\r\nHost: myserver.com\r\n\r\n",           
        "DELETE /XAXAX.XAXAX HTTP/1.1\r\nHost: myserver.com\r\n\r\n",           
        "LOCK /XAXAX.XAXAX HTTP/1.1\r\nHost: myserver.com\r\n\r\n",           
        "MKCOL /XAXAX/ HTTP/1.1\r\nHost: myserver.com\r\n\r\n",          
        "MOVE /XAXAX/ HTTP/1.1\r\nHost: myserver.com\r\n\r\n",            
        "NOTIFY http://XAXAX:80 HTTP/1.1\r\nHost: myserver.com\r\n\r\n",           
        "POLL /XAXAX/ HTTP/1.1\r\nHost: myserver.com\r\n\r\n",
        "PROPFIND /XAXAX.XAXAX HTTP/1.1\r\nHost: myserver.com\r\n\r\n",       
        "PROPPATCH /XAXAX.XAXAX HTTP/1.1\r\nHost: myserver.com\r\n\r\n",      
        "SEARCH /XAXAX/ HTTP/1.1\r\nHost: myserver.com\r\n\r\n",      
        "SUBSCRIBE /XAXAX HTTP/1.1\r\nHost: myserver.com\r\n\r\n",      
        "UNLOCK /XAXAX.XAXAX HTTP/1.1\r\nHost: myserver.com\r\n\r\n",         
        "UNSUBSCRIBE /XAXAX HTTP/1.1\r\nHost: myserver.com\r\n\r\n",      
        "X-MS-ENUMATTS /XAXAX.XAXAX HTTP/1.1\r\nHost: myserver.com\r\n\r\n",      
      );
    return (@Loginarray);
}

sub getCommandarray {
    my $this = shift;

    @cmdArray = (                               # These are commands specific to webdav.
        "Destination: XAXAX\r\nHost: myserver.com\r\n",           
        "Depth: XAXAX\r\nHost: myserver.com\r\n\r\n",
        "Brief: XAXAX\r\nHost: myserver.com\r\n\r\n",
        "Overwrite: XAXAX\r\nHost: myserver.com\r\n\r\n",
        "Timeout: XAXAX\r\nHost: myserver.com\r\n\r\n",
        "Location: XAXAX\r\nHost: myserver.com\r\n\r\n",
        "Subscription-id: XAXAX\r\nHost: myserver.com\r\n\r\n",
        "Translate: XAXAX\r\nHost: myserver.com\r\n\r\n",
        "Call-Back: XAXAX\r\nHost: myserver.com\r\n\r\n",
        "Lock-Token: XAXAX\r\nHost: myserver.com\r\n\r\n",
      );
    return(@cmdArray);
}

sub getLogin {
    my $this = shift;
    @login = (
        "BCOPY /webpage.aspx/ HTTP/1.1\r\n",   
        "BDELETE /webpage.aspx/ HTTP/1.1\r\n",                 
        "BMOVE /webpage.aspx/ HTTP/1.1\r\n",          
        "BPROPFIND /webpage.aspx/ HTTP/1.1\r\n",      
        "BPROPPATCH /webpage.aspx/ HTTP/1.1\r\n",     
        "COPY /webpage.aspx HTTP/1.1\r\n",           
        "DELETE /webpage.aspx HTTP/1.1\r\n",           
        "LOCK /webpage.aspx HTTP/1.1\r\n",           
        "MKCOL /webpage.aspx HTTP/1.1\r\n",          
        "MOVE /webpage.aspx HTTP/1.1\r\n",            
        "NOTIFY http://myserver.com:80 HTTP/1.1\r\n",           
        "POLL /webpage.aspx/ HTTP/1.1\r\n",
        "PROPFIND /webpage.aspx HTTP/1.1\r\n",       
        "PROPPATCH /webpage.aspx HTTP/1.1\r\n",      
        "SEARCH /webpage.aspx/ HTTP/1.1\r\n",      
        "SUBSCRIBE /webpage.aspx HTTP/1.1\r\n",      
        "UNLOCK /webpage.aspx HTTP/1.1\r\n",         
        "UNSUBSCRIBE /webpage.aspx HTTP/1.1\r\n",      
        "X-MS-ENUMATTS /webpage.aspx HTTP/1.1\r\n",      
      );
    return(@login);
}

sub testMisc {         #Put your corner case tests here
    my $this = shift;
    @cmdArray = (
        "BCOPY /webpage.aspx/ HTTP/1.1\r\nHost: myserver.com\r\n\r\n" . "Lotsofheaders: XAXAX\r\n" x 1024 . "\r\n",        
        "BDELETE /webpage.aspx/ HTTP/1.1\r\nHost: myserver.com\r\n\r\n" . "Lotsofheaders: XAXAX\r\n" x 1024 . "\r\n",        
        "BMOVE /webpage.aspx/ HTTP/1.1\r\nHost: myserver.com\r\n\r\n" . "Lotsofheaders: XAXAX\r\n" x 1024 . "\r\n",        
        "BPROPFIND /webpage.aspx/ HTTP/1.1\r\nHost: myserver.com\r\n\r\n" . "Lotsofheaders: XAXAX\r\n" x 1024 . "\r\n",        
        "COPY /webpage.aspx/ HTTP/1.1\r\nHost: myserver.com\r\n\r\n" . "Lotsofheaders: XAXAX\r\n" x 1024 . "\r\n",        
        "DELETE /webpage.aspx/ HTTP/1.1\r\nHost: myserver.com\r\n\r\n" . "Lotsofheaders: XAXAX\r\n" x 1024 . "\r\n",        
        "LOCK /webpage.aspx/ HTTP/1.1\r\nHost: myserver.com\r\n\r\n" . "Lotsofheaders: XAXAX\r\n" x 1024 . "\r\n",        
        "MKCOL /webpage.aspx/ HTTP/1.1\r\nHost: myserver.com\r\n\r\n" . "Lotsofheaders: XAXAX\r\n" x 1024 . "\r\n",        
        "MOVE /webpage.aspx/ HTTP/1.1\r\nHost: myserver.com\r\n\r\n" . "Lotsofheaders: XAXAX\r\n" x 1024 . "\r\n",        
        "NOTIFY /webpage.aspx/ HTTP/1.1\r\nHost: myserver.com\r\n\r\n" . "Lotsofheaders: XAXAX\r\n" x 1024 . "\r\n",        
        "POLL /webpage.aspx/ HTTP/1.1\r\nHost: myserver.com\r\n\r\n" . "Lotsofheaders: XAXAX\r\n" x 1024 . "\r\n",        
        "PROPFIND /webpage.aspx/ HTTP/1.1\r\nHost: myserver.com\r\n\r\n" . "Lotsofheaders: XAXAX\r\n" x 1024 . "\r\n",        
        "PROPPATCH /webpage.aspx/ HTTP/1.1\r\nHost: myserver.com\r\n\r\n" . "Lotsofheaders: XAXAX\r\n" x 1024 . "\r\n",        
        "SEARCH /webpage.aspx/ HTTP/1.1\r\nHost: myserver.com\r\n\r\n" . "Lotsofheaders: XAXAX\r\n" x 1024 . "\r\n",        
        "SUBSCRIBE /webpage.aspx/ HTTP/1.1\r\nHost: myserver.com\r\n\r\n" . "Lotsofheaders: XAXAX\r\n" x 1024 . "\r\n",        
        "UNLOCK /webpage.aspx/ HTTP/1.1\r\nHost: myserver.com\r\n\r\n" . "Lotsofheaders: XAXAX\r\n" x 1024 . "\r\n",        
        "UNSUBSCRIBE /webpage.aspx/ HTTP/1.1\r\nHost: myserver.com\r\n\r\n" . "Lotsofheaders: XAXAX\r\n" x 1024 . "\r\n",        
        "X-MS-ENUMATTS /webpage.aspx/ HTTP/1.1\r\nHost: myserver.com\r\n\r\n" . "Lotsofheaders: XAXAX\r\n" x 1024 . "\r\n",        
      );
    return(@cmdArray);
}

sub usage {
}

1;
