package bedmod::proxy;
use Socket;

# This package is an extension to bed, to check
# for http proxy server vulnerabilities.

sub new{
	my $this = {};
	bless $this;
	return $this;
}

sub init{
	my $this = shift;
	%special_cfg=@_;

	$this->{proto}="tcp";
	
  if ($special_cfg{'p'} eq "") {
    $this->{port}='8080'; 
  } else { 
    $this->{port} = $special_cfg{'p'};
  }

  if ($special_cfg{'d'}) { return; }
 	$iaddr = inet_aton($this->{target})             || die "Unknown host: $host\n";
	$paddr = sockaddr_in($this->{port}, $iaddr)     || die "getprotobyname: $!\n";
 	$proto = getprotobyname('tcp')                  || die "getprotobyname: $!\n";
 	socket(SOCKET, PF_INET, SOCK_STREAM, $proto)    || die "socket: $!\n";
 	connect(SOCKET, $paddr)				|| die "connection attempt failed: $!\n";
 	send(SOCKET, "HEAD / HTTP/1.0\r\n\r\n", 0)   	|| die "HTTP request failed: $!\n";
}

sub getQuit{
	return("\r\n\r\n");
}

sub getLoginarray {
 my $this = shift;
 @Loginarray = (
  "XAXAX\r\n\r\n",
  "XAXAX http://127.0.0.2/ HTTP/1.0\r\n\r\n",
  "HEAD http://XAXAX/ HTTP/1.0\r\n\r\n",
  "HEAD http://127.0.0.2:XAXAX/ HTTP/1.0\r\n\r\n",
  "HEAD http://127.0.0.2/XAXAX HTTP/1.0\r\n\r\n",
  "HEAD http://127.0.0.2/ XAXAX\r\n\r\n",
  "GET http://XAXAX/ HTTP/1.0\r\n\r\n",
  "GET http://127.0.0.2:XAXAX/ HTTP/1.0\r\n\r\n",
  "GET http://127.0.0.2/XAXAX HTTP/1.0\r\n\r\n",
  "GET http://127.0.0.2/ XAXAX\r\n\r\n",
  "CONNECT XAXAX HTTP/1.0\r\n\r\n",
  "CONNECT XAXAX:80 HTTP/1.0\r\n\r\n",
  "CONNECT 127.0.0.2:XAXAX HTTP/1.0\r\n\r\n",
  "CONNECT 127.0.0.2:80 XAXAX\r\n\r\n",
 );
 return (@Loginarray);
}

sub getCommandarray {
	my $this = shift;

	@cmdArray = (
    "XAXAX: XAXAX\r\n\r\n",
		"User-Agent: XAXAX\r\n\r\n",
		"Host: XAXAX\r\n\r\n",
    "Host: XAXAX:80\r\n\r\n",
    "Host: somehost:XAXAX\r\n\r\n",
		"Accept: XAXAX\r\n\r\n",
		"Accept-Encoding: XAXAX\r\n\r\n",
		"Accept-Language: XAXAX\r\n\r\n",
		"Accept-Charset: XAXAX\r\n\r\n",
		"Connection: XAXAX\r\n\r\n",
		"Referer: XAXAX\r\n\r\n",
    "Referer: XAXAX://somehost.com/\r\n\r\n",
    "Referer: http://XAXAX/\r\n\r\n",
    "Referer: http://somehost.com/XAXAX\r\n\r\n",
		"Authorization: XAXAX\r\n\r\n",
		"From: XAXAX\r\n\r\n",
		"Charge-To: XAXAX\r\n\r\n",
    "Authorization: XAXAX",
		"Authorization: XAXAX : foo\r\n\r\n",
		"Authorization: foo : XAXAX\r\n\r\n",
		"If-Modified-Since: XAXAX\r\n\r\n",
		"If-Match: XAXAX\r\n\r\n",
		"If-None-Match: XAXAX\r\n\r\n",
		"If-Range: XAXAX\r\n\r\n",
		"If-Unmodified-Since: XAXAX\r\n\r\n",
		"Max-Forwards: XAXAX\r\n\r\n",
		"Proxy-Authorization: XAXAX\r\n\r\n",
		"ChargeTo: XAXAX\r\n\r\n",
		"Pragma: XAXAX\r\n\r\n",
		"Expect: XAXAX\r\n\r\n",
		"Range: XAXAX\r\n\r\n",
    "Range: bytes=1-XAXAX\r\n\r\n",
    "Range: bytes=0-1,XAXAX\r\n",
		"Content-Length: XAXAX\r\n\r\n",
		"Cookie: XAXAX\r\n\r\n",
		"TE: XAXAX\r\n\r\n",
		"Upgrade: XAXAX\r\nConnection: upgrade\r\n\r\n",
	);
	return(@cmdArray);
}

sub getLogin{
	my $this = shift;
	@login = (
    "GET http://localhost/ HTTP/1.0\r\n",
  );
	return(@login);
}

sub testMisc{ #Put your corner case tests here...
  my $this = shift;
  @cmdArray = (
    "GET / HTTP/1.0\r\n" . "Lotsofheaders: XAXAX\r\n" x 1024 . "\r\n"
  );
  return(@cmdArray);
}

sub usage {
}

1;
