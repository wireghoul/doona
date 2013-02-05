package bedmod::http;
use Socket;

# This package is an extension to bed, to check
# for http server vulnerabilities.

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
    $this->{port}='80'; 
  } else { 
    $this->{port} = $special_cfg{'p'};
  }

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
	"XAXAX / HTTP/1.0\r\n\r\n",
  "HEAD XAXAX HTTP/1.0\r\n\r\n",
  "HEAD /XAXAX HTTP/1.0\r\n\r\n",
  "HEAD / XAXAX\r\n\r\n",
  "GET XAXAX HTTP/1.0\r\n\r\n",
  "GET /XAXAX HTTP/1.0\r\n\r\n",
  "GET / XAXAX\r\n\r\n",
  "GET /XAXAX\r\n\r\n",
  "POST XAXAX HTTP/1.0\r\n\r\n",
  "POST /XAXAX HTTP/1.0\r\n\r\n",
  "POST / XAXAX\r\n\r\n",
  "POST /XAXAX\r\n\r\n",
  "POST / HTTP/1.0\r\n\r\nXAXAX\r\n\r\n",
  "POST / HTTP/1.0\r\nContent-length: 10\r\n\r\nXAXAX\r\n\r\n",
  "POST / HTTP/1.0\r\nContent-Type: multipart/form-data; boundary=---XAXAX\r\n\r\n---XAXAX--\r\n\r\n",
  "POST / HTTP/1.0\r\nContent-Type: multipart/form-data; boundary=---AAAAA\r\n\r\n---AAAAA\r\nContent-Disposition: form-data; name=\"XAXAX\"\r\n\r\ntest\r\n---AAAAA--\r\n\r\n",
  "POST / HTTP/1.0\r\nContent-Type: multipart/form-data; boundary=---AAAAA\r\n\r\n---AAAAA\r\nContent-Disposition: form-data; name=\"test\"\r\n\r\nXAXAX\r\n---AAAAA--\r\n\r\n",
	"OPTIONS XAXAX HTTP/1.0\r\n\r\n",
	"OPTIONS /XAXAXHTTP/1.0\r\n\r\n",
	"OPTIONS / XAXAX\r\n\r\n",
 );
 return (@Loginarray);
}

sub getCommandarray {
	my $this = shift;

	@cmdArray = (
		"User-Agent: XAXAX\r\n\r\n", 
		"Host: XAXAX\r\n\r\n", 
		"Accept: XAXAX\r\n\r\n",
		"Accept-Encoding: XAXAX\r\n\r\n",
		"Accept-Language: XAXAX\r\n\r\n",
		"Accept-Charset: XAXAX\r\n\r\n",
		"Connection: XAXAX\r\n\r\n",
		"Referer: XAXAX\r\n\r\n",
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
		"Content-Length: XAXAX\r\n\r\n",
		"Cookie: XAXAX\r\n\r\n",
		"TE: XAXAX\r\n\r\n",
		"Upgrade: XAXAX\r\n\r\n",
	);
	return(@cmdArray);
}

sub getLogin{
	my $this = shift;
	@login = ("GET / HTTP/1.0\r\n");
	return(@login);
}

sub testMisc{
 return();
}


1;
