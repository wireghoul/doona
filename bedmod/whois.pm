package bedmod::whois;
use Socket;

# lame whois plugin :)

# create a new instance of this object
sub new {
    my $this = {};
    bless $this;
    return $this;
}

# initialise some parameters
sub init {
    my $this = shift;
    %special_cfg=@_;

    # Set protocol tcp/udp
    $this->{proto} = "tcp";

    if ($special_cfg{'p'} eq "") { $this->{port}='43'; }
    else { $this->{port} = $special_cfg{'p'}; }
    $this->{sport} = 0;
    $this->{vrfy} = "";
}

# how to quit ?
sub getQuit {
    return("");
}

# what to test without doing a login before
sub getLoginarray {
    my $this = shift;
    @Loginarray = ("");
    return (@Loginarray);
}

# which commands does this protocol know ?
sub getCommandarray {
    my $this = shift;

    # the XAXAX will be replaced with the buffer overflow / format string
    # place every command in this array you want to test
    @cmdArray = (
        "XAXAX\r\n",
        "?XAXAX\r\n",
        "!XAXAX\r\n",
        ".XAXAX\r\n",
        "XAXAX...\r\n",
        "*XAXAX\r\n",
        "XAXAX.tld\r\n",
        "domain.XAXAX\r\n"
      );
    return(@cmdArray);
}

# what to send to login ?
sub getLogin {
    my $this = shift;
    return("");
}

sub testMisc {
    my $this = shift;
    return();
}

sub usage {
}

1;
