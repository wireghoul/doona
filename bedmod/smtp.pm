package bedmod::smtp;
use Socket;

# This package is an extension to bed, to check
# for smtp server vulnerabilities.

sub new {
    my $this = {};
    bless $this;
    return $this;
}

sub init {
    my $this = shift;
    %special_cfg=@_;

    $this->{proto}="tcp";

    # check for missing args, set target and host
    if ($special_cfg{'p'} eq "") { $this->{port}='25'; }
    else { $this->{port} = $special_cfg{'p'}; }

    if ( $special_cfg{'u'} eq "") {
        &usage();
        exit(1);
    }

    # get info nessecairy for FTP
    $this->{mail} = $special_cfg{'u'};
    $this->{vrfy} = "HELP\r\n";
}

sub getQuit{
    return("QUIT\r\n");
}

sub getLoginarray {
    return(
        "XAXAX\r\n",
        "HELO XAXAX\r\n",
        "EHLO XAXAX\r\n",
        "HELP XAXAX\r\n",
    );
}

sub getCommandarray {
    my $this = shift;

    # the XAXAX will be replaced with the buffer overflow / format string
    # just comment them out if you don't like them..
    @cmdArray = (
        "EXPN XAXAX\r\n",
        "MAIL FROM: XAXAX\r\n",
        "MAIL FROM: <XAXAX>\r\n",
        "MAIL FROM: <$this->{mail}> XAXAX\r\n",
        "MAIL FROM: <$this->{mail}> RET=XAXAX\r\n",
        "MAIL FROM: <$this->{mail}> ENVID=XAXAX\r\n",
        "ETRN XAXAX\r\n",
        "ETRN \@XAXAX\r\n",
        "MAIL FROM: <$this->{mail}>\r\nRCPT TO: <XAXAX>\r\n",
        "MAIL FROM: <$this->{mail}>\r\nRCPT TO: <$mailaccount> XAXAX\r\n",
        "MAIL FROM: <$this->{mail}>\r\nRCPT TO: <$mailaccount> NOTIFY=XAXAX\r\n",
        "MAIL FROM: <$this->{mail}>\r\nRCPT TO: <$mailaccount> ORCPT=XAXAX\r\n",
        "HELP XAXAX\r\n",
        "VRFY XAXAX\r\n",
        "RCTP TO: XAXAX\r\n",
        "RCTP TO: <XAXAX>\r\n",
        "RCPT TO: <$mailaccount> XAXAX\r\n",
        "RCPT TO: <$mailaccount> NOTIFY=XAXAX\r\n",
        "RCPT TO: <$mailaccount> ORCPT=XAXAX\r\n",
        "RSET XAXAX\r\n",
        "AUTH mechanism XAXAX\r\n",
        "DATA XAXAX\r\n",
        "DATA\r\nXAXAX\r\n.",
        "XAXAX\r\n"
      );
    return(@cmdArray);
}

sub getLogin {
    my $this = shift;
    @login = (
        "HELO doona.pl\r\n",
        "EHLO doona.pl\r\n",
    );
    return(@login);
}

sub testMisc {
    my $this = shift;
    return();
}

sub usage {
    print qq~ Parameters for the SMTP plugin:

  -u <valid mail address at target host>

~;
}

1;
