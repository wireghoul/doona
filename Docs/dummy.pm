package bedmod::dummy;
use Socket;

# Example plugin for a doona module
# Replace the use of "dummy" with your module name
# Copy the file to bedmod as <modulename.pm>
#

# create a new instance of this object
sub new{
    my $this = {};

    # define everything you might need
    $this->{something} = undef;
    bless $this;
    return $this;
}

# initialise some parameters
sub init{
    my $this = shift;
    %special_cfg=@_;

    # Set protocol tcp/udp
    $this->{proto} = "tcp";

    # insert your default port here...
    if ($special_cfg{'p'} eq "") { $this->{port}='110'; }
      else { $this->{port} = $special_cfg{'p'}; }

    # verify you got everything you need,
    # $special_cfg will provide you the commandline
    # switches from u, v, w and x
    if ( $special_cfg{'u'} eq "") {
        &usage;
    }

    # set info necessary for for your module..
    $this->{u} = $special_cfg{'u'};

    # check that the server is still alive
    die "Server failed health check!\n" unless($this->health_check());
}

# Perform a common action such as authenticating here
# if it this check assume it has crashed
sub health_check {
    # Should send/receive packet and match expected behaviour to be considered healthy
    # return true to continue fuzzing
    return 1;
}

# how to quit ?
sub getQuit{
    # what to send to close the connection the right way
    return("QUIT\r\n");
}

# what to test without authenticating
# Typically the login stuff
sub getLoginarray {
    my $this = shift;
    @Loginarray = (
        "USER XAXAX\r\n",
        "USER $this->{username}\r\nPASS XAXAX\r\n"
    );
    return (@Loginarray);
}


# which commands does this protocol know ?
sub getCommandarray {
    my $this = shift;
    # the XAXAX will be replaced with the buffer overflow / format string data
    # place every command in this array you want to test
    @cmdArray = (
        "foo XAXAX\r\n",
        "bar XAXAX\r\n",
        "XAXAX\r\n"
    );
    return(@cmdArray);
}


# what to send to login ?
sub getLogin{    # login procedure
    my $this = shift;
    @login = (
        "Hi, I am a dummy\r\n",
        "This is my pass: foobar\r\n"
    );
    return(@login);
}

# here we can test everything besides buffer overflows and format strings
sub testMisc{
    # Insert your favourite directory traversal bug here :)
    my $this = shift;
    return();
}

# Module specific help goes here
# Leave an empty sub if there is no module specific help
sub usage {
    print qq~
  Parameters for the dummy plugin:

    -u <description what the user should provide>
~;
exit(1);
}

1;
