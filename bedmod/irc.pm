package bedmod::irc;
use Socket;

# This package is an extension to bed, to check
# for irc server vulnerabilities.

sub new {
    my $this = {};
    bless $this;
    return $this;
}

sub init {
    my $this = shift;
    %special_cfg=@_;

    $this->{proto}="tcp";

    if ($special_cfg{'p'} eq "") { $this->{port}='6667'; }
    else { $this->{port} = $special_cfg{'p'}; }
    $this->{vrfy} = "uk\r\n"; # server should reply with unknown command
}

sub getQuit {
    return("QUIT\r\n");
}

sub getLoginarray {
    my $this = shift;
    @Loginarray = (
        "XAXAX\r\n",
        "USER XAXAX 0 cc :dd\r\n",
        "USER aa XAXAX cc :dd\r\n",
        "USER aa 0 XAXAX :dd\r\n",
        "USER aa 0 cc :XAXAX\r\n",
        "USER aa 0 cc XAXAX\r\n",
        "USER aa 0 cc :dd XAXAX\r\n", # realname may contain spaces
        "USER aa 0 cc :dd\r\nNICK XAXAX\r\n",
        "NICK XAXAX\r\n",
        "PASS XAXAX\r\n",
        "PASS aa\r\nPASS XAXAX\r\n",
        "PASS XAXAX\r\nUSER aa 0 cc :dd\r\n",
        "PASS XAXAX\r\nNICK XAXAX\r\nUSER XAXAX XAXAX XAXAX XAXAX\r\n",
        "PASS XAXAX\r\nSERVER aa bb cc\r\n",
        "SERVER XAXAX bb cc\r\n",
        "SERVER aa XAXAX cc\r\n",
        "SERVER aa bb XAXAX\r\n",
      );
    return (@Loginarray);
}

sub getCommandarray {
    my $this = shift;

    # the XAXAX will be replaced with the buffer overflow / format string
    # just comment them out if you don't like them..
    @cmdArray = (
        "XAXAX\r\n",
        "NICK XAXAX\r\n",
        "JOIN XAXAX\r\n",
        "PART XAXAX\r\n",
        "SERVER XAXAX 1 :foobar\r\n",
        "SERVER test XAXAX :foobar\r\n",
        "SERVER test 1 :XAXAX\r\n",
        "OPER XAXAX\r\n",
        "OPER test XAXAX\r\n",
        "JOIN #XAXAX\r\n",
        "JOIN #test XAXAX\r\n",
        "JOIN \&XAXAX\r\n",
        "JOIN \&test XAXAX\r\n",
        "PART #XAXAX\r\n",
        "PART #foo XAXAX\r\n",
        "JOIN #XAXAX\r\nPART#XAXAX\r\n",
        "LIST XAXAX\r\n",
        "INVITE XAXAX #test\r\n",
        "INVITE foo #XAXAX\r\n",
        "KICK #XAXAX bar\r\n",
        "VERSION XAXAX\r\n",
        "MOTD XAXAX\r\n",
        "MODE XAXAX\r\n",
        "MODE XAXAX foo\r\n",
        "MODE foo XAXAX\r\n",
        "NAMES XAXAX\r\n",
        "STATS XAXAX\r\n",
        "STATS c XAXAX\r\n",
        "STATS h XAXAX\r\n",
        "STATS i XAXAX\r\n",
        "STATS k XAXAX\r\n",
        "STATS l XAXAX\r\n",
        "STATS m XAXAX\r\n",
        "STATS o XAXAX\r\n",
        "STATS y XAXAX\r\n",
        "STATS u XAXAX\r\n",
        "LINKS XAXAX\r\n",
        "TIME XAXAX\r\n",
        "CONNECT XAXAX\r\n",
        "TRACE XAXAX\r\n",
        "ADMIN XAXAX\r\n",
        "INFO XAXAX\r\n",
        "PRIVMSG foo XAXAX\r\n",
        "PRIVMSG XAXAX bar\r\n",
        "NOTICE foo XAXAX\r\n",
        "NOTICE XAXAX bar\r\n",
        "TOPIC XAXAX foo\r\n",
        "WHO XAXAX\r\n",
        "WHOIS XAXAX\r\n",
        "WHOWAS XAXAX\r\n",
        "WHOWAS foo 1 XAXAX\r\n",
        "KILL foo XAXAX\r\n",
        "KILL XAXAX bar\r\n",
        "PING XAXAX\r\n",
        "PONG XAXAX\r\n",
        "ERROR XAXAX\r\n",
        "AWAY XAXAX\r\n",
        "SUMMON XAXAX\r\n",
        "SUMMON foo XAXAX\r\n",
        "USERS XAXAX\r\n",
        "WALLOPS XAXAX\r\n",
        "USERHOST XAXAX\r\n",
        "ISON XAXAX\r\n"
      );
    return(@cmdArray);
}

sub getLogin {
    my $this = shift;
    @login = ("USER aaa bbb ccc :ddd\r\n", "NICK EEEEEE\r\n");
    return(@login);
}

sub testMisc {
    return();
}

sub usage {
}

1;
