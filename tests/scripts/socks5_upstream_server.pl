#!/usr/bin/perl -w

# Minimal SOCKS5 upstream proxy mock for tinyproxy regression tests.
#
# It implements just enough of RFC 1928 (SOCKS5) and RFC 1929 (username /
# password authentication) to exercise tinyproxy's upstream SOCKS5 client,
# and to assert on the exact bytes tinyproxy sends during the handshake.
#
# The behaviour is selected with --mode:
#
#   auth            Require that the client offered username/password auth,
#                   select it, then verify that the RFC 1929 credentials
#                   match --expect-user / --expect-pass *exactly* (including
#                   the single length octets).  This catches truncated or
#                   mis-encoded credentials.  On success it completes the
#                   CONNECT and answers the proxied request with "200 OK".
#
#   force-userpass  Select username/password auth (method 0x02) regardless
#                   of what the client offered.  A correct client that did
#                   not advertise that method must abort the handshake; if
#                   it instead starts authenticating, that is a failure.
#
#   noauth          Select "no authentication" and complete the CONNECT.
#
# The outcome is written as a single line ("OK: ..." or "FAIL: ...") to
# --result-file so the driving shell script can assert on it.
#
# Copyright (C) 2026 Tinyproxy contributors
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation; either version 2 of the License, or (at your option)
# any later version.

use strict;
use warnings;
use IO::Socket::INET;
use IO::Select;
use Getopt::Long;

my $port        = 0;
my $mode        = "auth";
my $expect_user = "";
my $expect_pass = "";
my $result_file = "";
my $ready_file  = "";
my $timeout     = 15;

GetOptions(
    "port=i"        => \$port,
    "mode=s"        => \$mode,
    "expect-user=s" => \$expect_user,
    "expect-pass=s" => \$expect_pass,
    "result-file=s" => \$result_file,
    "ready-file=s"  => \$ready_file,
    "timeout=i"     => \$timeout,
) or die "invalid command line options";

$| = 1;

sub finish {
    my ($status) = @_;
    if ($result_file ne "") {
        if (open(my $fh, ">", $result_file)) {
            print $fh $status, "\n";
            close($fh);
        }
    }
    warn "[socks5-mock] $status\n";
    exit($status =~ /^OK/ ? 0 : 1);
}

# Read exactly $n bytes (with a per-read timeout). Returns undef on EOF,
# error or timeout, which the caller turns into a diagnosed failure.
sub read_exact {
    my ($sock, $n) = @_;
    my $buf = "";
    my $sel = IO::Select->new($sock);
    while (length($buf) < $n) {
        my @ready = $sel->can_read($timeout);
        return undef unless @ready;
        my $chunk;
        my $got = sysread($sock, $chunk, $n - length($buf));
        return undef if !defined($got) || $got == 0;
        $buf .= $chunk;
    }
    return $buf;
}

# Bound the whole lifetime so a misbehaving client can never hang the suite
# (in particular accept() below has no timeout of its own).
$SIG{ALRM} = sub { finish("FAIL: mock timed out"); };
alarm($timeout * 2 + 5);

my $server = IO::Socket::INET->new(
    Proto     => "tcp",
    LocalAddr => "127.0.0.1",
    LocalPort => $port,
    Listen    => 1,
    ReuseAddr => 1,
) or die "cannot listen on 127.0.0.1:$port: $!";

if ($ready_file ne "") {
    if (open(my $fh, ">", $ready_file)) { print $fh "ready\n"; close($fh); }
}
warn "[socks5-mock] listening on 127.0.0.1:" . $server->sockport
   . " mode=$mode\n";

my $client = $server->accept() or finish("FAIL: accept failed");
$client->autoflush(1);

# ---- SOCKS5 greeting / method selection (RFC 1928) ----
my $greet = read_exact($client, 2);
finish("FAIL: short greeting")            unless defined $greet;
my ($ver, $nmethods) = unpack("CC", $greet);
finish("FAIL: bad version $ver in greeting") unless $ver == 5;
my $methods = read_exact($client, $nmethods);
finish("FAIL: short method list")         unless defined $methods;
my %offered = map { $_ => 1 } unpack("C*", $methods);

if ($mode eq "force-userpass") {
    # Select a method the client may never have offered.
    syswrite($client, pack("CC", 5, 2));
    my $next = read_exact($client, 1);
    if (!defined $next) {
        finish("OK: client aborted after server selected an unoffered method");
    }
    finish("FAIL: client kept going after unoffered method (byte="
           . unpack("C", $next) . ")");
}

if ($mode eq "noauth") {
    syswrite($client, pack("CC", 5, 0));
} else {
    # auth mode
    finish("FAIL: client did not offer username/password auth")
        unless $offered{2};
    syswrite($client, pack("CC", 5, 2));

    # ---- RFC 1929 username/password sub-negotiation ----
    my $ah = read_exact($client, 2);
    finish("FAIL: short auth header")          unless defined $ah;
    my ($av, $ulen) = unpack("CC", $ah);
    finish("FAIL: bad auth version $av")       unless $av == 1;
    my $user = $ulen ? read_exact($client, $ulen) : "";
    finish("FAIL: short username")             unless defined $user;
    my $pl = read_exact($client, 1);
    finish("FAIL: short password length")      unless defined $pl;
    my $plen = unpack("C", $pl);
    my $pass = $plen ? read_exact($client, $plen) : "";
    finish("FAIL: short password")             unless defined $pass;

    if ($ulen != length($expect_user) || $user ne $expect_user) {
        syswrite($client, pack("CC", 1, 1));
        finish("FAIL: username mismatch (got ulen=$ulen, expected "
               . length($expect_user) . ")");
    }
    if ($plen != length($expect_pass) || $pass ne $expect_pass) {
        syswrite($client, pack("CC", 1, 1));
        finish("FAIL: password mismatch (got plen=$plen, expected "
               . length($expect_pass) . ")");
    }
    syswrite($client, pack("CC", 1, 0));   # auth success
}

# ---- SOCKS5 CONNECT request ----
my $req = read_exact($client, 4);
finish("FAIL: short CONNECT request")     unless defined $req;
my ($cv, $cmd, $rsv, $atyp) = unpack("CCCC", $req);
finish("FAIL: bad version $cv in CONNECT") unless $cv == 5;
if    ($atyp == 1) { finish("FAIL: short IPv4 addr") unless defined read_exact($client, 4); }
elsif ($atyp == 4) { finish("FAIL: short IPv6 addr") unless defined read_exact($client, 16); }
elsif ($atyp == 3) {
    my $dl = read_exact($client, 1);
    finish("FAIL: short domain length") unless defined $dl;
    finish("FAIL: short domain")        unless defined read_exact($client, unpack("C", $dl));
}
else { finish("FAIL: unsupported address type $atyp"); }
finish("FAIL: short port") unless defined read_exact($client, 2);

# success, bound address 0.0.0.0:0
syswrite($client, pack("CCCC", 5, 0, 0, 1) . pack("Nn", 0, 0));

# ---- Act as the destination origin so the proxied request completes ----
my $sel = IO::Select->new($client);
if ($sel->can_read($timeout)) {
    my $junk;
    sysread($client, $junk, 65536);
}
my $body = "tinyproxy-socks5-ok";
syswrite($client,
      "HTTP/1.0 200 OK\r\n"
    . "Content-Type: text/plain\r\n"
    . "Content-Length: " . length($body) . "\r\n"
    . "Connection: close\r\n"
    . "\r\n"
    . $body);
close($client);
finish("OK: authenticated and connected");
