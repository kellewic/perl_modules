#!/usr/bin/perl

use Test;
BEGIN {
	plan tests => 3002;
}

use Syslog::Secure;
ok(1);

my $key = "THIS_KEY";
my $data = "This is some test data 1234567890";

my $cgi = new Syslog::Secure;
ok(1);

for (1..1_000){
	my $enc = $cgi->encrypt($cgi->encodebytes($data), $key);
	ok(1);

	my $dec = $cgi->decodebytes($cgi->decrypt($enc, $key));
	ok(1);

	ok($data, $dec);
}

1;

