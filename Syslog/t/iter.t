#!/usr/bin/perl

use Test;
BEGIN {
	plan tests => 1_702;
}

use Syslog::Secure;
my $key = "THIS_KEY";

for (1..1_000){
	my $enc = Syslog::Secure::sslEncrypt($key, $_);
   my $dec = Syslog::Secure::sslDecrypt($key, $enc);
	ok($_, $dec);
}

for ('A'..'zz'){
   my $enc = Syslog::Secure::sslEncrypt($key, $_);
   my $dec = Syslog::Secure::sslDecrypt($key, $enc);
   ok($_, $dec);
}

1;

