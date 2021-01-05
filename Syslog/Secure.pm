package Syslog::Secure;

require DynaLoader;
our $VERSION = '1.0';
our @ISA = qw(DynaLoader);
bootstrap Syslog::Secure $VERSION;

use Storable qw(freeze thaw);

sub new {
   my $class = shift;

   bless {
   }, ref $class || $class;
}


sub encrypt {
   my ($self, $enc, $KEY) = @_;
	$KEY ||= "PASSWORD";

	my $fr = freeze([$enc]);
	$fr =~ s/@{[chr(0)]}/:::/sg;
	my $data = sslEncrypt($KEY, "FrOzEn$fr");

   $data =~ s/\+/^/g;
   $data =~ s/=/*/g;
   $data =~ s/\//!/g;
   $data =~ s/\n/./g;

   return $data;
}


sub decrypt {
   my ($self, $data, $KEY) = @_;
	$KEY ||= "PASSWORD";

	$data =~ s/\^/+/g;
	$data =~ s/\*/=/g;
	$data =~ s/!/\//g;
	$data =~ s/\./\n/g;

  	$data = sslDecrypt($KEY, $data);

  	if ($data =~ s/^FrOzEn//){
     	$data =~ s/:::/chr(0)/sge;
     	eval { ($data) = thaw $data; };
  	}

   if ($@){
      return undef;
   }
   else{
		if (exists $data->[0]){
			return $data->[0];
		}
		else{
			return $data;
		}
   }
}

1;
__END__

