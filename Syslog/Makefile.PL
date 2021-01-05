use ExtUtils::MakeMaker;
WriteMakefile(
    'NAME'        => 'Syslog::Secure',
    'VERSION_FROM'   => 'Secure.pm',
    'PREREQ_PM'      => {},
	 LIBS			=> ['-lssl -lcrypto'],
);

