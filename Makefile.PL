use ExtUtils::MakeMaker;

use 5.008;

WriteMakefile
 ( NAME	 	=> 'XML::Compile::WSS'
 , VERSION	=> '0.91'

 , PREREQ_PM    =>
     { XML::Compile         => '1.21'
     , XML::Compile::Cache  => '0.99'
     , XML::Compile::C14N   => '0.10'
     , XML::Compile::SOAP   => '2.23'
     , Log::Report          => '0.92'

     , Digest::SHA1         => 0
     , Encode               => 0
     , Test::More           => 0.54
     , File::Basename       => 0
     , MIME::Base64         => 0
     }
 , EXE_FILES    => []
 , AUTHOR       => 'Mark Overmeer'
 , ABSTRACT     => 'OASIS Web Services Security'
 , LICENSE      => 'perl'
 );

### used by oodist during production of distribution
sub MY::postamble { <<'__POSTAMBLE' }

# for DIST
RAWDIR          = ../public_html/xml-compile-wss/raw
DISTDIR         = ../public_html/xml-compile-wss/source
LICENSE         = artistic

# for POD
FIRST_YEAR      = 2011
EMAIL           = perl@overmeer.net
EXTENDS         = ../XMLCompile:../XMLCache:../XMLC14N
WEBSITE         = http://perl.overmeer.net/xml-compile/
PODTAIL		= ../XML-shared-podtail
__POSTAMBLE
