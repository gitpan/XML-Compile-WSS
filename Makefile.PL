use ExtUtils::MakeMaker;

use 5.008;

WriteMakefile
 ( NAME	 	=> 'XML::Compile::WSS'
 , VERSION	=> '1.07'

 , PREREQ_PM    =>
     { XML::Compile         => '1.29'
     , XML::Compile::Cache  => '0.992'
     , XML::Compile::SOAP   => '2.33'
     , Log::Report          => '0.92'

     , Encode               => 0
     , Test::More           => 0.54
     , File::Basename       => 0
     , MIME::Base64         => 0
     , Digest::SHA          => 0
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
EXTENDS         = ../XMLCompile:../XMLCache:../XMLC14N:../WSSSIG
WEBSITE         = http://perl.overmeer.net/xml-compile/
PODTAIL		= ../XML-shared-podtail
__POSTAMBLE
