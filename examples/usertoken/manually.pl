#!/usr/bin/env perl
# This script demonstrates how to create username/password authentication
# by hand. Take a look at the with_help.pl example!

# Sadly, the WSS standard was written before the schema syntax
# received the substitutionGroup mechanism. Therefore. it uses
# "any" and "mixed" a lot. This means that application writers
# have to do a lot of manual work and read the specification for
# correct use.

use warnings;
use strict;

use XML::Compile::WSDL11;
use XML::Compile::SOAP11;
use XML::Compile::Transport::SOAPHTTP;
#use Log::Report mode => 3;

use XML::Compile::SOAP::WSS;

# next modules for testing only
use Data::Dumper;
$Data::Dumper::Indent    = 1;
$Data::Dumper::Quotekeys = 0;

# Configuration
my $myns   = 'http://msgsec.wssecfvt.ws.ibm.com';
my $wsdlfn = '../wsse/example.wsdl';
my ($username, $password, $operation) = qw/username password version/;

# The real work starts
my $wss  = XML::Compile::SOAP::WSS->new(version => '1.1');
my $wsdl = XML::Compile::WSDL11->new($wsdlfn);


my $getVersion = $wsdl->compileClient
  ( $operation

  # to overrule server as in wsdl, for testing only
  , transport_hook => \&fake_server
  );

# We want all components to be build with the same document instance,
# to avoid character-set problems
my $doc    = XML::LibXML::Document->new('1.0', 'UTF-8');

# The security information uses "any" everywhere, which makes it
# difficult to process automatically. The password in this case is
# a nested(!) any within the usernameToken, which is an any itself
# within the Security. Ugly. Very much pre-substitutionGroups.

#print $wsdl->template(PERL => 'wsse:Password');
my $pwtype = $wsdl->findName('wsse:Password');
my $pwnode = $wsdl->writer($pwtype)->($doc, $password);

#print $wsdl->template(PERL => 'wsse:UsernameToken');
my $untype = $wsdl->findName('wsse:UsernameToken');
my $token  = $wsdl->writer($untype)->($doc
  , { wsse_Username  => $username, $pwtype => $pwnode } );

# You can probably reuse the same security info for each call.
my $security = { $untype => $token };

# You will usually change the payload of the message. The explain()
# will tell you how it looks.
#print $wsdl->explain($operation, PERL => 'INPUT', recurse => 1);
my %payload  = ();

my ($answer, $trace) = $getVersion->
  ( _doc => $doc
  , wsse_Security => $security
  , %payload
  );

#print Dumper $answer;
#print Dumper $trace;
print $trace->printRequest;
#print $trace->printResponse;

exit 0;


#### HELPERS, for testing only

sub fake_server($$)
{   my ($request, $trace) = @_;
    my $content = $request->decoded_content;
    $content =~ s/></>\n</g;
    print $content;

    my $answer = <<_ANSWER;
<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope
   xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
   xmlns:x0="$myns">
  <SOAP-ENV:Body>
     <x0:hasVersion>3.14</x0:hasVersion>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
_ANSWER

    use HTTP::Response;

    HTTP::Response->new
      ( HTTP::Status::RC_OK
      , 'answer manually created'
      , [ 'Content-Type' => 'text/xml' ]
      , $answer
      );
}

