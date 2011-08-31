#!/usr/bin/env perl
# This script demonstrates how to create username/password authentication
# with help of the wsseBasicAuth() method

use warnings;
use strict;

use XML::Compile::WSDL11;
use XML::Compile::SOAP11;
use XML::Compile::Transport::SOAPHTTP;
#use Log::Report mode => 3;

use XML::Compile::SOAP::WSS;


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

# You can probably reuse the same security info for each call.
my $security = $wss->wsseBasicAuth($username, $password);

# You will usually change the payload of the message. The explain()
# will tell you how it looks.
#print $wsdl->explain($operation, PERL => 'INPUT', recurse => 1);
my %payload  = ();

my ($answer, $trace) = $getVersion->
  ( wsse_Security => $security
  , %payload
  );

print $trace->printRequest;
#print $trace->printResponse;

#use Data::Dumper;
#$Data::Dumper::Indent    = 1;
#$Data::Dumper::Quotekeys = 0;
#print Dumper $answer;
#print Dumper $trace;

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

