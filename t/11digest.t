#!/usr/bin/env perl
# Basically just ensure that examples/usertoken/with_help_digest.pl will work.

use warnings;
use strict;

use Test::More tests => 32;

use MIME::Base64            qw/decode_base64/;

use XML::Compile::WSDL11;
use XML::Compile::SOAP11;
use XML::Compile::Transport::SOAPHTTP;
use XML::Compile::SOAP::WSS;
use XML::Compile::WSS::Util qw/:wss11 :utp11/;

use XML::LibXML::XPathContext;

my $myns   = 'http://msgsec.wssecfvt.ws.ibm.com';
my ($username, $password, $operation) = qw/username password version/;
my $usernameId  = 'foo';
my $timestampId = 'baz';
my $nonce   = 'insecure';
my $now     = '2012-08-17T12:02:26Z';
my $then    = '2012-08-17T12:02:31Z';
#my $now = time;
#my $then = $now + 30;

my $wss     = XML::Compile::SOAP::WSS->new;
my $wsdl    = XML::Compile::WSDL11->new('t/example.wsdl');

my $getVersion = $wsdl->compileClient($operation
  , transport_hook => \&test_server);

my $auth = $wss->basicAuth
  ( username => $username
  , password => $password
  , pwformat => UTP11_PDIGEST
  , nonce    => $nonce
  , created  => $now
  , wsu_Id   => $usernameId
  );
ok($auth, 'Created basic-auth object');

my $ts = $wss->timestamp
  ( created => $now
  , expires => $then
  , wsu_Id  => $timestampId
  );
ok($auth, 'Created Timestamping object');

=pod
my $getVersion = $wsdl->compileClient
  ( $operation

  # to overrule server as in wsdl, for testing only
  , transport_hook => \&test_server
  );
=cut

ok($getVersion, "$operation compiled with test server");
my $theCorrectAnswer = 42;
my ($answer, $trace) = $getVersion->();

is( $answer->{body}, $theCorrectAnswer, 'Round-trip to server worked' );
# print $trace->printRequest;
# use Data::Dumper;
# print Dumper $answer;

{
    # Ticket 79315 notes that "text" passwords just skip Nonce and
    # Created.  This seems like a reasonable place to check that
    my $auth2  = $wss->basicAuth
      ( schema   => $wsdl
      , username => $username
      , password => $password
      , pwformat => UTP11_PTEXT
      , nonce    => $nonce
      , created  => $now
      , wsu_Id   => $usernameId
      );

    ok($auth2, 'PasswordText returns something sensible');
    
    my ($answer, $trace) = $getVersion->(wsse_Security => [$auth2, $ts]);
    is($answer->{body}, $theCorrectAnswer, 'Round-trip to server worked');
}

#### HELPERS, for testing only

sub test_server
{   my ($request, $trace) = @_;
    my $content = $request->decoded_content;

#warn $content;
    eval {
      my $contentDoc = XML::LibXML->load_xml( string => $content );
      ok( $contentDoc, 'Content is parseable' );

      my $xpc       = XML::LibXML::XPathContext->new;
      $xpc->registerNs( 'wsu'  => WSU_10 );
      $xpc->registerNs( 'wsse' => WSSE_10 );

      my ($securityElt, @extras) = $xpc->findnodes( '//wsse:Security', $contentDoc );
      ok( $securityElt, 'Security element is present' );
      is( @extras, 0, 'There is only one security element' );

      my ($unTokenElt) = $xpc->findnodes( 'wsse:UsernameToken', $securityElt );
      ok( $unTokenElt, 'UsernameToken is present' );

      ok( $unTokenElt->hasAttributeNS(WSU_10,'Id'), 'wsse:UsernameToken/@wsu:Id is present' );
      is( $unTokenElt->getAttributeNS(WSU_10,'Id'), $usernameId, 'UsernameToken has the right ID' );
      # Search for Nonce
      my ($nonceElt) = $xpc->findnodes( 'wsse:UsernameToken/wsse:Nonce', $securityElt );
      ok( $nonceElt, 'Nonce element exists' );
      is( decode_base64($nonceElt->textContent), $nonce, 'Nonce is the right encoding' );

      my ($createdElt) = $xpc->findnodes( 'wsse:UsernameToken/wsu:Created', $securityElt );
      ok( $createdElt, 'Created element exists under UsernameToken' );
      is( $createdElt->textContent, $now, 'Created element has the right content' );

      # Search for wsu:Timestamp
      my ($tsElt) = $xpc->findnodes( '//wsu:Timestamp', $contentDoc );
      ok( $tsElt, 'Timestamp element exists' );

      # Search for wsu:Timestamp/@wsu:Id
      ok( $tsElt->hasAttributeNS(WSU_10,'Id'), 'wsu:Timestamp/@wsu:Id is present' );
      is( $tsElt->getAttributeNS(WSU_10,'Id'), $timestampId, 'Timestamp has the right ID' );
    } || diag( "Something went wrong with the content: $!" );

    my $answer = <<_ANSWER;
<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope
   xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
   xmlns:x0="$myns">
  <SOAP-ENV:Body>
     <x0:hasVersion>$theCorrectAnswer</x0:hasVersion>
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
