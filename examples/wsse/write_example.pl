#!/usr/bin/env perl
#
# This script demonstrates the hoops you have to jump to produce
# the wsse example as included in this directory.
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

# We need the SOAP info from WSS as well, not only the WSS itself
use XML::Compile::SOAP::WSS;
use XML::Compile::WSS::Util  qw/DSIG_RSA_SHA1 DSIG_SHA1
   WSSE_BASE64 WSSE_X509v3/;

# C14N info
use XML::Compile::C14N::Util qw/C14N_EXC_NO_COMM/;

# next modules for testing only
use HTTP::Response;
use HTTP::Status  qw/RC_OK/;
use Data::Dumper;
$Data::Dumper::Indent    = 1;
$Data::Dumper::Quotekeys = 0;

# The real work starts
my $myns = 'http://msgsec.wssecfvt.ws.ibm.com';
my $wsdl = XML::Compile::WSDL11->new('example.wsdl');
my $wss  = XML::Compile::SOAP::WSS->new(version => '1.1', schema => $wsdl);

#print Dumper $wsdl->prefixes;
#print $wsdl->template(PERL => "ds:Signature");
#print $wsdl->template(PERL => "wsse:BinarySecurityToken");
#print $wsdl->template(PERL => "wsse:SecurityTokenReference");
#$wsdl->namespaces->printIndex;

my $getVersion = $wsdl->compileClient
  ( 'version'
  , transport_hook => \&fake_server
  );

# For every example on internet, these tokens are using different
# constants :(  The example included here does not reflect the latest
# spec (which will be produced)
my $doc       = XML::LibXML::Document->new('1.0', 'UTF-8');
my $tokentype = $wsdl->findName('wsse:BinarySecurityToken');
my $sec_token = $wsdl->writer($tokentype)->($doc,
  { EncodingType => WSSE_BASE64
  , ValueType    => WSSE_X509v3
# , wsu_id       => 'x509cert00'
  , _            => 'encoded certificate'
  });

my $incns_type = $wsdl->findName('c14n:InclusiveNamespaces');
my $incns1     = $wsdl->writer($incns_type)->($doc
  , {PrefixList => 'wsu SOAP-ENV'});

# create reference to the body
my $the_body =
  { URI             => '#TheBody'
  , ds_Transforms   =>
      { ds_Transform =>
         [{ Algorithm => C14N_EXC_NO_COMM,
          , cho_any => [{ $incns_type => $incns1 }]
          }]
      }
  , ds_DigestMethod => { Algorithm => DSIG_SHA1 }
  , ds_DigestValue  => 'tic tac toe'
  };

my $keyreftype  = $wsdl->findName('wsse:Reference');
my $keyref      = $wsdl->writer($keyreftype)->($doc
  , {URI => '#x509cert00', ValueType => WSSE_X509v3});

my $keyinfotype = $wsdl->findName('wsse:SecurityTokenReference');
my $keyinfo     = $wsdl->writer($keyinfotype)->($doc
  , {cho_any => [{$keyreftype => $keyref}] });

my $incns2    = $wsdl->writer($incns_type)->($doc
  , {PrefixList => 'ds wsu xenc SOAP-ENV'});

my $sigtype   = $wsdl->findName('ds:Signature');
my $signature = $wsdl->writer($sigtype)->($doc,
  { ds_SignedInfo =>
     { ds_CanonicalizationMethod =>
         { Algorithm => C14N_EXC_NO_COMM, $incns_type => $incns2 }
     , ds_SignatureMethod => { Algorithm => DSIG_RSA_SHA1 }
     , ds_Reference       => [ $the_body ]
     }
  , ds_SignatureValue => { _ => 'aap noot mies' }
  , ds_KeyInfo        => { cho_ds_KeyName => [{$keyinfotype => $keyinfo}] }
  } );

my $security =
  { $tokentype => $sec_token
  , $sigtype   => $signature
  };

my ($data, $trace) = $getVersion->(wsse_Security => $security);
#print Dumper $data;
#print Dumper $trace;
exit 0;


#### HELPERS
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

    HTTP::Response->new
      ( RC_OK
      , 'answer manually created'
      , [ 'Content-Type' => 'text/xml' ]
      , $answer
      );
}

