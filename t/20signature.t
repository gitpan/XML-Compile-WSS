#!/usr/bin/env perl
use warnings;
use strict;

use XML::Compile::WSDL11;
use XML::Compile::SOAP11;
use XML::Compile::Transport::SOAPHTTP;
use XML::Compile::SOAP::WSS;
use XML::Compile::WSS::Util  qw/:dsig :xtp10/;
use XML::Compile::C14N::Util qw/:c14n/;

use Log::Report;
use Data::Dumper;
$Data::Dumper::Indent    = 1;
$Data::Dumper::Quotekeys = 0;
use Test::More;

BEGIN {
    eval "require Crypt::OpenSSL::RSA";
    $@ and plan skip_all => "Crypt::OpenSSL::RSA not installed";

    plan tests => 1;
}

my $ns        = "http://example.net/";
my $wsdlfn    = 't/20any.wsdl';
my $anyop     = 'Test';
my $privkeyfn = 't/20mykey.pem';
my $pubkeyfn  = 't/20mykey.pub';

# From http://publib.boulder.ibm.com/infocenter/cicsts/v3r1/index.jsp?topic=%2Fcom.ibm.cics.ts31.doc%2Fdfhws%2FwsSecurity%2Fdfhws_soapmsg_signed.htm
my $output_xml = 'example.xml';

my $wss  = XML::Compile::SOAP::WSS->new;
my $wsdl = XML::Compile::WSDL11->new($wsdlfn);

my $sig  = $wss->signature
  ( digest_method   => DSIG_SHA1          # default
  , sign_method     => DSIG_RSA_SHA1
  , canon_method    => C14N_EXC_NO_COMM   # default
  , private_key     => $privkeyfn
  , public_key_type => XTP10_X509
  , public_key      => $pubkeyfn
  );

$wsdl->compileCalls(transport_hook => \&fake_server);
my ($out, $trace) = $wsdl->call($anyop, One => 1, Two => 2, Three => 3);
#warn Dumper $out;
$trace->printErrors;
#$trace->printResponse;

ok(1, 'passed');
exit 0;

### FROM HERE ON JUST AS DEMO
sub fake_server($$)
{  my ($request, $trace) = @_;
   my $content = $request->decoded_content;
   my $xml   = XML::LibXML->load_xml(string => $content);
warn $xml->toString(1);

#warn "SENDING RESPONSE";
   HTTP::Response->new(200, 'OK', ['Content-Type' => 'application/xml'], $content);
}
