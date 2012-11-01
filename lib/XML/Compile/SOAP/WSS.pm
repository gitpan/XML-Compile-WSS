# Copyrights 2011-2012 by [Mark Overmeer].
#  For other contributors see ChangeLog.
# See the manual pages for details on the licensing terms.
# Pod stripped from pm file by OODoc 2.00.
use warnings;
use strict;

package XML::Compile::SOAP::WSS;
use vars '$VERSION';
$VERSION = '1.05';

use base 'XML::Compile::SOAP::Extension';

use Log::Report 'xml-compile-wss';

use XML::Compile::WSS::Util  qw/:wss11 :utp11/;
use XML::Compile::WSS        ();
use XML::Compile::SOAP::Util qw/SOAP11ENV/;


sub init($)
{   my ($self, $args) = @_;
    $self->SUPER::init($args);
    $self->{XCSW_wss} = [];
    my $schema = $self->{XCSW_schema} = $args->{schema};

    # [1.0] to support backwards compat
    XML::Compile::WSS->loadSchemas($schema, '1.1') if $schema;
    $self;
}

sub wsdl11Init($$)
{   my ($self, $wsdl, $args) = @_;
    $self->SUPER::wsdl11Init($wsdl, $args);

    $self->{XCSW_schema} = $wsdl;
    XML::Compile::WSS->loadSchemas($wsdl, '1.1');
    $wsdl->prefixes('SOAP-ENV' => SOAP11ENV);

    $self;
}

sub soap11OperationInit($$)
{   my ($self, $op, $args) = @_;

    my $schema = $self->schema
        or error __x"WSS not connected to the WSDL: WSS needs to be instantiated
before the WSDL because it influences its interpretation";

    trace "adding wss header logic";  # get full type from any schema
    my $sec = $schema->findName('wsse:Security');
    $op->addHeader(INPUT  => "wsse_Security" => $sec, mustUnderstand => 1);
    $op->addHeader(OUTPUT => "wsse_Security" => $sec, mustUnderstand => 1);
}

sub soap11ClientWrapper($$$)
{   my ($self, $op, $call, $args) = @_;
    # Add empty security object, otherwise hooks will not get called.
    # May get overwritten by user supplied element or sublist of wss's.
    sub {
        my %data = @_;
        my $sec  = $data{wsse_Security};
        return $call->(%data)
            if ref $sec eq 'HASH';

        my $wss  = $sec || $self->{XCSW_wss};
        my @wss  = ref $wss eq 'ARRAY' ? @$wss : $wss;
        my $secw = $data{wsse_Security} = {};

        my $doc  = $data{_doc} ||= XML::LibXML::Document->new('1.0','UTF-8');
        $_->create($doc, $secw) for @wss;
 
        my ($answer, $trace) = $call->(%data);
        if(defined $answer)
        {   my $secr = $answer->{wsse_Security} ||= {};
            $_->check($secr) for @wss;
        }
 
        wantarray ? ($answer, $trace) : $answer;
    };
}

#---------------------------

sub schema()   { shift->{XCSW_schema} }
sub features() { @{shift->{XCSW_wss}} }
sub addFeature($)
{   my ($wss, $n) = (shift->{XCSW_wss}, shift);
    push @$wss, $n;
    $n;
}

#---------------------------

sub _start($$)
{   my ($self, $plugin, $args) = @_;

    eval "require $plugin";
    panic $@ if $@;

    my $schema = $args->{schema} ||= $self->schema
        or error __x"instantiate {pkg} before the wsdl, plugins after"
             , pkg => __PACKAGE__;

    $self->addFeature($plugin->new($args));
}


sub basicAuth(%)
{   my ($self, %args) = @_;
    $self->_start('XML::Compile::WSS::BasicAuth', \%args);
}


sub timestamp(%)
{   my ($self, %args) = @_;
    $self->_start('XML::Compile::WSS::Timestamp', \%args);
}


sub signature(%)
{   my ($self, %args) = @_;
    my $schema = $args{schema} || $self->schema;
    my $sig    = $self->_start('XML::Compile::WSS::Signature', \%args);

    my $sign_body =
     +{ type     => 'SOAP-ENV:Body'
      , after    => sub {
          my ($doc, $xml) = @_;

          # This is called twice, caused by the trick to get first the
          # body than the header processed when writing an envelope.
          # The second time, the signature element is already prepared,
          # no signing skipped.
          $sig->signElement($xml, id => 'TheBody');  # returns a fixed elem
          $sig->createSignature($doc);
          $xml;
     }};
    $schema->declare(WRITER => 'SOAP-ENV:Envelope', hooks => $sign_body);

    my $check_body =
     +{ type   => 'SOAP-ENV:Body'
      , before => sub {
          my ($node, $path) = @_;
          $sig->checkElement($node);
      }};
    $schema->declare(READER => 'SOAP-ENV:Envelope', hooks => $check_body);

    $sig;
}

#--------------------------------------
# [1.0] Expired interface
sub wsseBasicAuth($$$@)
{   my ($self, $username, $password, $pwtype, %args) = @_;
    # use XML::Compile::WSS::BasicAuth!!!  The method will be removed!

    eval "require XML::Compile::WSS::BasicAuth";
    panic $@ if $@;

    my $auth = XML::Compile::WSS::BasicAuth->new
      ( username  => $username
      , password  => $password
      , pwformat  => $pwtype || UTP11_PTEXT
      , %args
      , schema    => $self->schema
      );

   my $doc  = XML::LibXML::Document->new('1.0', 'UTF-8');
   $auth->create($doc, {});
}

# [1.0] Expired interface
sub wsseTimestamp($$$@)
{   my ($self, $created, $expires, %args) = @_;
    # use XML::Compile::WSS::Timestamp!!!  The method will be removed!

    eval "require XML::Compile::WSS::Timestamp";
    panic $@ if $@;

    my $ts = XML::Compile::WSS::Timestamp->new
      ( created => $created 
      , expires => $expires
      , %args
      , schema  => $self->schema
      );

   my $doc  = XML::LibXML::Document->new('1.0', 'UTF-8');
   $ts->create($doc, {});
}
 

1;