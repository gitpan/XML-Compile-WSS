# Copyrights 2011-2012 by [Mark Overmeer].
#  For other contributors see ChangeLog.
# See the manual pages for details on the licensing terms.
# Pod stripped from pm file by OODoc 2.00.
use warnings;
use strict;

package XML::Compile::SOAP::WSS;
use vars '$VERSION';
$VERSION = '1.00';

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
    # [1.0] wsse needed for backward compat functions
    $wsdl->prefixes('SOAP-ENV' => SOAP11ENV, wsse => WSSE_10);
    $self;
}

sub soap11OperationInit($$)
{   my ($self, $op, $args) = @_;

    trace "adding wss header logic";  # get full type from any schema
    my $sec = $self->schema->findName('wsse:Security');
    $op->addHeader(INPUT  => "wsse_Security" => $sec);
    $op->addHeader(OUTPUT => "wsse_Security" => $sec);
}

sub soap11ClientWrapper($$$)
{   my ($self, $op, $call, $args) = @_;
    # Add empty security object, otherwise hooks will not get called.
    # May get overwritten by user supplied element or sublist of wss's.
    sub { $call->(wsse_Security => $self->{XCSW_wss}, @_) };
}

#---------------------------

sub schema()     {shift->{XCSW_schema}}
sub wssConfigs() { @{shift->{XCSW_wss}} }
sub addWSS($) { my ($wss, $n) = (shift->{XCSW_wss}, shift); push @$wss, $n; $n }

#---------------------------

sub _start($$)
{   my ($self, $plugin, $args) = @_;

    eval "require $plugin";
    panic $@ if $@;

    my $schema = $args->{schema} ||= $self->schema
        or error __x"instantiate {pkg} before the wsdl, plugins after"
             , pkg => __PACKAGE__;

    $self->addWSS($plugin->new($args));
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
          $xml->setNamespace(SOAP11ENV, 'SOAP-ENV', 0);
          $sig->signElement($xml, id => 'TheBody');
          $xml;
     }};
    $schema->declare(WRITER => 'SOAP-ENV:Envelope', hooks => $sign_body);

    # We can only sign then all prefixes in Body are declared in Body
    $schema->declare(WRITER => 'SOAP-ENV:Body', include_namespaces => 1);

    my $check_body =
     +{ type     => 'SOAP-ENV:Body'
      , before => sub {
          my ($node, $path) = @_;
          $sig->checkDigest($node);
          $node;
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
   $auth->process($doc, {});
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
   $ts->process($doc, {});
}
 

1;
