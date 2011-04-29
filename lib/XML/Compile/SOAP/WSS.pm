# Copyrights 2011 by Mark Overmeer.
#  For other contributors see ChangeLog.
# See the manual pages for details on the licensing terms.
# Pod stripped from pm file by OODoc 2.00.
use warnings;
use strict;

package XML::Compile::SOAP::WSS;
use vars '$VERSION';
$VERSION = '0.11';

use base 'XML::Compile::WSS', 'XML::Compile::SOAP::Extension';

use Log::Report 'xml-compile-wss';

use XML::Compile::WSS::Util ':wss11';
#use XML::Compile::SOAP::Util qw/WSDL11/;


sub init($)
{   my ($self, $args) = @_;
    $self->XML::Compile::WSS::init($args);
    $self->XML::Compile::SOAP::Extension::init($args);
}

sub wsdl11Init($$)
{   my ($self, $wsdl, $args) = @_;

    # When no new(schema) is given, we need to load the schemas now
    $self->schema || $self->loadSchemas($wsdl);
}

sub soap11OperationInit($$)
{   my ($self, $op, $args) = @_;

    trace "adding wss header logic";
    my $sec = $self->schema->findName('wsse:Security');
    $op->addHeader(INPUT  => "wsse_Security" => $sec);
    $op->addHeader(OUTPUT => "wsse_Security" => $sec);
}

1;
