# Copyrights 2011 by Mark Overmeer.
#  For other contributors see ChangeLog.
# See the manual pages for details on the licensing terms.
# Pod stripped from pm file by OODoc 2.00.
use warnings;
use strict;

package XML::Compile::WSS;
use vars '$VERSION';
$VERSION = '0.12';


use Log::Report 'xml-compile-wss';

use XML::Compile::WSS::Util ':wss11';
use XML::Compile::Util       qw/SCHEMA2001/;
use XML::Compile::C14N;

use File::Basename           qw/dirname/;

my @prefixes11 = 
 ( wss  => WSS_11,  wsu    => WSU_10,    wsse  => WSSE_10
 , ds   => DSIG_NS, dsig11 => DSIG11_NS, dsigm => DSIG_MORE_NS
 , xenc => XENC_NS, ghc    => GHC_NS,    dsp   => DSP_NS
 );

my %versions =
  ( '1.1' => {xsddir => 'wss11', prefixes => \@prefixes11}
  );


sub new(@) { my $class = shift; (bless {}, $class)->init( {@_} ) }
sub init($)
{   my ($self, $args) = @_;
    my $version = $args->{version}
        or error __x"explicit wss_version required";
    trace "initializing wss $version";

    $version = '1.1'
        if $version eq WSS11MODULE;

    $versions{$version}
        or error __x"unknown wss version {v}, pick from {vs}"
             , v => $version, vs => [keys %versions];
    $self->{XCW_version} = $version;

    $self->loadSchemas($args->{schema})
        if $args->{schema};

    $self;
}

#-----------

sub version() {shift->{XCW_version}}
sub schema()  {shift->{XCW_schema}}

#-----------

sub wsseBasicAuth($$)
{   my ($self, $username, $password) = @_;

    my $schema = $self->schema or panic;
    my $pwtype = $schema->findName('wsse:Password');
    my $untype = $schema->findName('wsse:UsernameToken');

    my $doc    = XML::LibXML::Document->new('1.0', 'UTF-8');
    my $pwnode = $schema->writer($pwtype, include_namespaces => 0)
        ->($doc, $password);
    my $token  = $schema->writer($untype, include_namespaces => 0)
        ->($doc, { wsse_Username => $username, $pwtype => $pwnode } );

    +{ $untype => $token };
}

#-----------

sub loadSchemas($)
{   my ($self, $schema) = @_;

    $schema->isa('XML::Compile::Cache')
        or error __x"loadSchemas() requires a XML::Compile::Cache object";
    $self->{XCW_schema} = $schema;

    my $version = $self->version;
    my $def = $versions{$version};

    my $prefixes = $def->{prefixes};
    $schema->prefixes(@$prefixes);
    {   local $" = ',';
        $schema->addKeyRewrite("PREFIXED(@$prefixes)");
    }

    (my $xsddir = __FILE__) =~ s! \.pm$ !/$def->{xsddir}!x;
    my @xsd = glob "$xsddir/*.xsd";

    trace "loading wss for $version";

    $schema->importDefinitions
       ( \@xsd

         # Missing from wss-secext-1.1.xsd (schema BUG)  Gladly, all
         # provided schemas have element_form qualified.
       , element_form_default => 'qualified'
       );

    # Another schema bug; attribute wsu:Id not declared qualified
    my ($wsu, $xsd) = (WSU_10, SCHEMA2001);
    $schema->importDefinitions( <<__PATCH );
<schema
  xmlns="$xsd"
  targetNamespace="$wsu"
  elementFormDefault="qualified"
  attributeFormDefault="qualified">
    <attribute name="Id" type="ID" />
</schema>
__PATCH

    XML::Compile::C14N->new(version => 1.1, schema => $schema);
    $schema->allowUndeclared(1);
    $schema->addCompileOptions(RW => mixed_elements => 'STRUCTURAL');
    $schema->anyElement('ATTEMPT');

    $self;
}


1;
