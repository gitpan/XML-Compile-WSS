# Copyrights 2011-2012 by [Mark Overmeer].
#  For other contributors see ChangeLog.
# See the manual pages for details on the licensing terms.
# Pod stripped from pm file by OODoc 2.00.
use warnings;
use strict;

package XML::Compile::WSS;
use vars '$VERSION';
$VERSION = '1.00';


use Log::Report 'xml-compile-wss';

use XML::Compile::WSS::Util qw/:wss11 UTP11_PDIGEST UTP11_PTEXT/;
use XML::Compile::Util      qw/SCHEMA2001/;
use XML::Compile::C14N;
use XML::Compile::Schema::BuiltInTypes qw/builtin_type_info/;

use File::Basename          qw/dirname/;
use Digest::SHA1            qw/sha1_base64/;
use Encode                  qw/encode/;
use MIME::Base64            qw/encode_base64/;
use POSIX                   qw/strftime/;

my @prefixes11 = 
 ( wss   => WSS_11,  wsu    => WSU_10,    wsse  => WSSE_10
 , ds    => DSIG_NS, dsig11 => DSIG11_NS, dsigm => DSIG_MORE_NS
 , xenc  => XENC_NS, ghc    => GHC_NS,    dsp   => DSP_NS
 );

my %versions =
  ( '1.1' => {xsddir => 'wss11', prefixes => \@prefixes11}
  );


sub new(@)
{   my $class = shift;
    my $args  = @_==1 ? shift : {@_};
    (bless {}, $class)->init($args)->prepare;
}

my $schema;
sub init($)
{   my ($self, $args) = @_;
    my $version = $args->{wss_version} || $args->{version}
        or error __x"explicit wss_version required";
    trace "initializing wss $version";

    $version = '1.1'
        if $version eq WSS11MODULE;

    $versions{$version}
        or error __x"unknown wss version {v}, pick from {vs}"
             , v => $version, vs => [keys %versions];
    $self->{XCW_version} = $version;

    if($schema = $args->{schema})
    {   my $class = ref $self;    # it is class, not object, related!
        $class->loadSchemas($args->{schema}, $version);
    }
    $self;
}

sub prepare($)
{   my ($self, $args) = @_;
    $self->prepareWriting($schema);
    $self->prepareReading($schema);
    $self;
}

#-----------

sub version() {shift->{XCW_version}}
sub schema()  {$schema}

#-----------

# Some elements are allowed to have an Id attribute from the wsu
# schema, regardless of what the actual schema documents say.  So an
# attribute "wsu_Id" should get interpreted as such, if the writer
# has registered this hook.
sub _hook_WSU_ID
{   my ($doc, $values, $path, $tag, $r) = @_ ;
    my $id = delete $values->{wsu_Id};  # remove first, to avoid $r complaining
    my $node = $r->($doc, $values);
    if($id)
    {   $node->setNamespace(WSU_10, 'wsu', 0);
        $node->setAttributeNS(WSU_10, 'Id' => $id);
    }
    $node;
}

#-----------

# wsu had "allow anything" date fields, not type dateTime
sub dateTime($)
{   my ($self, $time) = @_;
    return $time if !defined $time || ref $time;

    my $dateTime = builtin_type_info 'dateTime';
    if($time !~ m/[^0-9.]/) { $time = $dateTime->{format}->($time) }
    elsif($dateTime->{check}->($time)) {}
    else {return $time}

     +{ _ => $time
      , ValueType => SCHEMA2001.'/dateTime'
      };
}


my $schema_loaded = 0;
sub loadSchemas($$)
{   my ($class, $schema, $version) = @_;
    return $class if $schema_loaded++;

    $schema->isa('XML::Compile::Cache')
        or error __x"loadSchemas() requires a XML::Compile::Cache object";

    my $def      = $versions{$version};
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
    # Besides, ValueType is often used on timestamps, which are declared
    # as free-format fields (@*!&$#!&^ design committees!)
    my ($wsu, $xsd) = (WSU_10, SCHEMA2001);
    $schema->importDefinitions( <<__PATCH );
<schema
  xmlns="$xsd"
  xmlns:wsu="$wsu"
  targetNamespace="$wsu"
  elementFormDefault="qualified"
  attributeFormDefault="unqualified">
    <attribute name="Id" type="ID" form="qualified" />

    <complexType name="AttributedDateTime">
      <simpleContent>
        <extension base="string">
          <attribute name="ValueType" type="anyURI" />
          <attributeGroup ref="wsu:commonAtts"/>
        </extension>
      </simpleContent>
   </complexType>

</schema>
__PATCH

    XML::Compile::C14N->new(version => '1.1', schema => $schema);
    $schema->allowUndeclared(1);
    $schema->addCompileOptions(RW => mixed_elements => 'STRUCTURAL');
    $schema->anyElement('ATTEMPT');

    # If we find a wsse_Security which points to a WSS or an ARRAY of
    # WSS, we run all of them.
    my $process_security =
     +{ type   => 'wsse:SecurityHeaderType'
      , before => sub {
        my ($doc, $from, $path) = @_;
        my $data = {};
        if( UNIVERSAL::isa($from, 'XML::Compile::SOAP::WSS')
         || UNIVERSAL::isa($from, __PACKAGE__))
             { $from->process($doc, $data) }
        elsif(ref $from eq 'ARRAY')
             { $_->process($doc, $data) for @$from }
        else { $data = $from }

        $data;
    }};

    $schema->declare(WRITER => 'wsse:Security', hooks => $process_security);
    $schema;
}

sub prepareWriting($) { shift }
sub prepareReading($) { shift }


1;
