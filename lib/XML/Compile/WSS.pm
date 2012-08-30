# Copyrights 2011-2012 by [Mark Overmeer].
#  For other contributors see ChangeLog.
# See the manual pages for details on the licensing terms.
# Pod stripped from pm file by OODoc 2.00.
use warnings;
use strict;

package XML::Compile::WSS;
use vars '$VERSION';
$VERSION = '0.90';


use Log::Report 'xml-compile-wss';

use XML::Compile::WSS::Util qw/:wss11 UTP11_PDIGEST/;
use XML::Compile::Util      qw/SCHEMA2001/;
use XML::Compile::C14N;

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

sub _datetime($)
{   my $time = shift;
    return $time if !$time || $time =~ m/[^0-9.]/;

    my $subsec = $time =~ /(\.[0-9]+)/ ? $1 : '';
    strftime "%Y-%m-%dT%H:%M:%S${subsec}Z", gmtime $time;
}


sub wsseTimestamp($$%)
{   my ($self, $created, $expires, %opts) = @_ ;

    my $schema   = $self->schema or panic;
    my $timestamptype = $schema->findName('wsu:Timestamp') ;
    my $doc      = XML::LibXML::Document->new('1.0', 'UTF-8');

    my $tsWriter = $schema->writer($timestamptype, include_namespaces => 1,
      , hook => {type => 'wsu:TimestampType', replace => \&_hook_WSU_ID} );

    my $tsToken  = $tsWriter->($doc, {wsu_Id => $opts{wsu_Id}
      , wsu_Created => _datetime($created)
      , wsu_Expires => _datetime($expires)});

    +{$timestamptype => $tsToken};
}


sub wsseBasicAuth($$;$%)
{   my ($self, $username, $password, $type, %opts) = @_;
    my $schema = $self->schema or panic;
    my $doc    = XML::LibXML::Document->new('1.0', 'UTF-8');

    # The spec says we include "created" and "nonce" nodes if they're present.
    my @additional;
    if($type eq UTP11_PDIGEST)
    {  
        my $nonce = $opts{nonce} || '';
        if($nonce)
        {   my $noncetype = $schema->findName('wsse:Nonce') ;
            my $noncenode = $schema->writer($noncetype, include_namespaces => 0)
               ->($doc, {_ => encode_base64($nonce)});
            push @additional, $noncetype => $noncenode;
        }

        my $created = $opts{created} || '';
        if($created)
        {    my $createdtype = $schema->findName('wsu:Created' ) ;
             my $cnode = $schema->writer($createdtype, include_namespaces => 0)
               ->($doc, {_ => _datetime($created) } );
             push @additional, $createdtype => $cnode;
        }

        $password = sha1_base64(encode utf8 => "$nonce$created$password").'=';
    }

    my $pwtype = $schema->findName('wsse:Password');
    my $pwnode = $schema->writer($pwtype, include_namespaces => 0)
        ->($doc, {_ => $password, Type => $type});
    push @additional, $pwtype => $pwnode;

    # UsernameToken is allowed to have an "Id" attribute from the wsu schema.
    # We set up the writer with a hook to add that particular attribute.
    my $untype   = $schema->findName('wsse:UsernameToken');
    my $unwriter = $schema->writer($untype, include_namespaces => 1,
      , hook => {type => 'wsse:UsernameTokenType', replace => \&_hook_WSU_ID});

    my $token   = $unwriter->($doc
      , {wsu_Id => $opts{wsu_Id}, wsse_Username => $username, @additional});

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
