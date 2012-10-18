# Copyrights 2011-2012 by [Mark Overmeer].
#  For other contributors see ChangeLog.
# See the manual pages for details on the licensing terms.
# Pod stripped from pm file by OODoc 2.00.
use warnings;
use strict;

package XML::Compile::WSS::Signature;
use vars '$VERSION';
$VERSION = '1.01';

use base 'XML::Compile::WSS';

use Log::Report 'xml-compile-wss';

use XML::Compile::WSS::Util   qw/:wss11 :dsig :xtp10 :wsm10/;
use XML::Compile::C14N::Util  qw/:c14n/;

use XML::LibXML               ();
use HTTP::Response            ();
use MIME::Base64              qw/decode_base64 encode_base64/;
use File::Slurp               qw/read_file/;
use Digest                    ();

my $unique = $$.time;

use Data::Dumper;
$Data::Dumper::Indent    = 1;
$Data::Dumper::Quotekeys = 0;

my %canon =          #comment  excl
  ( &C14N_v10_NO_COMM  => [ 0, 0 ]
  , &C14N_v10_COMMENTS => [ 1, 0 ]
  , &C14N_v11_NO_COMM  => [ 0, 0 ]
  , &C14N_v11_COMMENTS => [ 1, 0 ]
  , &C14N_EXC_NO_COMM  => [ 0, 1 ]
  , &C14N_EXC_COMMENTS => [ 1, 1 ]
  );

my ($digest_algorithm, $sign_algorithm);
{  my ($signs, $sigmns) = (DSIG_NS, DSIG_MORE_NS);
   # the digest algorithms can be distiguish by pure lowercase, no dash.
   $digest_algorithm = qr/^(?:$signs|$sigmns)([a-z0-9]+)$/;
   $sign_algorithm   = qr/^(?:$signs|$sigmns)([a-z0-9]+)\-([a-z0-9]+)$/;
}


sub init($)
{   my ($self, $args) = @_;
    $args->{wss_version} ||= '1.1';

    $self->SUPER::init($args);

    # Run digest to initialize modules (and detect what is not installed)
    # Usually client and server use the same algorithms
    my $digest = $self->{XCWS_digmeth}  = $args->{digest_method} || DSIG_SHA1;
    $self->digest($digest, \"test digest");

    my $sign   = $self->{XCWS_signmeth} = $args->{sign_method} || DSIG_RSA_SHA1;
    $self->{XCWS_signer}     = $self->_create_signer($sign, $args);

    $self->{XCWS_pubkey_uri} = $args->{public_key_uri} || '#public-key';
    $self->{XCWS_publ_key}   = $args->{publish_pubkey} || 'INCLUDE_BY_REF';

    $self->{XCWS_canonmeth}  = $args->{canon_method}   || C14N_EXC_NO_COMM;
    $self->{XCWS_prefixlist} = $args->{prefix_list}
                            || [ qw/ds wsu xenc SOAP-ENV/ ];
    $self->{XCWS_to_check}   = {};
    $self;
}

#-----------------------------


sub defaultDigestMethod() { shift->{XCWS_digmeth} }


sub digest($$)
{   my ($self, $method, $text) = @_;
    $method =~ $digest_algorithm
        or error __x"digest {name} is not a correct constant";
    my $algo = uc $1;

    my $digest = try { Digest->new($algo)->add($text)->digest };
    $@ and error __x"cannot use digest method {short}, constant {name}: {err}"
      , short => $algo, name => $method, err => $@->wasFatal;

    $digest;
}

#-----------------------------


sub defaultCanonMethod() {shift->{XCWS_canonmeth}}
sub canon($) {my $r = $canon{$_[1] || shift->defaultCanonMethod}; $r ? @$r : ()}
sub prefixList() {shift->{XCWS_prefixlist} || []}

# XML::Compile has to trick with prefixes, because XML::LibXML does not
# permit the creation of nodes with explicit prefix, only by namespace.
# The next can be slow and is ugly, Sorry.  MO
sub _repair_xml($$)
{   my ($self, $xc_out_dom) = @_;

    # only doc element does charsets correctly
    my $doc       = $xc_out_dom->ownerDocument;
    $doc->setDocumentElement($xc_out_dom);

    # reparse tree
    my $fixed_dom = XML::LibXML->load_xml(string => $xc_out_dom->toString(0));
    my $new_out   = $fixed_dom->documentElement;
    $doc->importNode($new_out);
    $new_out;
}

sub _apply_canon(;$$)
{   my ($self, $algo, $prefixlist) = @_;
    $algo       ||= $self->defaultCanonMethod;
    $prefixlist ||= $self->prefixList;

    my ($with_comments, $with_exc) = $self->canon($algo);
    defined $with_comments
        or error __x"unsupported canonicalization method {name}", name => $algo;

    my $serialize = $with_exc ? 'toStringEC14N' : 'toStringC14N';

    # Don't know what $path and $context are expected to be
    my $path      = 0;

    sub {
        my ($node) = @_;
        my $repaired = $self->_repair_xml($node);
        my $context = XML::LibXML::XPathContext->new($repaired);
        $repaired->$serialize($with_comments, undef, $context, $prefixlist);
    };
}

sub _apply_canon_siginfo($$)
{   my ($self, $siginfo_node, $sig) = @_;

    my $canon = $sig->{ds_SignedInfo}{ds_CanonicalizationMethod} or panic;
    $self->_apply_canon
      ( $canon->{Algorithm}
      , $canon->{c14n_InclusiveNamespaces}{PrefixList}
      )->($siginfo_node);
}

#-----------------------------


sub _create_keyinfo()
{   my $self  = shift;
    my $pubpk = $self->{XCWS_publ_key};
    return $pubpk if ref $pubpk eq 'CODE';
 
    $pubpk eq 'INCLUDE_BY_REF'
        or error __x"publish_pubkey either CODE or 'INCLUDE_BY_REF'";

    my $token   = $self->{XCWS_pubkey_base64};
    my $uri     = $self->{XCWS_pubkey_uri};
    my $keytype = $self->{XCWS_pubkey_t};

    my $schema  = $self->schema;
    $schema->prefixFor(WSU_10);

    my $krt = $schema->findName('wsse:Reference');
    my $krw = $schema->writer($krt, include_namespaces => 0);

    my $kit = $schema->findName('wsse:SecurityTokenReference');
    my $kiw = $schema->writer($kit, include_namespaces => 0);

    my $ctt = $schema->findName('wsse:BinarySecurityToken');
    my $ctw = $schema->writer($ctt, include_namespaces => 0);

    sub ($$) {
       my ($doc, $sec) = @_;
       my $kr  = $krw->($doc, {URI => $uri, ValueType => $keytype});
       my $ki  = $kiw->($doc, {cho_any => {$krt => $kr}});
       my %keyinfo;
       push @{$keyinfo{cho_ds_KeyName}}, {$kit => $ki};

       my $ct  = $ctw->($doc,
         { EncodingType => WSM10_BASE64
         , ValueType    => $keytype
         , _            => $token        # already base64
         });
       $ct->setNamespace(WSU_10, 'wsu', 0);
       $ct->setAttributeNS(WSU_10, 'Id', $uri);
       $sec->{$ctt} = $ct;
       \%keyinfo;
    };
}

#-----------------------------

sub signMethod() {shift->{XCWS_signmeth}}

sub _create_signer($$)
{   my ($self, $method, $args) = @_;
    $method =~ $sign_algorithm
        or error __x"Method {name} is not a sign algorithm";
    my ($algo, $hashing) = (uc $1, uc $2);

    if($algo eq 'RSA') { $self->_setup_hashing_rsa($hashing, $args) }
    else
    {   error __x"signing algorithm {name} not (yet) unsupported", name => $hashing;
    }

}


sub signElement(%)
{   my ($self, $node, %args) = @_;
    my $wsuid = $node->getAttributeNS(WSU_10, 'Id');
    unless($wsuid)
    {   $wsuid = $args{id} || 'elem-'.$unique++;
        $node->setNamespace(WSU_10, 'wsu', 0);
        $node->setAttributeNS(WSU_10, 'Id', $wsuid);
    }
    push @{$self->{XCWS_to_sign}}, +{node => $node,  id => $wsuid};
    $node;
}


sub elementsToSign() { delete shift->{XCWS_to_sign} || [] }


sub checkElement($%)
{   my ($self, $node, %args) = @_;
    my $id = $node->getAttributeNS(WSU_10, 'Id')
        or error "element to check {name} has no wsu:Id"
             , name => $node->nodeName;

warn "CHECK $id";
    $self->{XCWS_to_check}{$id} = $node;
}
#   my $sig  = $signatures{$uri} or panic $uri;
#   my $ref  = $references{$uri} or panic $uri;
#   $self->_digest_elem_check($node, $ref)
# probably fails due to serialization problem of the body
#        or warning __x"received body digest does not match";
#    $node;


sub elementsToCheck()
{   my $self = shift;
    my $to_check = delete $self->{XCWS_to_check};
    $self->{XCWS_to_check} =  {};
    $to_check;
}

#-----------------------------
#### HELPERS


sub _digest_elem_check($$)
{   my ($self, $elem, $ref) = @_;
    my $transf   = $ref->{ds_Transforms}{ds_Transform}[0]; # only 1 transform
    my ($inclns, $preflist) = %{$transf->{cho_any}[0]};    # only 1 kv pair
    my $elem_c14n = $self->_apply_canon($transf->{Algorithm}, $preflist)
        ->($elem);

#MO: Output not OK
print "TEXT=$elem_c14n";

    my $digmeth = $ref->{ds_DigestMethod}{Algorithm} || '(none)';
    $self->digest($digmeth, \$elem_c14n) eq $ref->{ds_DigestValue};
}

sub prepareReading($)
{   my ($self, $schema) = @_;
    $self->SUPER::prepareReading($schema);

    my %security_tokens;   # the BinarySecurityToken keys, binary form

    my $take_security_token
      = { type    => 'wsse:BinarySecurityTokenType'
        , after   => sub {
        my ($node, $data, $path) = @_;
        my $id     = $data->{wsu_id} = $node->getAttributeNS(WSU_10, 'Id');

        if(my $enc = $data->{EncodingType})
        {   $enc eq WSM10_BASE64
                or error __x"security token encoding {type} not supported"
                    , type => $enc;
            $security_tokens{$id} = decode_base64 $data->{_};
        }

        $data;
       }};

    $schema->declare(READER => 'wsse:BinarySecurityToken'
      , hooks => $take_security_token);

    $self->{XCWS_reader} = sub {
        my $data = shift;
        my $sec  = $data->{wsse_Security}
            or error __x"no security block found";

        my $sig  = $sec->{ds_Signature}
            or error __x"no signature block found";

use Data::Dumper;
#print "HOOK: ", Dumper $data;
#XXX MO: check signed info first
        my $info = $sig->{ds_SignedInfo} || {};

        my %references;
        foreach my $ref (@{$info->{ds_Reference}})
        {   my $uri = $ref->{URI};
            $references{$uri} = $ref;
        }

        my $check = $self->elementsToCheck;
print "FOUND: ", Dumper \%references, $info, $check;
        foreach my $id (sort keys %$check)
        {   my $node = $check->{$id};
            my $ref  = delete $references{"#$id"}
                or error __x"cannot find digest info for {elem}", elem => $id;
            $self->_digest_elem_check($node, $ref)
                or warning __x"digest info of {elem} is wrong", elem => $id;
warn "OK $id";
        }
    };

    $self;
}

sub process_received($)
{   my ($self, $data) = @_;
    $self->{XCWS_reader}->($data);
}

### BE WARNED: created nodes can only be used once!!! in XML::LibXML

sub _create_inclns($)
{   my ($self, $prefixes) = @_;
    $prefixes && @$prefixes or return ();

    my $schema = $self->schema;
    my $type   = $schema->findName('c14n:InclusiveNamespaces');
    my $incns  = $schema->writer($type, include_namespaces => 0);

    ( $type, sub {$incns->($_[0], {PrefixList => $prefixes})} );
}

sub _fill_signed_info($$)
{   my ($self, $canon, $prefixes) = @_;
    my ($incns, $incns_make) = $self->_create_inclns($prefixes);
    my $canonical = $self->_apply_canon($canon, $prefixes);
    my $digest    = $self->defaultDigestMethod;
    my $signmeth  = $self->signMethod;

    sub {
        my ($doc, $parts) = @_;
        my $canon_method =
         +{ Algorithm => $canon
          , $incns    => $incns_make->($doc)
          };
    
        my @refs;
        foreach my $part (@$parts)
        {   my $digested  = $self->digest($digest, $canonical->($part->{node}));
    
            my $transform =
              { Algorithm => $canon
              , cho_any => [ {$incns => $incns_make->($doc)} ]
              };
    
            push @refs,
             +{ URI             => '#'.$part->{id}
              , ds_Transforms   => { ds_Transform => [$transform] }
              , ds_DigestValue  => $digested
              , ds_DigestMethod => { Algorithm => $digest }
              };
        }
    
         +{ ds_CanonicalizationMethod => $canon_method
          , ds_Reference              => \@refs
          , ds_SignatureMethod        => { Algorithm => $signmeth }
          };
    };
}

sub prepareWriting($)
{   my ($self, $schema) = @_;
    $self->SUPER::prepareWriting($schema);
    return $self if $self->{XCWS_sign};
    my @elements_to_sign;

    my $settings  = $self->_create_keyinfo;
    my $si_canon  = $self->defaultCanonMethod;
    my $si_prefl  = $self->prefixList;

    my $fill_signed_info = $self->_fill_signed_info($si_canon, $si_prefl);
    my $canonical = $self->_apply_canon($si_canon, $si_prefl);
    my $sign      = $self->{XCWS_hasher};

    # encode by hand, because we need the signature immediately
    my $infow = $schema->writer('ds:SignedInfo');

    my $sigt  = $schema->findName('ds:Signature');
    my $sigw  = $schema->writer($sigt);

    $self->{XCWS_sign} = sub {
        my ($doc, $sec) = @_;
        my $info      = $fill_signed_info->($doc, $self->elementsToSign);
        my $keyinfo   = $settings->($doc, $sec);
        my $info_node = $self->_repair_xml($infow->($doc, $info));
        my $signature = $sign->(\$canonical->($info_node));

        # The signature value is only known when the Info is ready,
        # but gladly they are produced in the same order.
        my %sig =
          ( ds_SignedInfo     => $info_node
          , ds_SignatureValue => {_ => $signature}
          , ds_KeyInfo        => $keyinfo
          );

        $sec->{$sigt}     = $sigw->($doc, \%sig);
        $sec;
    };
    $self;
}

sub create($$)
{   my ($self, $doc, $data) = @_;
    $self->{XCWS_sign}->($doc, $data);
}

#---------------------------

sub _setup_hashing_rsa($$)
{   my ($self, $hashing, $args) = @_;

    require Crypt::OpenSSL::RSA;

    my $pkt = $self->{XCWS_pubkey_t} = $args->{public_key_type} || XTP10_X509;

    ### Private key
    my $priv = $args->{private_key}
        or error "signer rsa requires the private_rsa key";

    my $privkey = $self->{XCWS_privkey}
      = UNIVERSAL::isa($priv, 'Crypt::OpenSSL::RSA') ? $priv
      : index($priv, "\n") >= 0
      ? Crypt::OpenSSL::RSA->new_private_key($priv)
      : Crypt::OpenSSL::RSA->new_private_key(scalar read_file $priv);

    ### Public key
    my $pub    = $args->{public_key} || $privkey;
    my $pubkey = $self->{XCWS_pubkey}
      = UNIVERSAL::isa($pub, 'Crypt::OpenSSL::RSA') ? $pub
      : index($pub, "\n") >= 0
      ? Crypt::OpenSSL::RSA->new_public_key($pub)
      : Crypt::OpenSSL::RSA->new_public_key(scalar read_file $pub);

    ### Hashing
    my $use_hash = "use_\L$hashing\E_hash";
    $privkey->can($use_hash)
        or error __x"hash {type} not supported by {pkg}"
            , type => $hashing, pkg => ref $privkey;
    $privkey->$use_hash();

    $self->{XCWS_hasher} = sub { my $rtext = shift; $privkey->sign($$rtext) };

    my $pub64
      = $pkt eq XTP10_X509    ? $pubkey->get_public_key_x509_string
      : $pkt eq XTP10_X509PKI ? $pubkey->get_public_key_string
      : error __x"rsa unsupported public key format {type}", type => $pkt;

    $pub64 =~ s/^---[^\n]*\n//gm;   # remove wrapper
    $self->{XCWS_pubkey_base64} = $pub64;
    $self;
}
1;
