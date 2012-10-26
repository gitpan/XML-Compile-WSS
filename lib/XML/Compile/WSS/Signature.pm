# Copyrights 2011-2012 by [Mark Overmeer].
#  For other contributors see ChangeLog.
# See the manual pages for details on the licensing terms.
# Pod stripped from pm file by OODoc 2.00.
use warnings;
use strict;

package XML::Compile::WSS::Signature;
use vars '$VERSION';
$VERSION = '1.03';

use base 'XML::Compile::WSS';

use Log::Report 'xml-compile-wss';

use XML::Compile::WSS::Util   qw/:wss11 :dsig :xtp10 :wsm10/;
use XML::Compile::C14N::Util  qw/:c14n/;

use XML::LibXML     ();
use HTTP::Response  ();
use MIME::Base64    qw/decode_base64 encode_base64/;
use File::Slurp     qw/read_file/;
use Digest          ();
use Scalar::Util    qw/blessed/;

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

my %keywraps =
 ( &XTP10_X509    => 'PUBLIC KEY'
 , &XTP10_X509PKI => 'RSA PUBLIC KEY'
 , &XTP10_X509v3  => 'CERTIFICATE'
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

    my $sign = $self->{XCWS_signmeth} = $args->{sign_method} || DSIG_RSA_SHA1;
    $self->{XCWS_signer}     = $self->_create_signer($sign, $args);

    $self->{XCWS_pubkey_uri} = $args->{public_key_id } || 'public-key';
    $self->{XCWS_publ_key}   = $args->{publish_pubkey} || 'INCLUDE_BY_REF';

    $self->{XCWS_canonmeth}  = $args->{canon_method}   || C14N_EXC_NO_COMM;
    $self->{XCWS_prefixlist} = $args->{prefix_list}
                            || [ qw/ds wsu xenc SOAP-ENV/ ];
    $self->{XCWS_to_check}   = {};
    $self->{XCWS_checker}    = $self->_create_remote_pubkey($args);
    $self;
}

#-----------------------------


sub defaultDigestMethod() { shift->{XCWS_digmeth} }


sub digest($$)
{   my ($self, $method, $text) = @_;
    $method =~ $digest_algorithm
        or error __x"digest {name} is not a correct constant";
    my $algo = uc $1;

    my $digest = try { Digest->new($algo)->add($$text)->digest };
    $@ and error __x"cannot use digest method {short}, constant {name}: {err}"
      , short => $algo, name => $method, err => $@->wasFatal;

    $digest;
}

sub _digest_elem_check($$)
{   my ($self, $elem, $ref) = @_;
    my $transf   = $ref->{ds_Transforms}{ds_Transform}[0]; # only 1 transform
    my ($inclns, $preflist) = %{$transf->{cho_any}[0]};    # only 1 kv pair
    my $elem_c14n = $self
        ->_apply_canon($transf->{Algorithm}, $preflist->{PrefixList})
        ->($elem);

    my $digmeth = $ref->{ds_DigestMethod}{Algorithm} || '(none)';
    $self->digest($digmeth, \$elem_c14n) eq $ref->{ds_DigestValue};
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
    my $doc    = $xc_out_dom->ownerDocument;

    # building bottom up: be sure we have all namespaces which may be
    # declared later, on higher in the hierarchy.
    my $env    = $doc->createElement('Dummy');
    my $prefixes = $self->schema->prefixes;
    $env->setNamespace($_->{uri}, $_->{prefix}, 0)
        for values %$prefixes;

    # reparse tree
    $env->addChild($xc_out_dom);
    my $fixed_dom = XML::LibXML->load_xml(string => $env->toString(0));
    my $new_out   = ($fixed_dom->documentElement->childNodes)[0];
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
sub checker()    {shift->{XCWS_checker}}

sub _create_signer($$)
{   my ($self, $method, $args) = @_;
    $method =~ $sign_algorithm
        or error __x"method {name} is not a sign algorithm";
    my ($algo, $hashing) = (uc $1, uc $2);

    if($algo eq 'RSA') { $self->_setup_hashing_rsa($hashing, $args) }
    else
    {   error __x"signing algorithm {name} not (yet) unsupported", name => $hashing;
    }

}

sub _checker_from_token($$)
{   my ($self, $method, $token) = @_;
    $method =~ $sign_algorithm
        or error __x"method {name} is not a sign algorithm", name => $method;
    my ($algo, $hashing) = (uc $1, uc $2);

        $algo eq 'RSA' ? $self->_checker_from_token_rsa($hashing, $token)
      : error __x"signing algorithm {name} not (yet) unsupported"
          , name => $hashing;
}

sub _create_remote_pubkey($)
{   my ($self, $args) = @_;
    my $key = $args->{remote_pubkey} or return;

    if(ref $key)
    {   blessed $key && $key->isa('Crypt::OpenSSL::RSA')
            or error __x"server public key object type not supported";
        return $self->_check_rsa($key);
    }

    if($key =~ m/\.(?:der|pub)$/i)
    {   my $pubkey = Crypt::OpenSSL::RSA->new_public_key(scalar read_file $key);
        return $self->_check_rsa($pubkey);
    }

    # construct a token as if from the server, less to implement per algo
    my $method = $args->{remote_sign_method} || DSIG_RSA_SHA1;
    my %token =
      ( ValueType    => ($args->{remote_pubkey_type} || XTP10_X509)
      , EncodingType => $args->{remote_pubkey_encoding}
      , _            => $key
      );

    $self->_checker_from_token($method, \%token);
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

    $self->{XCWS_to_check}{$id} = $node;
}


sub elementsToCheck()
{   my $self = shift;
    my $to_check = delete $self->{XCWS_to_check};
    $self->{XCWS_to_check} =  {};
    $to_check;
}

#-----------------------------
#### HELPERS

sub _get_sec_token($$)
{   my ($self, $sec, $sig) = @_;
    my $sec_tokens = $sig->{ds_KeyInfo}{cho_ds_KeyName}[0]
        ->{wsse_SecurityTokenReference}{cho_any}[0];
    my ($key_type, $key_data) = %$sec_tokens;
    $key_type eq 'wsse_Reference'
        or error __x"key-type {type} not yet supported", type => $key_type;
    my $key_uri    = $key_data->{URI} or panic;
    (my $key_id    = $key_uri) =~ s/^#//;
    my $token      = $sec->{wsse_BinarySecurityToken};

    $token->{wsu_Id} eq $key_id
        or error __x"token does not match reference";

    $token->{ValueType} eq $key_data->{ValueType}
        or error __x"token type {type1} does not match expected {type2}"
            , type1 => $token->{ValueType}, type2 => $key_data->{ValueType};
    $token;
}

sub prepareReading($)
{   my ($self, $schema) = @_;
    $self->SUPER::prepareReading($schema);

    my %security_tokens;   # the BinarySecurityToken keys, binary form

    $schema->declare(READER => 'ds:Signature',
      , hooks => {type => 'ds:SignedInfoType', after => 'XML_NODE'});

    $self->{XCWS_reader} = sub {
        my $sec  = shift;
#warn Dumper $sec;
        my $sig  = $sec->{ds_Signature};
        unless($sig)
        {   # When the signature is missing, we only die if we expect one
            $self->checker or return;
            error __x"requires signature block missing from remote";
        }

        my $info       = $sig->{ds_SignedInfo} || {};

        # Check signature on SignedInfo
        my $can_meth   = $info->{ds_CanonicalizationMethod};
        my $can_pref   = $can_meth->{c14n_InclusiveNamespaces}{PrefixList};
        my $si_canon   = $self->_apply_canon($can_meth->{Algorithm}, $can_pref)
            ->($info->{_XML_NODE});

        my $checker    = $self->checker;
        unless($checker)
        {   my $sig_meth = $info->{ds_SignatureMethod}{Algorithm};
            my $token    = $self->_get_sec_token($sec, $sig);
            $checker     = $self->_checker_from_token($sig_meth, $token);
        }
        $checker->(\$si_canon, $sig->{ds_SignatureValue}{_})
            or error __x"signature on SignedInfo incorrect";

        # Check digest of the elements
        my %references;
        foreach my $ref (@{$info->{ds_Reference}})
        {   my $uri = $ref->{URI};
            $references{$uri} = $ref;
        }

        my $check = $self->elementsToCheck;
#print "FOUND: ", Dumper \%references, $info, $check;
        foreach my $id (sort keys %$check)
        {   my $node = $check->{$id};
            my $ref  = delete $references{"#$id"}
                or error __x"cannot find digest info for {elem}", elem => $id;
            $self->_digest_elem_check($node, $ref)
                or warning __x"digest info of {elem} is wrong", elem => $id;
        }
    };

    $self;
}

sub check($)
{   my ($self, $data) = @_;
    $self->{XCWS_reader}->($data);
}

### BE WARNED: created nodes can only be used once!!! in XML::LibXML

sub _create_inclns($)
{   my ($self, $prefixes) = @_;
    $prefixes ||= [];
    my $schema  = $self->schema;
    my $type    = $schema->findName('c14n:InclusiveNamespaces');
    my $incns   = $schema->writer($type, include_namespaces => 0);

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
        {   my $digested  = $self->digest($digest,\$canonical->($part->{node}));
    
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
        return $sec if $sec->{$sigt};
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
{   my ($self, $doc, $sec) = @_;
    # cannot do much yet, first the Body must be ready.
    $self->{XCWS_sec_hdr} = $sec;
    $self;
}


sub createSignature($)
{   my ($self, $doc) = @_;
    $self->{XCWS_sign}->($doc, $self->{XCWS_sec_hdr});
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
      = blessed $priv && $priv->isa('Crypt::OpenSSL::RSA') ? $priv
      : index($priv, "\n") >= 0
      ? Crypt::OpenSSL::RSA->new_private_key($priv)
      : Crypt::OpenSSL::RSA->new_private_key(scalar read_file $priv);

    ### Public key
    my $pub    = $args->{public_key} || $privkey;
    my $pubkey = $self->{XCWS_pubkey}
      = blessed $pub && $pub->isa('Crypt::OpenSSL::RSA')? $pub
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

sub _checker_from_token_rsa($$)
{   my ($self, $hashing, $token) = @_;

    require Crypt::OpenSSL::RSA;
#cache here based on token?  Performance worth the effort?

    my $key = $token->{_};
    my $enc = $token->{EncodingType};

    if(!$enc)
    {   $key = encode_base64 $key;
        $enc = WSM10_BASE64;
    }
    elsif($enc eq WSM10_BASE64) {}
    else {error __x"unsupported token encoding {type} received", type => $enc}

    my $vtype  = $token->{ValueType};
    my $wrap   = $keywraps{$vtype}
        or error __x"unsupported token type {type} received", type => $vtype;

    # the input format of openssl is very strict
    for($key)
    {   s/\s+//gs;
        s/(.{64})/$1\n/g;   # exactly 64 chars per line
        s/\s*\z//s;
    }
    my $pubkey = Crypt::OpenSSL::RSA->new_public_key(<<__PUBLIC_KEY);
-----BEGIN $wrap-----
$key
-----END $wrap-----
__PUBLIC_KEY

    my $use_hash = "use_\L$hashing\E_hash";
    $pubkey->can($use_hash)
        or error __x"hash {type} not supported by {pkg}"
            , type => $hashing, pkg => ref $pubkey;
    $pubkey->$use_hash();
    $self->_check_rsa($pubkey);
}

sub _check_rsa($)
{   my ($self, $pubkey) = @_;
    sub { my ($plain, $sig) = @_; $pubkey->verify($$plain, $sig) }
}

1;
