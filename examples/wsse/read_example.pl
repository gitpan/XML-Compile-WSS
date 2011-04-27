#!/usr/bin/env perl
# This script demonstrates how the security component of the
# soap message (included in this directory) is interpreted.
# The SOAP wrapper itself is being ignored.

use warnings;
use strict;

use XML::Compile::Util  qw/type_of_node/;
use XML::Compile::Cache;
use XML::Compile::WSS;

# next modules for testing only
use Data::Dumper;
$Data::Dumper::Indent    = 1;
$Data::Dumper::Quotekeys = 0;

# The real work starts
my $schema = XML::Compile::Cache->new;
my $wss  = XML::Compile::WSS->new(version => '1.1', schema => $schema);

# strip the SOAP wrapper
use XML::LibXML;
my $parser = XML::LibXML->new;
my $doc    = $parser->load_xml(location => 'wsse-example.xml');
my $root   = $doc->documentElement;
my ($head) = $root->getChildrenByLocalName('Header');
my ($sec)  = $head->getChildrenByLocalName('Security');

my $data   = $schema->reader(type_of_node $sec)->($sec);
print Dumper $data;
