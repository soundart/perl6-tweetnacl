use v6;
use Test;
use TweetNacl;
plan 1;

my %result = crypto_box_keypair();
cmp-ok %result.keys , '==', ('public_key', 'secret_key');
