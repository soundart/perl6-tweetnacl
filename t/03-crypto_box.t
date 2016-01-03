use v6;
use Test;
use TweetNacl;
plan 1;


my %ckeys = crypto_box_keypair();
my $msg = 'Hello World';
my $data = crypto_box($msg, %ckeys<public_key> , %ckeys<secret_key>);
note $data;
is $data, ""