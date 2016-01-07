use v6;
use Test;
use TweetNacl;
plan 1;


my %ckeys = crypto_box_keypair();
my $msg = 'Hello World';
my $nonce = nonce();
my $data = crypto_box($msg, $nonce, %ckeys<public_key> , %ckeys<secret_key>);
my $rmsg = crypto_box_open($data, $nonce, %ckeys<public_key> , %ckeys<secret_key>);
note $rmsg;
is $rmsg, $msg;