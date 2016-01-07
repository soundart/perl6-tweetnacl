use v6;
use Test;
use TweetNacl;
plan 1;


my $keys = keypair.new;
my $msg = 'Hello World';
my $nonce = nonce();
my $data = crypto_box($msg, $nonce, $keys.public , $keys.secret);
my $rmsg = crypto_box_open($data, $nonce, $keys.public , $keys.secret);
note $rmsg;
is $rmsg, $msg;