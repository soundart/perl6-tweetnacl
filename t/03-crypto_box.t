use v6;
use Test;
use TweetNacl;
plan 3;


my $keys = keypair.new;
my $msg = 'Hello World'.encode('UTF-8');
my $nonce = nonce();
my $data1 = crypto_box($msg, $nonce, $keys.public , $keys.secret);
my $rmsg1 = crypto_box_open($data1, $nonce, $keys.public , $keys.secret);
note $rmsg1;
is $rmsg1, $msg , "Roundtrip encrypt->decrypt";

my $cb = CryptoBox.new(pk => $keys.public , sk => $keys.secret);
my $data2 = $cb.encrypt($msg, $nonce);
is-deeply $data1, $data2, "encrypt, precomputation interface";

my $cbo = CryptoBoxOpen.new(pk => $keys.public , sk => $keys.secret);
my $rmsg2 = $cbo.decrypt($data2, $nonce);
is $rmsg2.decode('UTF-8'), $msg, "decrypt, precomputation interface";
