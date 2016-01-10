use v6;
use Test;
use Crypt::TweetNacl::PublicKey;
use NativeCall;
plan 2;


my $keypair = KeyPair.new;
isa-ok $keypair.secret, CArray[int8];
isa-ok $keypair.public, CArray[int8];
