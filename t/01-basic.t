use v6;
use Test;
use TweetNacl;
use NativeCall;
plan 2;


my $keypair = keypair.new;
isa-ok $keypair.secret, CArray[int8];
isa-ok $keypair.public, CArray[int8];
