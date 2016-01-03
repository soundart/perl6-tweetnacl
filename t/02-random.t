use v6;
use Test;
use TweetNacl;
plan 1;

my $a = randombytes(42);
my $b = randombytes(42);
nok $a eqv $b;
