use v6;
use Test;
use Crypt::TweetNacl::PublicKey;
plan 1;

my $a = randombytes(42);
my $b = randombytes(42);
nok $a eqv $b;
