use v6;
use Test;
use TweetNacl;
plan 1;

is crypto_box_keypair(), 3;
