use v6;
use NativeCall;
use LibraryMake;

unit module TweetNacl;

sub library {
    my $so = get-vars('')<SO>;
    return ~%?RESOURCES{"libtweetnacl$so"};
}

#int crypto_box_keypair(u8 *y,u8 *x);
sub crypto_box_keypair_(CArray[int8], CArray[int8]) returns Int is symbol('crypto_box_keypair') is native('tweetnacl');

#https://nacl.cr.yp.to/box.html
sub crypto_box_keypair()
{
    my $secret_key = CArray[int8].new;
    my $public_key = CArray[int8].new;
    my $number_of_ints = 32;
    $secret_key[$number_of_ints - 1] = 0; # extend the array to 32 items
    $public_key[$number_of_ints - 1] = 0; # extend the array to 32 items
    my $n = crypto_box_keypair_($public_key,secret_key);
    my %ret = { secret_key => $secret_key, public_key => $public_key}
    return ret;
}
