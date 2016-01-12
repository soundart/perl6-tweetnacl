use v6;
use NativeCall;
use LibraryMake;
use Crypt::TweetNacl::Constants;

unit module Crypt::TweetNacl::Sign;

=begin pod
=head1 NAME

	   Crypt::TweetNacl::Sign - public key crypto library for signing

=head1 SYNOPSIS


=head1 DESCRIPTION

=head1 OPTIONS

=head1 RETURN VALUE

   In case problems arise this is reported by an exception.

=head1 ERRORS


=head1 DIAGNOSTICS


=head1 EXAMPLES


=head1 ENVIRONMENT


=head1 FILES


=head1 CAVEATS

   Various other(not documented) classes and methods might be exported
   by the library. Please ignore them.

=head1 BUGS


=head1 RESTRICTIONS


=head1 NOTES


=head1 SEE ALSO

   - https://nacl.cr.yp.to/sign.html
   - https://tweetnacl.cr.yp.to/tweetnacl-20131229.pdf

=head1 AUTHOR

    Frank Hartmann

=head1 HISTORY


=end pod



DOC INIT {
        use Pod::To::Text;
        pod2text($=pod);
}




#     unsigned char pk[crypto_sign_PUBLICKEYBYTES];
#     unsigned char sk[crypto_sign_SECRETKEYBYTES];

#     crypto_sign_keypair(pk,sk);

sub crypto_sign_keypair_int(CArray[int8], CArray[int8]) is symbol('crypto_sign_keypair') is native(TWEETNACL) returns int { * }

class KeyPair is export
{
    has $.secret;
    has $.public;
    submethod BUILD()
    {
        $!secret := CArray[int8].new;
        $!public := CArray[int8].new;
        $!secret[CRYPTO_SIGN_SECRETKEYBYTES - 1] = 0; # extend the array to 32 items
        $!public[CRYPTO_SIGN_PUBLICKEYBYTES - 1] = 0; # extend the array to 32 items
        my $ret = crypto_sign_keypair_int($!public,$!secret);
        if ($ret != 0) {
            die "crypto_box_keypair_int, bad return code: $ret";
        }
    }
}
