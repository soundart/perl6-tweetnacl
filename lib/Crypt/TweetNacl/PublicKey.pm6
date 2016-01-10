use v6;
use NativeCall;
use LibraryMake;
use TweetNacl::Constants;

unit module Crypt::TweetNacl;

=begin pod
=head1 NAME

	   TweetNacl - crypto library

=head1 SYNOPSIS

    use TweetNacl;

    # create keys
    my $alice = keypair.new;
    my $bob = keypair.new;

    # create Buf to encrypt
    my $msg = 'Hello World'.encode('UTF-8');

    # encrypt
    my $cb = CryptoBox.new(pk => $alice.public , sk => $bob.secret);
    my $data = $cb.encrypt($msg);

    # decrypt
    my $cbo = CryptoBoxOpen.new(pk => $bob.public , sk => $alice.secret);
    my $rmsg = $cbo.decrypt($data);
    say $rmsg.decode('UTF-8')

=head1 DESCRIPTION

=head2 key generation

   class keypair creates a public/secret keypair. And stores them in
   attributes public and secret.

=head2 ciphertext handling

   class ciphertext consists of two attributes: data and a nonce.

   The constructor accepts:
   - CArray with 16 leading zeros, removes them and stores them into the attribute data.
   - And a 24Byte nonce.

   The data without leading zeros can be accessed with the .data accessor.
   The data with leading zeros can be accessed with the .zdata accessor.

   The idea is to transport data(no leading zeros) and nonce to the
   receiver combine them into a new ciphertext and decrypt into the
   plaintext message. Somehow this is still missing...

=head2 encryption

   class CryptoBox encrypts for a public key

   The constructor accepts:
    - the public key of the receiver
    - the secret key of the sender

   method encrypt accepts a Buf and returns class ciphertext

=head2 decryption

   class CryptoBoxOpen decrypts for and verifies the sender
   The constructor accepts:
    - the secret key of the receiver
    - the public key of the sender

   method decrypt accepts a ciphertext and returns a Buf

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

   - https://nacl.cr.yp.to/box.html
   - https://tweetnacl.cr.yp.to/tweetnacl-20131229.pdf

=head1 AUTHOR

    Frank Hartmann

=head1 HISTORY

    v0.0.1 initial version offered at #perl6

=end pod



DOC INIT {
        use Pod::To::Text;
        pod2text($=pod);
}


sub remove_leading_elems($return_type!, $buf!, Int $num_elems) is export(:TESTING)
{
    my $data := $return_type.new;
    my $dlen = $buf.elems - $num_elems;
    $data[$dlen - 1] = 0;
    my $i = 0;
    loop ($i = 0; $i < $dlen; $i++)
    {
        $data[$i] = $buf[$i + $num_elems];
    }
    return $data;
}


constant $tweetnacl = %?RESOURCES<libraries/tweetnacl>.Str;

# https://nacl.cr.yp.to/box.html
# int crypto_box_keypair(u8 *y,u8 *x);

sub crypto_box_keypair_int(CArray[int8], CArray[int8]) is symbol('crypto_box_keypair') is native($tweetnacl) returns int { * }

class keypair is export
{
    has $.secret;
    has $.public;
    submethod BUILD()
    {
        $!secret := CArray[int8].new;
        $!public := CArray[int8].new;
        $!secret[CRYPTO_BOX_SECRETKEYBYTES - 1] = 0; # extend the array to 32 items
        $!public[CRYPTO_BOX_SECRETKEYBYTES - 1] = 0; # extend the array to 32 items
        my $ret = crypto_box_keypair_int($!public,$!secret);
        if ($ret != 0) {
            die "crypto_box_keypair_int, bad return code: $ret";
        }
    }
}
#https://nacl.cr.yp.to/box.html

# void randombytes(unsigned char *x,unsigned long long xlen)

# todo check signedness of xlen
sub randombytes_int(CArray[int8], longlong) is symbol('randombytes') is native($tweetnacl) { * }

sub randombytes(int $xlen!) is export
{
    my $data = CArray[int8].new;
    $data[$xlen - 1] = 0;
    randombytes_int($data, $xlen);
    return $data;
}

sub nonce() is export
{
    return randombytes(CRYPTO_BOX_NONCEBYTES);
}

# const unsigned char pk[crypto_box_PUBLICKEYBYTES];
#     const unsigned char sk[crypto_box_SECRETKEYBYTES];
#     const unsigned char n[crypto_box_NONCEBYTES];
#     const unsigned char m[...]; unsigned long long mlen;
#     unsigned char c[...];
#
#     crypto_box(c,m,mlen,n,pk,sk);

sub crypto_box_int (CArray[int8], CArray[int8], longlong, CArray[int8], CArray[int8], CArray[int8]) is symbol('crypto_box') is native($tweetnacl) is export returns int32 { * };

sub prepend_zeros($buf!, Int $num_zeros!)
{
    my $mlen = $num_zeros + $buf.elems;
    my $msg  = CArray[int8].new;
    $msg[$mlen - 1] = 0;        #alloc
    my Int $i;
    loop ($i=0; $i < $num_zeros ; $i++)
    {
        $msg[$i] = 0;
    }
    loop ($i=0; $i < $buf.elems; ++$i)
    {
        $msg[$i+$num_zeros] = $buf[$i];
    }
    return $msg;
}

sub crypto_box (Blob $buf!, CArray[int8] $nonce!, CArray[int8] $pk!, CArray[int8] $sk!) is export
{
    my longlong $mlen = CRYPTO_BOX_ZEROBYTES + $buf.elems;
    my $data = CArray[int8].new;
    $data[$mlen - 1] = 0;       #alloc
    my $msg  = prepend_zeros($buf, CRYPTO_BOX_ZEROBYTES);
    my $ret = crypto_box_int($data, $msg, $mlen, $nonce, $pk, $sk);
    if ($ret != 0) {
        die "crypto_box, bad return code: $ret";
    }
    return $data;
}

#      unsigned char k[crypto_box_BEFORENMBYTES];
#      const unsigned char pk[crypto_box_PUBLICKEYBYTES];
#      const unsigned char sk[crypto_box_SECRETKEYBYTES];

#      crypto_box_beforenm(k,pk,sk);#int crypto_box_beforenm(u8 *k,const u8 *y,const u8 *x);

sub crypto_box_beforenm_int (CArray[int8], CArray[int8], CArray[int8]) is symbol('crypto_box_beforenm') is native($tweetnacl) is export returns int32 { * };

# const unsigned char k[crypto_box_BEFORENMBYTES];
# const unsigned char n[crypto_box_NONCEBYTES];
# const unsigned char c[...]; unsigned long long clen;
# unsigned char m[...];

# crypto_box_open_afternm(m,c,clen,n,k);

sub crypto_box_afternm_int (CArray[int8], CArray[int8], longlong, CArray[int8], CArray[int8]) is symbol('crypto_box_afternm') is native($tweetnacl) is export returns int32 { * };

class Ciphertext
{
    has $.data;
    has $.nonce;
    has $!dlen;

    submethod BUILD(CArray[int8] :$zdata!, CArray[int8] :$nonce!)
    {
        $!data = remove_leading_elems(CArray[int8], $zdata, CRYPTO_BOX_BOXZEROBYTES);
        $!dlen = $!data.elems;
        $!nonce = $nonce;
    }

    # return data with prepend zeros
    method zdata()
    {
        my $zdata = prepend_zeros($!data, CRYPTO_BOX_BOXZEROBYTES);
        return $zdata;

    }
}

class CryptoBox is export
{
    has $!key;
    submethod BUILD(CArray[int8] :$pk!, CArray[int8] :$sk!)
    {
        $!key := CArray[int8].new;
        $!key[CRYPTO_BOX_BEFORENMBYTES - 1] = 0; # extend the array to 32 items
        my $ret = crypto_box_beforenm_int($!key, $pk, $sk);
        if ($ret != 0) {
            die "crypto_box_beforenm_int, bad return code: $ret";
        }
    }

    multi method encrypt(Blob $buf!, CArray[int8] $nonce!)
    {
        my longlong $mlen = CRYPTO_BOX_ZEROBYTES + $buf.elems;
        my $data = CArray[int8].new;
        $data[$mlen - 1] = 0;   #alloc
        my $msg  = prepend_zeros($buf, CRYPTO_BOX_ZEROBYTES);
        my $ret = crypto_box_afternm_int($data, $msg, $mlen, $nonce, $!key);
        if ($ret != 0) {
            die "crypto_box, bad return code: $ret";
        }
        return $data;
    }

    multi method encrypt(Blob $buf!)
    {
        my $nonce = nonce();
        my $data  = self.encrypt($buf, $nonce);
        my $ciph  = Ciphertext.new(zdata => $data, nonce => $nonce);
        return $ciph;
    }
}


#     const unsigned char pk[crypto_box_PUBLICKEYBYTES];
#     const unsigned char sk[crypto_box_SECRETKEYBYTES];
#     const unsigned char n[crypto_box_NONCEBYTES];
#     const unsigned char c[...]; unsigned long long clen;
#     unsigned char m[...];
#     crypto_box_open(m,c,clen,n,pk,sk);

sub crypto_box_open_int(CArray[int8], CArray[int8], longlong, CArray[int8], CArray[int8], CArray[int8]) is symbol('crypto_box_open') is native($tweetnacl) is export returns int32 { * }


sub crypto_box_open(CArray[int8] $c!, CArray[int8] $nonce!, CArray[int8] $pk!, CArray[int8] $sk!) is export
{
    my $msg  = CArray[int8].new;
    my $clen = $c.elems;
    $msg[$clen - 1] = 0;        #alloc
    my $i;
    loop ($i=0; $i < CRYPTO_BOX_BOXZEROBYTES ; $i++)
    {
        if ($c[$i] != 0) {
            die "crypto_box_open, bad ciphertext";
        }
    }
    my $ret = crypto_box_open_int($msg, $c, $clen, $nonce, $pk, $sk);
    if ($ret != 0) {
        die "crypto_box_open, bad return code: $ret";

    }
    return remove_leading_elems(Buf, $msg, CRYPTO_BOX_ZEROBYTES);
}

# The crypto_box_open_afternm function is callable as follows:

#    #include "crypto_box.h"

#    const unsigned char k[crypto_box_BEFORENMBYTES];
#    const unsigned char n[crypto_box_NONCEBYTES];
#    const unsigned char c[...]; unsigned long long clen;
#    unsigned char m[...];

#    crypto_box_open_afternm(m,c,clen,n,k)

sub crypto_box_open_afternm_int(CArray[int8], CArray[int8], longlong, CArray[int8], CArray[int8]) is symbol('crypto_box_open_afternm') is native($tweetnacl) is export returns int32 { * }

class CryptoBoxOpen is export
{
    has $!key;
    submethod BUILD(CArray[int8] :$pk!, CArray[int8] :$sk!)
    {
        $!key := CArray[int8].new;
        $!key[CRYPTO_BOX_BEFORENMBYTES - 1] = 0; # extend the array to 32 items
        my $ret = crypto_box_beforenm_int($!key, $pk, $sk);
        if ($ret != 0) {
            die "crypto_box_beforenm_int, bad return code: $ret";
        }
    }
    multi method decrypt(CArray[int8] $c!, CArray[int8] $nonce!)
    {
        my $msg  = CArray[int8].new;
        my $clen = $c.elems;
        $msg[$clen - 1] = 0;    #alloc
        my $i;
        loop ($i=0; $i < CRYPTO_BOX_BOXZEROBYTES ; $i++)
        {
            if ($c[$i] != 0) {
                die "crypto_box_open, bad ciphertext";
            }
        }
        my $ret = crypto_box_open_afternm_int($msg, $c, $clen, $nonce, $!key);
        if ($ret != 0) {
            die "crypto_box_open_afternm_int, bad return code: $ret";

        }
        return remove_leading_elems(Buf, $msg, CRYPTO_BOX_ZEROBYTES);
    }

    multi method decrypt(Ciphertext $ciph!)
    {
        return self.decrypt($ciph.zdata, $ciph.nonce);
    }
}
