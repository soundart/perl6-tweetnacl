use v6;
use NativeCall;
use LibraryMake;
use TweetNacl::Constants;
unit module TweetNacl;


sub library {
    my $so = get-vars('')<SO>;
    for @*INC {
        if ($_~'/tweetnacl'~$so).path.r {
            return $_~'/tweetnacl'~$so;
        }
    }
    die "Unable to find libtweetnacl";
}
# https://nacl.cr.yp.to/box.html
# int crypto_box_keypair(u8 *y,u8 *x);

sub crypto_box_keypair_int(CArray[int8], CArray[int8]) is symbol('crypto_box_keypair') is native('./lib/tweetnacl') returns int { * }

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
        if ($ret != 0)
          {
            die "crypto_box_keypair_int, bad return code: $ret";
          }
      }
  }
#https://nacl.cr.yp.to/box.html

# void randombytes(unsigned char *x,unsigned long long xlen)

# todo check signedness of xlen
sub randombytes_int(CArray[int8], longlong) is symbol('randombytes') is native('./lib/tweetnacl') { * }

sub randombytes(int $xlen) is export
{
    my $data = CArray[int8].new;
    $data[$xlen - 1] = 0;
    randombytes_int($data, $xlen);
    return $data;
}

sub nonce() is export
{
    return randombytes(24);
}

# const unsigned char pk[crypto_box_PUBLICKEYBYTES];
#     const unsigned char sk[crypto_box_SECRETKEYBYTES];
#     const unsigned char n[crypto_box_NONCEBYTES];
#     const unsigned char m[...]; unsigned long long mlen;
#     unsigned char c[...];
#
#     crypto_box(c,m,mlen,n,pk,sk);

sub crypto_box_int (CArray[int8], CArray[int8], longlong, CArray[int8], CArray[int8], CArray[int8]) is symbol('crypto_box') is native('./lib/tweetnacl') is export returns int32 { * };


sub crypto_box (Blob $buf, CArray[int8] $nonce, CArray[int8] $pk, CArray[int8] $sk) is export
{
    #my Blob $buf = $m.encode('UTF-8');
    my longlong $mlen = CRYPTO_BOX_ZEROBYTES + $buf.elems;
    my $data = CArray[int8].new;
    my $msg  = CArray[int8].new;
    $data[$mlen - 1] = 0; #alloc
    $msg[$mlen - 1] = 0; #alloc
    my $i;
    loop ($i=0; $i < CRYPTO_BOX_ZEROBYTES ; $i++)
    {
        $msg[$i] = 0;
    }
    loop ($i=0; $i < $buf.elems; ++$i)
    {
        $msg[$i+CRYPTO_BOX_ZEROBYTES] = $buf[$i];
    }
    my $ret = crypto_box_int($data, $msg, $mlen, $nonce, $pk, $sk);
    if ($ret != 0)
    {
        die "crypto_box, bad return code: $ret";
    }
    return $data;
}


#     const unsigned char pk[crypto_box_PUBLICKEYBYTES];
#     const unsigned char sk[crypto_box_SECRETKEYBYTES];
#     const unsigned char n[crypto_box_NONCEBYTES];
#     const unsigned char c[...]; unsigned long long clen;
#     unsigned char m[...];
#     crypto_box_open(m,c,clen,n,pk,sk);

sub crypto_box_open_int(CArray[int8], CArray[int8], longlong, CArray[int8], CArray[int8], CArray[int8]) is symbol('crypto_box_open') is native('./lib/tweetnacl') is export returns int32 { * }

sub crypto_box_open(CArray[int8] $c, CArray[int8] $nonce, CArray[int8] $pk, CArray[int8] $sk) is export
{
    my $msg  = CArray[int8].new;
    my $clen = $c.elems;
    note "ciphertext len :" ~ $clen;
    $msg[$clen - 1] = 0; #alloc
    my $i;
    loop ($i=0; $i < CRYPTO_BOX_BOXZEROBYTES ; $i++)
    {
        if ($c[$i] != 0)
        {
            die "crypto_box_open, bad ciphertext";
        }
    }
    my $ret = crypto_box_open_int($msg, $c, $clen, $nonce, $pk, $sk);
    if ($ret != 0)
    {
        die "crypto_box_open, bad return code: $ret";

    }
    my $buf = Buf.new;
    loop ($i=0; $i < $clen - CRYPTO_BOX_ZEROBYTES ; $i++)
    {
        $buf[$i] = $msg[$i + CRYPTO_BOX_ZEROBYTES];
    }
    my Str $s = $buf.decode('UTF-8');
    return $s;
}
