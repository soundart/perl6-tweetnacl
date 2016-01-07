use v6;
use NativeCall;
use LibraryMake;

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

#https://nacl.cr.yp.to/box.html
sub crypto_box_keypair() is export
{
    my $secret_key = CArray[int8].new;
    my $public_key = CArray[int8].new;
    my $number_of_ints = 32;
    $secret_key[$number_of_ints - 1] = 0; # extend the array to 32 items
    $public_key[$number_of_ints - 1] = 0; # extend the array to 32 items
    my $n = crypto_box_keypair_int($public_key,$secret_key);
    my %ret := { secret_key => $secret_key, public_key => $public_key};
    return %ret;
}

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

sub nonce()
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

sub crypto_box_test (CArray[int8] $c, CArray[int8] $m, longlong $len, CArray[int8] $nonce, CArray[int8] $pk, CArray[int8] $sk) is export
  {
    return crypto_box_int ($c, $m, $len, $nonce, $pk, $sk);
  }

sub crypto_box (Str $m, CArray[int8] $pk, CArray[int8] $sk) is export
{
    my $crypto_box_NONCEBYTES = 24;
    my $crypto_box_ZEROBYTES = 32;
    my Blob $buf = $m.encode('UTF-8');
    my longlong $mlen = $crypto_box_ZEROBYTES + $buf.elems;
    my $data = CArray[int8].new;
    my $msg  = CArray[int8].new;
    $data[$mlen - 1] = 0; #alloc
    $msg[$mlen - 1] = 0; #alloc
    my $i;
    loop ($i=0; $i < $crypto_box_ZEROBYTES ; $i++)
    {
        $msg[$i] = 0;
    }
    loop ($i=0; $i < $buf.elems; ++$i)
    {
        $msg[$i+$crypto_box_ZEROBYTES] = $buf[$i];
    }
    my $nonce = nonce();
    my $ret = crypto_box_int($data, $msg, $mlen, $nonce, $pk, $sk);
    if ($ret != 0)
    {
        die "crypto_box, bad return code: $ret";
    }
    loop ($i=0; $i < $mlen; ++$i)
    {
        note $i ~ " : " ~ $data[$i];
    }
    return $data;
}


#     const unsigned char pk[crypto_box_PUBLICKEYBYTES];
#     const unsigned char sk[crypto_box_SECRETKEYBYTES];
#     const unsigned char n[crypto_box_NONCEBYTES];
#     const unsigned char c[...]; unsigned long long clen;
#     unsigned char m[...];
#     crypto_box_open(m,c,clen,n,pk,sk);

sub crypto_box_open_int(CArray[int8], CArray[int8], longlong, CArray[int8], CArray[int8], CArray[int8]) is symbol('crypto_box_open') is native('./lib/tweetnacl') returns int32 { * }

sub crypto_box_open(CArray[int8] $c, CArray[int8] $pk, CArray[int8] $sk) is export
{
    my $crypto_box_NONCEBYTES = 24;
    my $crypto_box_ZEROBYTES = 32;
    my $crypto_box_BOXZEROBYTES = 16;
    my $msg  = CArray[int8].new;
    my $nonce  = CArray[int8].new;
    my $clen = $c.elems;
    note "ciphertext len :" ~ $clen;
    $msg[$clen - 1] = 0; #alloc
    $nonce[$crypto_box_NONCEBYTES - 1] = 0; #alloc
    my $i;
    loop ($i=0; $i < $crypto_box_BOXZEROBYTES ; $i++)
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
    loop ($i=0; $i < $clen - $crypto_box_ZEROBYTES ; $i++)
    {
        $buf[$i] = $msg[$i + $crypto_box_ZEROBYTES];
    }
    my Str $s = $buf.decode('UTF-8');
    return $s;
}
