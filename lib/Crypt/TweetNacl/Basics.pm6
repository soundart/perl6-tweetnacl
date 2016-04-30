use v6;
use Crypt::Random;
use Crypt::TweetNacl::Constants;

unit module Crypt::TweetNacl::Basics;


sub remove_leading_elems($return_type!, $buf!, Int $num_elems) is export
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


sub buf_to_carray(Buf $buf) is export
{
    my $carray = CArray[int8].new;
    $carray[$_] = $buf[$_] for ^$buf.elems;
    return $carray;
}


sub nonce() is export
{
    return buf_to_carray(crypt_random_buf(CRYPTO_BOX_NONCEBYTES));
}


sub prepend_zeros($buf!, Int $num_zeros!) is export
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

class Ciphertext is export
{
    has $.data;
    has $.nonce;
    has $!dlen;

    submethod BUILD(CArray :$zdata!, CArray :$nonce!)
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
