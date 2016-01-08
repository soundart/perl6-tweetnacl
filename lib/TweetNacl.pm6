use v6;
use NativeCall;
use LibraryMake;
use TweetNacl::Constants;
unit module TweetNacl;

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

sub randombytes(int $xlen) is export
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

sub crypto_box (Blob $buf, CArray[int8] $nonce, CArray[int8] $pk, CArray[int8] $sk) is export
  {
    my longlong $mlen = CRYPTO_BOX_ZEROBYTES + $buf.elems;
    my $data = CArray[int8].new;
    my $msg  = CArray[int8].new;
    $data[$mlen - 1] = 0;       #alloc
    $msg[$mlen - 1] = 0;        #alloc
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

    submethod BUILD(CArray[int8] :$zdata, CArray[int8] :$nonce)
      {
        $!data := CArray[int8].new;
        $!dlen = $zdata.elems - CRYPTO_BOX_BOXZEROBYTES;
        $!data[$!dlen - 1] = 0; #
        my $i = 0;
        # remove leading zeros
        loop ($i = 0; $i < $!dlen; $i++)
          {
            $!data[$i] = $zdata[$i + CRYPTO_BOX_BOXZEROBYTES];
          }
        $!nonce = $nonce;
      }

    # return data with prepend zeros
    method zdata()
      {
        my $zdata = CArray[int8].new;
        my $zlen = $!dlen + CRYPTO_BOX_BOXZEROBYTES;
        $zdata[$zlen - 1] = 0;
        # prepend zeros
        my $i = 0;
        loop ($i = 0; $i < CRYPTO_BOX_BOXZEROBYTES; $i++)
          {
            $zdata[$i] = 0;
          }
        loop ($i = 0; $i < $!dlen; $i++)
          {
            $zdata[$i + CRYPTO_BOX_BOXZEROBYTES] = $!data[$i];
          }
        return $zdata;

      }
  }
  class CryptoBox is export
  {
    has $!key;
    submethod BUILD(CArray[int8] :$pk, CArray[int8] :$sk)
      {
        $!key := CArray[int8].new;
        $!key[CRYPTO_BOX_BEFORENMBYTES - 1] = 0; # extend the array to 32 items
        my $ret = crypto_box_beforenm_int($!key, $pk, $sk);
        if ($ret != 0) {
          die "crypto_box_beforenm_int, bad return code: $ret";
        }
      }

    multi method encrypt(Blob $buf, CArray[int8] $nonce)
      {
        my longlong $mlen = CRYPTO_BOX_ZEROBYTES + $buf.elems;
        my $data = CArray[int8].new;
        my $msg  = CArray[int8].new;
        $data[$mlen - 1] = 0;   #alloc
        $msg[$mlen - 1] = 0;    #alloc
        my $i;
        loop ($i=0; $i < CRYPTO_BOX_ZEROBYTES ; $i++)
          {
            $msg[$i] = 0;
          }
        loop ($i=0; $i < $buf.elems; ++$i)
          {
            $msg[$i+CRYPTO_BOX_ZEROBYTES] = $buf[$i];
          }
        my $ret = crypto_box_afternm_int($data, $msg, $mlen, $nonce, $!key);
        if ($ret != 0) {
          die "crypto_box, bad return code: $ret";
        }
        return $data;
      }

    multi method encrypt(Blob $buf)
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


  sub crypto_box_open(CArray[int8] $c, CArray[int8] $nonce, CArray[int8] $pk, CArray[int8] $sk) is export
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
    my $buf = Buf.new;
    loop ($i=0; $i < $clen - CRYPTO_BOX_ZEROBYTES ; $i++)
      {
        $buf[$i] = $msg[$i + CRYPTO_BOX_ZEROBYTES];
      }
    return $buf;
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
    submethod BUILD(CArray[int8] :$pk, CArray[int8] :$sk)
      {
        $!key := CArray[int8].new;
        $!key[CRYPTO_BOX_BEFORENMBYTES - 1] = 0; # extend the array to 32 items
        my $ret = crypto_box_beforenm_int($!key, $pk, $sk);
        if ($ret != 0) {
          die "crypto_box_beforenm_int, bad return code: $ret";
        }
      }
    multi method decrypt(CArray[int8] $c, CArray[int8] $nonce)
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
        my $buf = Buf.new;
        loop ($i=0; $i < $clen - CRYPTO_BOX_ZEROBYTES ; $i++)
          {
            $buf[$i] = $msg[$i + CRYPTO_BOX_ZEROBYTES];
          }
        return $buf;
      }

    multi method decrypt(Ciphertext $ciph)
      {
        return self.decrypt($ciph.zdata, $ciph.nonce);
      }
  }
