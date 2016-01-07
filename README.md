NAME
====

TweetNacl - crypto lib

SYNOPSIS
========

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


INSTALL
=======

    export PATH=~/.rakudobrew/bin:$PATH
    export PATH=~/.rakudobrew/moar-2015.12/install/share/perl6/site/bin:$PATH

    perl6 Configure.pl6
    make
    make test
    # panda install git://github.com/soundart/perl6-tweetnacl.git

DESCRIPTION
===========

For details see
- https://nacl.cr.yp.to/box.html
- http://tweetnacl.cr.yp.to/tweetnacl-20131229.pdf.

This is my first perl6 attempt. Feedback very much appreciated.

open questions:

- how to do the panda thing

- class Ciphertext: attributes $!data and $!nonce have to be
  transported(e.g. send via network) from encryption to
  decryption host. Should there be a serialize() method?

- howto make "make test" load the shared lib, without native('./lib/tweetnacl')

COPYRIGHT AND LICENSE
=====================

see LICENSE
