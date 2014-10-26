# Introduction #

PKMin is a tool that removes redundancy, increases entropy and
obfuscates a GPG/OpenPGP private key, thus making it smaller (easier
to backup) and more secure. It uses the `paperkey` program but further
removes redundant information such as key fingerprints (which can be
recovered from the public key), checksums, as well as some common
easy-to-remember parameters, such as encryption algorithm.  In
essence, it only leaves the *truly secret part* of the key, such as
the encrypted N bits of the RSA/DSA key and the salt used to stretch
the key passphrase, and obfuscates it using the One-Time Pad to slow
down a brute-force attack.

# Installation #

For simplicity, the whole functionality is provided by a single Python
file.  Therefore, you can run it just like you would normally run a Python
script, i.e.

    $ python /path/to/pkmin/pkmin.py

(`/path/to/pkmin` is the top-level directory where the `pkmin.py` file
resides).

Optionally, you can run test cases from the top-level directory, i.e.

	$ cd /path/to/pkmin
    $ python -m unittest discover test/

or by running each of them individually as a script (i.e., `python
test/test_*.py`).

## Dependencies ##

* Python 2.7 (>= 2.7.8 for obfuscation)
* paperkey 1.3
  ([download link](http://www.jabberwocky.com/software/paperkey/paperkey-1.3.tar.gz))

## PGP ##

The GnuPG (or an OpenPGP-compliant) program is not a dependency, but
it is *recommended* to be installed because it allows a simpler usage.

PKMin has been tested to work correctly with the following versions:

* GnuPG 1.4.11
* GnuPG 2.0.25

but it is expected to work any other release (only the standard flags
`--export-secret-keys` and `--fingerprints` are ever used).

To specify a custom path to the PGP program, use `--gpg-path
/custom/path/to/gpg`.

# Usage #

The main use case is to safely back up a master key. It is designed to
be simple to use for *most* users, and increasingly more complicated for
non-default (and advanced) users who have to *remember* their
customizations. For instance, if you generated your RSA key as follows

    $ gpg --gen-key

and used "John Doe" as the Real name, you would be able to minify it
and print it in Base64 (ASCII) encoding with

    $ python pkmin.py -a 'John Doe'

which would make it ready for a paper backup.

Then, when you need to recover it, you would typically first import
your public key (which can hopefully be recovered from your other
machine or Internet), and then import your unminified key as follows:

    $ python -a -r /path/to/minified_key 'John Doe' | gpg --import

(drop the pipe to just unminify it and print it to stdout).

Finally, if you want your minified key to be obfuscated and thus
harder to crack, just add the "--otp" flag in the examples above.
(You will have to remember an additional passphrase, though.)

## Minification ##

Whether for a convenience or a security precaution, you often want to
minify the key *on the fly*, without storing (a copy of) it to a
temporary file (which might well be world-readable by default). You
can do so by passing the key string "<key>" as an argument (quote
to treat as a single argument), e.g.:

    $ gpg --export-secret-key <key>

which is equivalent to:

    $ gpg --export-secret-key <key> | python pkmin.py

This will minify the key whose associated name/email/comment match the
`<key>` string. In case of multiple matches, the minification will
fail and an error will be reported (which is good, since you probably
do not want to minify some keys *unintentionally*).

Alternatively, if your private key had already been exported to a
file, you can minify it using the `--secret-key` flag, e.g.:

    $ python pkmin.py --secret-key sec_key.bin

**Note**: If your private key had been exported in ASCII armored
 format, you should import it and re-export it as in the binary format
 (default).

### Limitations ###

Currently, only keys with up to 2 subkeys are supported. Partly, this
is a design decision, because the tool is intended to be used to
protect the master key or at least the
["laptop" keypair](https://alexcabal.com/creating-the-perfect-gpg-keypair/#transforming-your-master-keypair-into-your-laptop-keypair)
(the master key with the signing subkey stripped off using
`--export-secret-subkeys` followed by import of the key).

To overcome this limitation, you might want to consider protecting
other (sub)keys by encrypting them using your master key (which tends
to be more secure, anyways).

## Recovery (unminification) ##

If you choose to customize the encryption or cipher algorithm (or even
use none), you will have to *remember* these customizations and pass
them explicitly using flags (switches) during the unminification (key
recovery). For example, if your private key uses AES256 encryption and
the SHA512 digest algorithm (rather than the defaults (CAST5 and SHA1,
respectively), you would typically recover it as follows:

    $ python pkmin.py --s2k-cipher-algo AES256 --s2k-digest-algo SHA512 \
        -r minified_key_file <key> | gpg --import

**Note**: Most of the flags will happily accept "incorrect" arguments
  (valid but unintended). This is a design decision, to make the key
  cracking process harder (since the attacker would need to guess all
  the parameters at once).

### Interaction with PGP ###

You can minimize or ultimately avoid the use of PGP software by
dropping the `<key>` argument and explicitly providing the exported
public key and its fingerprints.

For example, if you had exported your public key from the above
example to `pub_key.bin`, you would instead type:

    $ python pkmin.py --s2k-cipher-algo AES256 --s2k-digest-algo SHA512 \
		--pubring pub_key.bin \
		--fingerprint 17B8A8C4B203A8DD5C43DEE0BC53B0177246FBE1 \
		--fingerprint 974DC99DD3AE21BE69C929C9818FFBD0BEFFD530 \
		> sec_key.bin

which would unminify it without the help of PGP and save it to
`sec_key.bin`, possibly on a machine that is not intended to import
the key. Once you transfer it to the target machine, you would import
it using gpg, i.e. `gpg --import sec_key.bin`.

### Coding ###

**Note**: If you used the non-default (base64 or base16) coding in the
  minification, be *sure* to pass the same flags when unminifying; you
  might not be warned if you omit them (so the recovery might silently
  fail).

## Obfuscation (optional) ##

Normally, your PGP private key is already encrypted. Nevertheless, you
might want to make it even more secure, especially if you plan to back
it up on the Internet.

PKMin allows you to apply the One-Time Pad algorithm on your key,
which is in theory perfectly secure. To derive the OTP key (whose
length may vary), it queries for a passphrase (twice) and stretches it
to the right length using the SHA512 cipher algorithm. Hence, this
"encryption" algorithm is of
[questionable](https://crypto.stackexchange.com/questions/1957/can-pbkdf2-be-used-to-create-an-xor-cipher-key-to-encrypt-random-plaintext/1960)
security, and shall be considered as a means of *obfuscation only*.

**Note**: Keep in mind that *any* passphrase will "successfully"
  unminify a key. This is intentional, to prevent the attacker from
  first focusing on breaking the OTP passphrase and then on breaking
  the encryption passphrase, which would only be marginally more
  secure. (Basically, the attacker needs to try to break the
  encryption passphrase for *each* possible OTP passphrase.)

### Slowing down the attacker ###

You can slow the obfuscation down arbitrarily by increasing the number
of iterations used to derive the OTP key (using PBKDF2) using the `-i`
flag. For instance,

    $ python pkmin.py --hex 'John Doe' --otp -i 1234567

would use 1234567 iterations to derive the OTP key.

The default number of iterations is 65536; it is chosen such that
(un)minification takes *a few seconds* on most comodity machines.

**Note**: It is highly recommended you use a non-default value which
  is easy to remember but fits your security demands (e.g., a
  pragmatic choice would be a value which would cause the program to
  run several minutes or even hours).
