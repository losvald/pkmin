# test_integration.py
#
# Copyright (C) 2014 Leo Osvald (leo.osvald@gmail.com)
#
# This file is part of PKMin.
#
# PKMin is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# PKMin is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with YOUR PROGRAM NAME. If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import

import data.fingerprints
import data.minified
import data.paperkey
import pkmin

import binascii
import itertools
import os
import struct
import sys
import unittest

from binascii import hexlify, unhexlify
from contextlib import contextmanager
from re import escape
from StringIO import StringIO

_SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))

def _allzeroes_key_factory(key_len, salt, iter_cnt):
    return bytes(bytearray(0 for i in range(key_len)))

def _iota_key_factory(key_len, salt, iter_cnt):
    return bytes(bytearray(i & 0xff for i in range(key_len)))

def _key_path(filename):
    path = os.path.join(_SCRIPT_PATH, 'data', filename)
    if not os.path.exists(path):
        raise ValueError("File does not exist: " + path)
    return path

def _pub_key_path(basename):
    return _key_path(basename + '.pub')

def _sec_key_path(basename):
    return _key_path(basename + '.sec')

def _min_key_path(basename):
    return _key_path(basename + '.sec.min')

def _create_fingerprint_args(var):
    return list(itertools.chain.from_iterable(
        ('--fingerprint', hexlify(fp))
        for fp in getattr(data.fingerprints, var)
    ))

def _xor_iota(octets):
    return bytes(bytearray(
        b ^ (i & 0xff) for i, b in enumerate(bytearray(octets))
    ))

@contextmanager
def _string_stream(std_stream, buf=b""):
    if std_stream not in ('stdin', 'stdout', 'stderr'): raise ValueError

    try:
        string_stream = StringIO(buf)
        setattr(sys, std_stream, string_stream)
        yield string_stream
        string_stream.close()
    finally:
        setattr(sys, std_stream, getattr(sys, '__%s__' % std_stream))

class MainTest(unittest.TestCase):
    paperkey_path = os.environ.get('PAPERKEY_PATH', "paperkey")
    gpg_path = os.environ.get('GPG_PATH', "gpg")

    def call_main(self, arg_dict, args=[], otp_key_factory=None):
        arg_dict2 = { # set defaults for arg_dict (without external mods)
            '--paperkey-path': self.paperkey_path,
            '--gpg-path': self.gpg_path,
        }
        arg_dict2.update(arg_dict)
        arg_dict = arg_dict2
        args = filter( # prepend the flattened dict without None values
            lambda x: x is not None,
            itertools.chain.from_iterable(arg_dict.iteritems())
        ) + (['--otp'] if otp_key_factory is not None else []) + args

        with _string_stream('stdout') as stdout:
            with _string_stream('stderr') as stderr:
                pkmin.main(args, otp_key_factory)
                return stdout.getvalue(), stderr.getvalue()

    def assertMinified(self, out, var):
        self.assertEqual(hexlify(getattr(data.minified, var)), hexlify(out))

    def assertOptionReminded(self, err, option_str):
        self.assertRegexpMatches(err, 'REMEMBER to pass "%s"' % option_str)

    def test_minify_s2k_outside_common_prefix_not_reminded(self):
        _, err = self.call_main({
            '--secret-key': _sec_key_path(
                'RSA_4096_CAST5_SHA512_65011712_NOSIGN'
            ),
        })
        self.assertOptionReminded(err, "--prefix-length 2")
        self.assertOptionReminded(err, "--s2k-digest-algo SHA512")

    def test_minify_no_otp_s2k_count_only(self):
        key = 'RSA_2240_CAST5_SHA1_45678'
        out, err = self.call_main({
            '--secret-key': _sec_key_path(key),
        })
        self.assertMinified(out, key)
        self.assertOptionReminded(err, "--s2k-count 47104")
        self.assertNotRegexpMatches(err, "--s2k-cipher-algo")
        self.assertNotRegexpMatches(err, "--s2k-digest-algo")
        self.assertNotRegexpMatches(err, "--length-diff")
        self.assertNotRegexpMatches(err, "--prefix-length")
        self.assertNotRegexpMatches(err, "--plaintext")

    def test_minify_no_otp_length_diff_prefix_length_plaintext(self):
        key = 'DSA_1024_PLAINTEXT'
        out, err = self.call_main({
            '--secret-key': _sec_key_path(key),
        })
        self.assertMinified(out, key)
        self.assertOptionReminded(err, "--length-diff 12")
        self.assertOptionReminded(err, "--prefix-length 2")
        self.assertOptionReminded(err, "--plaintext")

    # def test_minify_no_otp_s2k_cipher_algo_only(self):
    #     raise NotImplementedError

    def test_minify_allzeroes_otp_same_as_no_otp(self):
        arg_dict = {'--secret-key': _sec_key_path('DSA_1024_PLAINTEXT')}
        self.assertEqual(
            hexlify(self.call_main(arg_dict, [], None)[0]),
            hexlify(self.call_main(arg_dict, [], _allzeroes_key_factory)[0]),
        )

    def test_minify_iota_otp_s2k_digest_algo_only(self):
        key = 'DSA_1024_CAST5_SHA512_65536'
        octets, err = self.call_main(
                {'--secret-key': _sec_key_path(key)},
                [], _iota_key_factory,
            )
        self.assertMinified(_xor_iota(octets), key)
        self.assertOptionReminded(err, "--s2k-digest-algo SHA512")
        self.assertNotRegexpMatches(err, "--s2k-cipher-algo")

    def _create_salt_checking_allzeroes_key_factory(self, exp_salt):
        def key_factory(key_len, salt, iter_cnt):
            self.assertEqual(exp_salt, salt)
            return _allzeroes_key_factory(key_len, salt, iter_cnt)
        return key_factory

    def test_minify_otp_salt_no_nonce(self):
        key = 'DSA_1024_PLAINTEXT'
        self.call_main(
            {'--secret-key': _sec_key_path(key)},
            [],
            self._create_salt_checking_allzeroes_key_factory(
                b"".join(getattr(data.fingerprints, key))
            ),
        )

    def test_minify_otp_salt_long_nonce(self):
        key = 'DSA_1024_PLAINTEXT'
        nonce = b"0123456789" * 100
        self.call_main(
            {'--secret-key': _sec_key_path(key), '-s': nonce},
            [],
            self._create_salt_checking_allzeroes_key_factory(
                b"".join(getattr(data.fingerprints, key)) + nonce
            ),
        )

    def assertUnminified(self, out, key):
        with open(_sec_key_path(key)) as unmin_key_file:
            self.assertSequenceEqual(
                hexlify(unmin_key_file.read()),
                hexlify(out),
            )

    def test_unminify_allzeroes_otp(self):
        key = 'RSA_2240_CAST5_SHA1_45678'
        arg_dict = {
            '-r': _min_key_path(key),
            '--pubring': _pub_key_path(key),
            '--s2k-count': "45678",
        }
        args = _create_fingerprint_args(key)
        out, _ = self.call_main(arg_dict, args, _allzeroes_key_factory)
        self.assertUnminified(out, key)

    def test_unminify_iota_otp(self):
        key = 'RSA_2240_CAST5_SHA1_45678'
        with open(_min_key_path(key)) as key_file:
            xorified_octets = _xor_iota(key_file.read())
        with _string_stream('stdin', xorified_octets):
            out, err = self.call_main(
                {
                    '-r': '-',
                    '--pubring': _pub_key_path(key),
                    '--s2k-count': "45678",
                },
                _create_fingerprint_args(key),
                _iota_key_factory,
            )
            self.assertUnminified(out, key)

    def test_unminify_no_otp_length_diff_prefix_length_plaintext(self):
        key = 'DSA_1024_PLAINTEXT'
        arg_dict = {
            '-r': _min_key_path(key),
            '--pubring': _pub_key_path(key),
            '--plaintext': None,
        }
        args = _create_fingerprint_args(key)
        with self.assertRaisesRegexp(ValueError, "length diffs inconsistent"):
            self.call_main(arg_dict, args)

        out, _ = self.call_main(arg_dict, args + [
            "--length-diff", "12",
            "--prefix-length", "2",
        ])
        self.assertUnminified(out, key)

    def test_no_otp_reversible_all_default(self):
        key = 'RSA_2048_CAST5_SHA1_65536'
        args = _create_fingerprint_args(key) + [
            '-r',
            '--pubring', _pub_key_path(key)
        ]

        min_out, err = self.call_main({'--secret-key': _sec_key_path(key)})
        self.assertEqual("", err) # verify no reminders printed

        with _string_stream('stdin', min_out):
            out, err = self.call_main({}, args)
            self.assertEqual("", err)
            self.assertUnminified(out, key)

    def test_no_otp_reversible_s2k_all_custom(self):
        key = 'RSA_4096_AES256_SHA512_65011712'
        args = _create_fingerprint_args(key) + [
            '-r',
            '--pubring', _pub_key_path(key),
            '--s2k-cipher-algo', "AES256",
            '--s2k-digest-algo', "SHA512",
            '--s2k-count', "65011712",
        ]

        min_out, err = self.call_main({'--secret-key': _sec_key_path(key)})

        self.assertOptionReminded(err, "--s2k-count 65011712")
        self.assertOptionReminded(err, "--s2k-cipher-algo AES256")
        self.assertOptionReminded(err, "--s2k-digest-algo SHA512")
        self.assertNotRegexpMatches(err, "--length-diff")
        self.assertNotRegexpMatches(err, "--prefix-length")

        with _string_stream('stdin', min_out):
            out, err = self.call_main({}, args)
            self.assertEqual("", err)
            self.assertUnminified(out, key)

    def test_pbkdf2_otp_reversible_only_if_correct_params(self):
        key = 'RSA_2240_CAST5_SHA1_45678'
        args = _create_fingerprint_args(key) + [
            '-r',
            '--pubring', _pub_key_path(key),
        ]
        def create_pbkdf2_key_factory(passphrase="S0me p@ss"):
            return pkmin._create_pbkdf2_key_factory(lambda: passphrase)

        min_out, err = self.call_main({
            '--secret-key': _sec_key_path(key),
        }, [], create_pbkdf2_key_factory())
        self.assertOptionReminded(err, "--s2k-count 47104")

        with _string_stream('stdin', min_out):
            out, err = self.call_main({
                '--s2k-count': "45678",
            }, args, create_pbkdf2_key_factory())
            self.assertEqual("", err)
            self.assertUnminified(out, key)

        with _string_stream('stdin', min_out):
            out, err = self.call_main({
                '-i': "42",
                '--s2k-count': "45678",
            }, args, create_pbkdf2_key_factory())
            self.assertEqual("", err) # validate no errors for wrong -i
            self.assertRaises(AssertionError, self.assertUnminified, out, key)

        with _string_stream('stdin', min_out):
            out, err = self.call_main({
                '-s': "wrong salt",
                '--s2k-count': "45678",
            }, args, create_pbkdf2_key_factory())
            self.assertEqual("", err) # validate no errors for wrong -s
            self.assertRaises(AssertionError, self.assertUnminified, out, key)

        with _string_stream('stdin', min_out):
            out, err = self.call_main({
            }, args, create_pbkdf2_key_factory("wrong pass"))
            self.assertEqual("", err) # validate no errors for wrong passphrase
            self.assertRaises(AssertionError, self.assertUnminified, out, key)

    # maxDiff = None

    def setUp(self):
        setattr(pkmin, 'verbosity', 0)

if __name__ == '__main__':
    unittest.main()
