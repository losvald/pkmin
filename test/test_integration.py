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

import binascii
import itertools
import os
import pkmin
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

    def test_minify_no_otp(self):
        out, err = self.call_main({
            '--secret-key': _sec_key_path('rsa2240-s2k-count'),
        })
        self.assertMinified(out, 'RSA_2240_CAST5_SHA1_45678')
        self.assertEqual("", err)

    def assertOptionReminded(self, err, option_str):
        self.assertRegexpMatches(err, 'REMEMBER to pass "%s"' % option_str)

    def test_minify_no_otp_length_diff_prefix_length(self):
        out, err = self.call_main({
            '--secret-key': _sec_key_path('dsa1024-nopass'),
        })
        self.assertMinified(out, 'DSA_1024_NOPASS')
        self.assertOptionReminded(err, "--length-diff 12")
        self.assertOptionReminded(err, "--prefix-length 2")

    def test_minify_allzeroes_key_same_as_no_otp(self):
        arg_dict = {'--secret-key': _sec_key_path('dsa1024-nopass')}
        self.assertEqual(
            hexlify(self.call_main(arg_dict, [], None)[0]),
            hexlify(self.call_main(arg_dict, [], _allzeroes_key_factory)[0]),
        )

    def test_minify_allzeroes_key_same_as_no_otp(self):
        arg_dict = {'--secret-key': _sec_key_path('dsa1024-nopass')}
        self.assertEqual(
            hexlify(self.call_main(arg_dict, [], None)[0]),
            hexlify(self.call_main(arg_dict, [], _allzeroes_key_factory)[0]),
        )

    def test_minify_iota_otp(self):
        octets = _xor_iota(
            self.call_main(
                {'--secret-key': _sec_key_path('dsa1024-nopass')},
                [], _iota_key_factory,
            )[0]
        )
        self.assertMinified(octets, 'DSA_1024_NOPASS')

    def _create_salt_checking_allzeroes_key_factory(self, exp_salt):
        def key_factory(key_len, salt, iter_cnt):
            self.assertEqual(exp_salt, salt)
            return _allzeroes_key_factory(key_len, salt, iter_cnt)
        return key_factory

    def test_minify_otp_salt_no_nonce(self):
        self.call_main(
            {'--secret-key': _sec_key_path('dsa1024-nopass')},
            [],
            self._create_salt_checking_allzeroes_key_factory(
                b"".join(getattr(data.fingerprints, 'DSA_1024_NOPASS'))
            ),
        )

    def test_minify_otp_salt_long_nonce(self):
        nonce = b"0123456789" * 100
        self.call_main(
            {'--secret-key': _sec_key_path('dsa1024-nopass'), '-s': nonce},
            [],
            self._create_salt_checking_allzeroes_key_factory(
                b"".join(getattr(data.fingerprints, 'DSA_1024_NOPASS')) + nonce
            ),
        )

    def assertUnminified(self, out, key):
        with open(_sec_key_path(key)) as unmin_key_file:
            self.assertEqual(hexlify(unmin_key_file.read()), hexlify(out))

    def test_unminify_allzeroes_otp(self):
        key = 'rsa2240-s2k-count'
        arg_dict = {
            '-r': _min_key_path(key),
            '--pubring': _pub_key_path(key),
        }
        args = _create_fingerprint_args('RSA_2240_CAST5_SHA1_45678')
        out, _ = self.call_main(arg_dict, args, _allzeroes_key_factory)
        self.assertUnminified(out, key)

    def test_unminify_iota_otp(self):
        key = 'rsa2240-s2k-count'
        with open(_min_key_path(key)) as key_file:
            xorified_octets = _xor_iota(key_file.read())
        with _string_stream('stdin', xorified_octets):
            out, err = self.call_main(
                {'--pubring': _pub_key_path(key)},
                _create_fingerprint_args('RSA_2240_CAST5_SHA1_45678'),
                _iota_key_factory,
            )
            self.assertUnminified(out, key)

    def test_unminify_no_otp_length_diff(self):
        key = 'dsa1024-nopass'
        arg_dict = {
            '-r': _min_key_path(key),
            '--pubring': _pub_key_path(key),
        }
        args = _create_fingerprint_args('DSA_1024_NOPASS')
        with self.assertRaisesRegexp(ValueError, "length diffs inconsistent"):
            self.call_main(arg_dict, args)

        out, _ = self.call_main(arg_dict, args + [
            "--length-diff", "12",
            "--prefix-length", "2",
        ])
        self.assertUnminified(out, key)

    def test_pbkdf2_otp_reversible_only_if_correct_params(self):
        key = 'rsa2240-s2k-count'
        args = _create_fingerprint_args('RSA_2240_CAST5_SHA1_45678') + [
            '--pubring', _pub_key_path(key),
        ]
        def create_pbkdf2_key_factory(passphrase="S0me p@ss"):
            return pkmin._create_pbkdf2_key_factory(lambda: passphrase)

        min_out, err = self.call_main({
            '--secret-key': _sec_key_path(key),
        }, [], create_pbkdf2_key_factory())
        self.assertEqual("", err)

        with _string_stream('stdin', min_out):
            out, err = self.call_main({
            }, args, create_pbkdf2_key_factory())
            self.assertEqual("", err)
            self.assertUnminified(out, key)

        with _string_stream('stdin', min_out):
            out, err = self.call_main({
                '-i': "42",
            }, args, create_pbkdf2_key_factory())
            self.assertEqual("", err) # validate no errors for wrong -i
            self.assertRaises(AssertionError, self.assertUnminified, out, key)

        with _string_stream('stdin', min_out):
            out, err = self.call_main({
                '-s': "wrong salt",
            }, args, create_pbkdf2_key_factory())
            self.assertEqual("", err) # validate no errors for wrong -s
            self.assertRaises(AssertionError, self.assertUnminified, out, key)

        with _string_stream('stdin', min_out):
            out, err = self.call_main({
            }, args, create_pbkdf2_key_factory("wrong pass"))
            self.assertEqual("", err) # validate no errors for wrong passphrase
            self.assertRaises(AssertionError, self.assertUnminified, out, key)

    def setUp(self):
        setattr(pkmin, 'verbosity', 0)
