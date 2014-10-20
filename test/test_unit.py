# test_unit.py
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
import struct
import unittest

from binascii import hexlify, unhexlify

class ParseFingerprintTest(unittest.TestCase):
    def assertParses(self, gpg_out, *fingerprints):
        actual = pkmin._parse_fingerprints(gpg_out)
        expected = list(fingerprints)
        self.assertEqual(expected, actual)

    def test_gnupg_1_4_11_single_subkey(self):
        self.assertParses(
"""pub   4096R/6032CFB7 2014-09-20
      Key fingerprint = 45AB EF37 5D57 EDC7 39F2  B8A1 D48F 0FE7 6032 CFB7
uid                  for safe (safe) <for.safe@for.safe>
sub   4096R/A924561F 2014-09-20
      Key fingerprint = ABDF E51D 9755 EC4C AC94  043A 35B1 129F A924 561F

""",
            "45ABEF375D57EDC739F2B8A1D48F0FE76032CFB7",
            "ABDFE51D9755EC4CAC94043A35B1129FA924561F",
        )

    def test_gnupg_2_0_25_no_subkeys(self):
        self.assertParses(
"""pub   2048R/2F80F67E 2014-09-14
      Key fingerprint = 3768 45AE 4A9E F7AC 2D97  EEC1 754C 07F6 2F80 F67E
uid       [ unknown] John Doe (test) <jdoe@domain.com>

""",
            "376845AE4A9EF7AC2D97EEC1754C07F62F80F67E",
        )

    def test_gnupg_1_4_11_no_subkey_fingerprint_in_uid(self):
        self.assertParses(
"""pub   1024D/0FB7BC55 2014-09-27
      Key fingerprint = 88B5 D1E4 C431 2CBD 662A  43C9 70F3 0FBB 0FB7 BC55
uid                  Key fingerprint = 88B5 D1E4 C431 2CBD 662A  43C9 70F3 0FBB 0FB7 BC55
sub   1024g/A45C44E6 2014-09-27

""",
            "88B5D1E4C4312CBD662A43C970F30FBB0FB7BC55",
        )

class XorifyTest(unittest.TestCase):
    def test_diff_lengths_raises_value_error(self):
        self.assertRaises(ValueError, pkmin._xorify, b"\x01", b"\x01\x02")
        self.assertRaises(ValueError, pkmin._xorify, b"\x010203", b"\x01")
        self.assertRaises(ValueError, pkmin._xorify, b"\x010203", b"")
        self.assertRaises(ValueError, pkmin._xorify, b"", b"\x42")

    def test_str_raises_value_error(self):
        if bytes != str:        # for Python 3
            self.assertRaises(ValueError, pkmin._xorify, b"\x75", "\xba")
            self.assertRaises(ValueError, pkmin._xorify, "\x12", b"\x13")
            self.assertRaises(ValueError, pkmin._xorify, "\x88", "\x88")

    def test_reversible_all_otp(self):
        octets = b"\xca\xfe"
        s = set()
        for octet1 in range(0x100):
            for octet2 in range(0x100):
                otp = struct.pack("BB", octet1, octet2)
                octets_xored = pkmin._xorify(octets, otp)
                octets_rexored = pkmin._xorify(octets_xored, otp)
                self.assertEqual(octets, octets_rexored)
                s.add(octets_xored)
        assert len(s) == 0x10000

    def test_reversible_long_otp(self):
        octets = b"\x1b\xfa\x07\xe4\x69" * 103 + b"\x85\x72" * 5678
        otp = bytes(bytearray(reversed(octets)))
        self.assertEqual(octets, pkmin._xorify(pkmin._xorify(octets, otp), otp))

class S2KCountCodecTest(unittest.TestCase):
    codec = pkmin.S2KCountCodec()
    def test_decode(self):
        for octet, exp in {
                b"\x00": 1024,
                b"\x0a": 1664,
                b"\x33": 9728,
                b"\x5c": 57344,
                b"\xb2": 2359296,
                b"\xfe": 62914560,
                b"\xff": 65011712,
        }.iteritems():
            self.assertEqual(exp, self.codec.decode(octet))

    def test_encode(self):
        for octet, exp in {
                0: b"\x00", 1023: b"\x00", 1024: b"\x00",
                1664: b"\x0a",
                1665: b"\x0b",
                9728: b"\x33",
                57344: b"\x5c",
                2359296: b"\xb2",
                64000000: b"\xFF",
                65011712: b"\xFF",
        }.iteritems():
            self.assertEqual(hexlify(exp), hexlify(self.codec.encode(octet)))

    def test_invertible(self):
        for octet in bytes(bytearray(i for i in range(0x100))):
            count = self.codec.decode(octet)
            self.assertTrue(1024 <= count <= 65011712)
            self.assertEqual(octet, self.codec.encode(count))

class MinifyTest(unittest.TestCase):
    def assertMinifies(self, var):
        act_key, act_fps, s2k = pkmin.minify(getattr(data.paperkey, var))
        act_key = hexlify(act_key)
        self.assertEqual(
            (hexlify(getattr(data.minified, var)),
             getattr(data.fingerprints, var)),
            (act_key, act_fps)
        )
        return s2k

    def test_rsa_2048_default_s2k(self):
        s2k = self.assertMinifies('RSA_2048_CAST5_SHA1_65536')
        self.assertEqual(pkmin.S2K_DEFAULTS, s2k)

    def test_dsa_1024_plaintext_diff_subkey_len(self):
        s2k = self.assertMinifies('DSA_1024_PLAINTEXT')
        self.assertIsNone(s2k)

    def test_dsa_1024_sha512_diff_subkey_len(self):
        s2k = self.assertMinifies('DSA_1024_CAST5_SHA512_65536')
        self.assertNotEqual(None, s2k)
        self.assertEqual(pkmin.S2K_CIPHER_ALGOS['CAST5'], s2k.cipher_algo)
        self.assertEqual(pkmin.S2K_DIGEST_ALGOS['SHA512'], s2k.digest_algo)
        self.assertEqual(pkmin.S2KCountCodec().encode(65536), s2k.count)

    def test_rsa_2240_custom_s2k_count(self):
        s2k = self.assertMinifies('RSA_2240_CAST5_SHA1_45678')
        self.assertEqual(pkmin.S2KCountCodec().encode(45678), s2k.count)
        self.assertEqual(pkmin.S2K_DIGEST_ALGOS['SHA1'], s2k.digest_algo)

    def test_rsa_4096_sha512_max_s2k_count_nosign(self):
        self.assertMinifies('RSA_4096_CAST5_SHA512_65011712_NOSIGN')

    @classmethod
    def setUpClass(cls):
        setattr(pkmin, 'verbosity', -1)
        cls.maxDiff = None

    # def setUp(self):
    #     setattr(pkmin, 'verbosity', 2)
    #     pkmin._info("\n===", '.'.join(self.id().split('.')[-2:]), "===")

class UnminifyTest(unittest.TestCase):
    def assertUnminifies(self, var, len_diffs, prefix_len, **s2k):
        act_key = pkmin.unminify(
            getattr(data.minified, var),
            getattr(data.fingerprints, var),
            None if s2k.get('plaintext') else
            pkmin.S2K_DEFAULTS._replace(**s2k),
            len_diffs,
            prefix_len,
        )
        # strip off the ignored CRC-24 checksum and hexlify (for better diff)
        act_key = hexlify(act_key[:-pkmin._CRC_OCTET_CNT])
        exp_key = hexlify(getattr(data.paperkey, var)[:-pkmin._CRC_OCTET_CNT])
        self.assertSequenceEqual(exp_key, act_key)

    def test_rsa_2240_default_s2k(self):
        self.assertUnminifies(
            'RSA_2048_CAST5_SHA1_65536',
            [0, 0],
            13,
        )

    def test_dsa_1024_plaintext_diff_subkey_len(self):
        self.assertUnminifies('DSA_1024_PLAINTEXT', [0, 12], 2, plaintext=True)

    def test_dsa_1024_sha512_diff_subkey_len(self):
        self.assertUnminifies(
            'DSA_1024_CAST5_SHA512_65536',
            [0, 11],
            13,
            digest_algo=pkmin.S2K_DIGEST_ALGOS['SHA512'],
        )

    def test_rsa_2240_custom_s2k_count(self):
        self.assertUnminifies(
            'RSA_2240_CAST5_SHA1_45678',
            [0, 0],
            13,
            count=pkmin.S2KCountCodec().encode(45678),
        )

    def test_rsa_4096_sha512_max_s2k_count_nosign(self):
        self.assertUnminifies(
            'RSA_4096_CAST5_SHA512_65011712_NOSIGN',
            [0, 1321 - 3],
            2,
            digest_algo=pkmin.S2K_DIGEST_ALGOS['SHA512'],
            count=pkmin.S2KCountCodec().encode(65011712),
        )

    @classmethod
    def setUpClass(cls):
        setattr(pkmin, 'verbosity', -1)
        cls.maxDiff = None

    # def setUp(self):
    #     setattr(pkmin, 'verbosity', 2)
    #     pkmin._info("\n===", '.'.join(self.id().split('.')[-2:]), "===")

if __name__ == '__main__':
    unittest.main()
