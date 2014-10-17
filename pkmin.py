# pkmin.py
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

from __future__ import print_function

import argparse
import binascii
import struct
import subprocess
import sys

from collections import namedtuple
from getpass import getpass
from hashlib import pbkdf2_hmac
from os.path import commonprefix

verbosity = 0

_PGP_VERSION_OCTET = b"\x04"

# Paperkey-related constants
_PAPERKEY_FMT_VERSION_OCTET = b"\x00" # paperkey format version length
_FINGERPRINT_OCTET_CNT = 20   # the current version of OpenPGP uses 20 octets
_SECRET_LEN_OCTET_CNT = 2     # length preceding each key printed by paperkey
_SECRET_LEN_PACK_FMT = ">H"   # format passed to pack struct.(un)pack
_CRC_OCTET_CNT_ = 3           # trailing checksum length produced by paperkey
_CRC_FAKED_OCTETS = b"\x00" * _CRC_OCTET_CNT_ # a fake CRC24

# Secret (sub)keys begin with the prefix FE0?030? (empirically verified)
# _SECRET_MAGIC_PREFIX_MASK = b"\xFF\xF0\xFF\xF0"
# _SECRET_MAGIC_PREFIX =      b"\xFE\x00\x03\x00"
_SECRET_COMMON_PREFIX_OCTET_CNT = 13  # likely shared with 1st subkey (E)
_SECRET_PLAINTEXT_TAG = b"\x00"
_SECRET_PLAINTEXT_CHKSUM_OCTET_CNT = 2
_SECRET_PLAINTEXT_CHKSUM_PACK_FMT = ">H" # format passed to pack struct.(un)pack

S2K_CIPHER_ALGOS = {
    'CAST5': b"\x03",
    'BLOWFISH': b"\x04",
    'AES128': b"\x07",
    'AES192': b"\x08",
    'AES256': b"\x09",
    'TWOFISH': b"\x0A",
}
S2K_DIGEST_ALGOS = {
    'SHA1': b"\x02",
    'SHA256': b"\x08",
    'SHA384': b"\x09",
    'SHA512': b"\x0A",
    'SHA224': b"\x0B",
}
S2K = namedtuple('S2K', ['cipher_algo', 'digest_algo', 'count'])
S2K_DEFAULTS = S2K("CAST5", "SHA1", 65536)

def create_s2k(
        cipher_algo=S2K_DEFAULTS.cipher_algo,
        digest_algo=S2K_DEFAULTS.digest_algo,
        count=S2K_DEFAULTS.count,
):
    return S2K(cipher_algo, digest_algo, count)

class ForwardCompatError(Exception):
    def __init__(self, msg_suffix):
        Exception.__init__(self, "not forward-compatible with " + msg_suffix)

class ExternalProgramError(Exception):
    def __init__(self, msg, stderr, returncode):
        Exception.__init__(self, "%s%s" % (
            msg,
            " (exit code = %d)" % returncode if verbosity > 1 else "",
        ))
        self.returncode = returncode
        self.stderr = stderr

def _info(*objs):
    if verbosity >= 0:
        print(*objs, file=sys.stderr)

def _warn(*objs):
    _info("warning:", *objs)

def _create_recovery_reminder(option, arg):
    def to_option_args(arg): # converts to "[option arg...]" if iterable
        try: return " ".join("%s %s" % (option, arg) for arg in arg)
        except TypeError: return to_option_args((arg,))

    return '\n (REMEMBER to pass "%s" in the recovery)' % to_option_args(arg)

def _uppercase_hexlify(octets):
    return binascii.hexlify(octets).upper()

def _compute_checksum(octets, count):
    return sum(bytearray(octets)) & ((1 << (8 * count)) - 1)

def minify(octets):
    if octets[0] != _PAPERKEY_FMT_VERSION_OCTET:
        raise ForwardCompatError("specified paperkey - need format version 00")

    fingerprints = []
    secrets = []
    ind = 1
    ind_to = len(octets) - _CRC_OCTET_CNT_
    while ind < ind_to:
        if octets[ind] != _PGP_VERSION_OCTET:
            raise ForwardCompatError(
                "OpenPGP (sub)key version - need version 04"
            )
        ind += 1

        fingerprint = str(octets[ind : ind + _FINGERPRINT_OCTET_CNT])
        if verbosity > 1:
            _info("Fingerprint:", _uppercase_hexlify(fingerprint))
        fingerprints.append(fingerprint)
        ind += _FINGERPRINT_OCTET_CNT

        secret_len = struct.unpack(
            _SECRET_LEN_PACK_FMT,
            octets[ind : ind + _SECRET_LEN_OCTET_CNT],
        )[0]
        assert secret_len
        ind += _SECRET_LEN_OCTET_CNT

        secret = octets[ind : ind + secret_len]
        ind += secret_len

        if verbosity > 1:
            _info("Prefix:", _uppercase_hexlify(
                secret[:_SECRET_COMMON_PREFIX_OCTET_CNT]
            ))
            _info("Extracted (sub)key length %d" % secret_len)

        # strip off checksum for non-encrypted keys
        if secret[0] == _SECRET_PLAINTEXT_TAG:
            secret = secret[:-_SECRET_PLAINTEXT_CHKSUM_OCTET_CNT]
            if verbosity > 1:
                _info("Secret checksum: %04X" % _compute_checksum(
                    secret,
                    _SECRET_PLAINTEXT_CHKSUM_OCTET_CNT,
                ))

        secrets.append(secret)

    secret_lens = map(len, secrets)
    if len(set(secret_lens)) != 1:
        len_diffs = [sub_len - secret_lens[0] for sub_len in secret_lens[1:]]
        _warn(
            "(Sub)key lengths not unique; |subkey| - |key| = %s" % len_diffs +
            _create_recovery_reminder("--length-diff", len_diffs)
        )

    secret_prefix = bytes(commonprefix(secrets) if len(secrets) else "")
    if verbosity > 0:
        _info("Secret common prefix:", _uppercase_hexlify(secret_prefix))

    if len(secrets) > 2:
        raise NotImplementedError(
            "Multiple subkeys not supported (found %d)" % (len(secrets) - 1),
        )

    if len(secret_prefix) < _SECRET_COMMON_PREFIX_OCTET_CNT:
        _warn(
            "sub(key)s do not share a common prefix of length %d" % (
                _SECRET_COMMON_PREFIX_OCTET_CNT,
            ) + _create_recovery_reminder("--prefix-length", len(secret_prefix))
        )

        # Warn if any redundancy found outside secret common prefix
        matching_octet_cnt = sum(b1 ^ b2 == 0 for b1, b2 in zip(*map(
            lambda s: s[:_SECRET_COMMON_PREFIX_OCTET_CNT],
            map(bytearray, secrets),
        ))) - len(secret_prefix)
        if matching_octet_cnt:
            _warn("%d octets match after secret common prefix %s" % (
                    matching_octet_cnt,
                    _uppercase_hexlify(secret_prefix)
            ))

    out = secret_prefix
    for secret in secrets:
        out += bytes(secret[len(secret_prefix):])
    return out, fingerprints

def unminify(octets, fingerprints, s2k, len_diffs, common_prefix_len):
    if len(len_diffs) != len(fingerprints):
        raise ValueError("length diffs inconsistent with found fingerprints")

    count = len(len_diffs)    # (sub)keys to recover
    if count > 2:
        raise NotImplementedError(
            "Multiple subkeys not supported (requested %d)" % count
        )

    secret_prefix = octets[:common_prefix_len]
    secret_suffix_sum = len(octets) - common_prefix_len
    secret_len_avg = (secret_suffix_sum - sum(len_diffs)) / count
    if (common_prefix_len + sum(len_diffs) + secret_len_avg * count !=
        len(octets)) or secret_suffix_sum < 0:
        raise ValueError("length diffs inconsistent with common prefix length")

    ind = common_prefix_len
    out = bytearray(_PAPERKEY_FMT_VERSION_OCTET)
    for fingerprint, len_diff in zip(fingerprints, len_diffs):
        out += _PGP_VERSION_OCTET
        out += fingerprint
        if verbosity > 1:
            _info("Fingerprint:", _uppercase_hexlify(fingerprint))

        secret_suffix_len = secret_len_avg + len_diff
        secret = secret_prefix + octets[ind : ind + secret_suffix_len]
        ind += secret_suffix_len

        if secret[0] == _SECRET_PLAINTEXT_TAG:
            checksum = _compute_checksum(
                secret, _SECRET_PLAINTEXT_CHKSUM_OCTET_CNT,
            )
            if verbosity > 1:
                _info("Secret checksum: %04X" % checksum)
            secret_suffix_len += _SECRET_PLAINTEXT_CHKSUM_OCTET_CNT
            secret += struct.pack(_SECRET_PLAINTEXT_CHKSUM_PACK_FMT, checksum)

        out += struct.pack(_SECRET_LEN_PACK_FMT, len(secret))
        out += secret

        if verbosity > 1:
            _info("Recovered (sub)key of length", len(secret))

    out += _CRC_FAKED_OCTETS # dump fake CRC24 and use --ignore-crc-error
    return out

def _parse_fingerprints(pgp_out):
    return [
        # TODO: is there a more machine-readable way to retrieve fingerprints?
        "".join(line.partition("=")[-1].split())
        for line in pgp_out.split("\n")
        if "fingerprint" in line and not line.startswith("uid")
    ]

def _quiet_check_output(args, msg, input=None, error_filter=lambda line: True):
    """Run command with arguments and return its output as a byte string,
    with stderr captured but suppressed (unlike subprocess.check_output).

    If the return code was non-zero it raises ExternalProgramError."""

    p = subprocess.Popen(
        args,
        stdin=(subprocess.PIPE if input is not None else None),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    p_out, p_err = p.communicate(input)
    if p.returncode:
        raise ExternalProgramError(
            msg,
            "\n".join(filter(error_filter, p_err.rstrip().split("\n"))),
            p.returncode,
        )
    return p_out

def _xorify(octets, otp):
    if len(octets) != len(otp): raise ValueError
    if not (bytes == type(octets) == type(otp)): raise TypeError

    return bytes(bytearray(
        octet ^ offset
        for octet, offset in zip(bytearray(octets), bytearray(otp))
    ))

def otp(octets, fingerprints, nonce, iter_cnt, key_factory):
    salt = b"".join(fingerprints) + nonce
    return _xorify(octets, key_factory(len(octets), salt, iter_cnt))

def _create_pbkdf2_key_factory(passphrase_factory):
    return lambda key_len, salt, iter_cnt: (
        pbkdf2_hmac('sha512', passphrase_factory(), salt, iter_cnt, key_len)
    )

def _read_passphrase():
    while True:
        pp1, pp2 = (
            getpass("Enter OTP passhrase: "),
            getpass("Repeat the OTP passhrase: "),
        )
        if pp1 == pp2:
            return pp1

def main(args, otp_key_factory=_create_pbkdf2_key_factory(_read_passphrase)):
    global verbosity
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "key", nargs='?',
        help="The secret key to (un)minify (will be passed to gpg)",
    )
    parser.add_argument(
        "-v", "--verbose", dest='verbosity',
        help="Increase output verbosity (can be repeated)",
        action='count', default=0,
    )
    parser.add_argument(
        "-q", "--quiet", action='store_true',
        help="Do not write any errors, warnings or info to stderr",
    )
    parser.add_argument(
        "--paperkey-path", default="paperkey",
        help="The path to the paperkey program",
    )
    parser.add_argument(
        "-p", "--otp", action='store_true',
        help="Use PBKDF2-based one-time pad",
    )
    parser.add_argument(
        "-i", metavar="ITERATIONS", type=int, default=1,
        help="Use that many iterations in PBKDF2",
    )
    parser.add_argument(
        "-s", metavar="SALT", dest='nonce', type=bytes, default="",
        help="Salt suffix to be appended to the each fingerprint",
    )
    coding_group = parser.add_mutually_exclusive_group()
    coding_group.add_argument(
        "-a", "--ascii", action='store_true',
        help="Use base64 coding instead of raw (binary)",
    )
    coding_group.add_argument(
        "-x", "--hex", action='store_true',
        help="Use base16 coding instead of raw (binary)",
    )
    parser.add_argument(
        "--secret-key",
        help="Read the key to minify from this file (not stdin)",
    )
    parser.add_argument(
        "-r", dest='min_key_file', type=argparse.FileType('rb'),
        help="Recover the minified key from this file (not stdin)",
    )
    recov_args = parser.add_argument_group("recovery options")
    recov_args.add_argument(
        "--pubring",
        help="Public keyring used to unminify the key",
    )
    recov_args.add_argument(
        "--fingerprint", metavar='FINGERPRINT', dest='fingerprints',
        action='append',
        help="Specify a (sub)key fingerprint (bypasses gpg)",
    )
    recov_args.add_argument(
        "--gpg-path", default="gpg",
        help="The path to the gpg program",
    )
    recov_args.add_argument(
        "--length-diff", type=int,
        help="|subkey| - |key| (use only if warned)",
    )
    common_prefix_group = recov_args.add_mutually_exclusive_group()
    common_prefix_group.add_argument(
        "--prefix-length", type=int, default=_SECRET_COMMON_PREFIX_OCTET_CNT,
        help="Secret common prefix length (use only if warned)",
    )
    s2k_group = parser.add_argument_group("GPG's --s2k-* options")
    s2k_group.add_argument(
        "--s2k-cipher-algo", default=S2K_DEFAULTS.cipher_algo,
        choices=S2K_CIPHER_ALGOS,
        help="Cipher algorithm that was used to encrypt the key",
    )
    s2k_group.add_argument(
        "--s2k-digest-algo", default=S2K_DEFAULTS.digest_algo,
        choices=S2K_DIGEST_ALGOS,
        help="Digest algorithm that was used to encrypt the key",
    )
    s2k_group.add_argument(
        "--s2k-count", default=S2K_DEFAULTS.count,
        type=int,
        help="Number of times the key passphrase was mangled",
    )

    args = parser.parse_args(args)
    def get_arg(name, default_value):
        arg = getattr(args, name)
        return arg if arg is not None else default_value

    verbosity = args.verbosity if not args.quiet else -1

    if args.key or (args.fingerprints and args.pubring):
        fps = args.fingerprints
        if fps is None:
            fps = _parse_fingerprints(
                _quiet_check_output([
                    args.gpg_path, "--fingerprint", "--fingerprint", args.key,
                ], "failed to retrieve fingerprints from gpg")
            )
            if verbosity > 0:
                for fp in fps:
                    _info("Parsed fingerprint:", fp)
        fps = map(binascii.unhexlify, fps)
        subkey_cnt = len(fps) - 1
        len_diffs = [0] + (
            [args.length_diff] if get_arg('length_diff', 0) else
            [0] * subkey_cnt
        )
        if verbosity > 1:
            _info("Secret length differences:", ' '.join(map(str, len_diffs)))

        s2k = create_s2k(
            cipher_algo=args.s2k_cipher_algo,
            digest_algo=args.s2k_digest_algo,
            count=args.s2k_count,
        )

        octets = get_arg('min_key_file', sys.stdin).read()

        if args.ascii:
            octets = binascii.a2b_base64(octets)
        elif args.hex:
            octets = binascii.a2b_hex(octets)

        if args.otp:
            octets = otp(octets, fps, args.nonce, args.i, otp_key_factory)

        octets = unminify(octets, fps, s2k, len_diffs, args.prefix_length)

        sys.stdout.write(_quiet_check_output(
            [
                args.paperkey_path, "--pubring", args.pubring,
                "--ignore-crc-error",
            ],
            input=octets,
            msg="failed to recover secret key using paperkey",
            error_filter=(
                lambda l: not l.startswith("CRC of secret does not match")
            ),
        ))
    else:
        if args.min_key_file:
            parser.error("not specified the key to unminify")

        octets, fps = minify(_quiet_check_output(
            [args.paperkey_path] + (
                ["--secret-key", args.secret_key] if args.secret_key else []
            ) + ["--output-type", "raw"],
            "failed to extract secret part of the key using paperkey",
        ))

        if args.otp:
            octets = otp(octets, fps, args.nonce, args.i, otp_key_factory)

        if args.ascii:
            print(binascii.b2a_base64(octets))
        elif args.hex:
            print(binascii.b2a_hex(octets))
        else:
            sys.stdout.write(octets)

if __name__ == '__main__':
    def _error(exit_code, *objs):
        _info("%s: " % __file__, *objs)
        sys.exit(exit_code)

    try:
        main(sys.argv[1:])
    except ExternalProgramError as e:
        if verbosity > 0:
            _info(e.stderr)
        _error(1, e)
    except ForwardCompatError as e:
        _error(3, e)
    except NotImplementedError as e:
        _info(
"""Note: storing multiple subkeys is redundant and thus discouraged.
Back up only the master key (with an encryption subkey), then
encrypt other subkeys using the masterkey.
"""
        )
        sys.exit(4)
