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
_CRC_OCTET_CNT = 3           # trailing checksum length produced by paperkey
_CRC_FAKED_OCTETS = b"\x00" * _CRC_OCTET_CNT # a fake CRC24

_SECRET_COMMON_PREFIX_OCTET_CNT = 13  # likely shared with 1st subkey (E)
_SECRET_PLAINTEXT_TAG = b"\x00"
_SECRET_PLAINTEXT_CHKSUM_OCTET_CNT = 2
_SECRET_PLAINTEXT_CHKSUM_PACK_FMT = ">H" # format passed to pack struct.(un)pack
_SECRET_S2K_TAGS = (b"\xFE", b"\xFF")
_SECRET_S2K_MODE_ITER_SALTED_OCTET = b"\x03"
_SECRET_S2K_SALT_IND = 4 # index at which the non-stripped S2K salt begins
_SECRET_S2K_SALT_OCTET_CNT = 8

def _reversed_dict(d):
    return dict((v, k) for k, v in d.items())

class S2KCountCodec(object):
    @property
    def _expbias(self): return 6
    @property
    def _shift(self): return 4
    @property
    def _mask(self): return (1 << self._shift) - 1

    def decode(self, octet):
        c = ord(octet)
        return (1 + self._mask + (c & self._mask)) << (
            (c >> self._shift) + self._expbias)

    @classmethod
    def _to_bytes(cls, ordinal):
        return bytes(bytearray([ordinal]))

    def encode(self, count):
        # TODO: reduce time complexity to O(1) by reverse-engineering decode()
        lo, hi = 0x00, 0xFF
        while lo < hi:          # round up octet using binary search
            mid = (lo + hi - 1) // 2
            mid_count = self.decode(self._to_bytes(mid))
            if mid_count >= count:
                hi = mid
            else:
                lo = mid + 1
        return self._to_bytes(hi)

S2K_CIPHER_ALGOS = {
    # 'IDEA': b"\x01", # discouraged as it is broken
    # '3DES': b"\x02", # discouraged as it is broken
    'CAST5': b"\x03",
    # 'BLOWFISH': b"\x04", # discouraged as there is a class of known weak keys
    'AES128': b"\x07",
    'AES192': b"\x08",
    'AES256': b"\x09",
    'TWOFISH': b"\x0A",
}
S2K_CIPHER_OCTETS = _reversed_dict(S2K_CIPHER_ALGOS)
S2K_DIGEST_ALGOS = {
    # 'MD5': b"\x01", # deprecated
    'SHA1': b"\x02",
    'RIPEMD160': b"\x03",
    'SHA256': b"\x08",
    'SHA384': b"\x09",
    'SHA512': b"\x0A",
    'SHA224': b"\x0B",
}
S2K_DIGEST_OCTETS = _reversed_dict(S2K_DIGEST_ALGOS)
S2K = namedtuple('S2K', ['cipher_algo', 'digest_algo', 'count'])
S2K_DEFAULTS = S2K(
    S2K_CIPHER_ALGOS['CAST5'],
    S2K_DIGEST_ALGOS['SHA1'],
    S2KCountCodec().encode(65536),
)

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

def _create_recovery_reminder(option, arg=None):
    def to_option_args(arg):
        if arg is None:
            return option
        try: # converts to "[option arg...]" if iterable but not string
            if not isinstance(arg, str):
                return " ".join("%s %s" % (option, arg) for arg in arg)
        except TypeError:
            pass
        return to_option_args((arg,))

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
    ind_to = len(octets) - _CRC_OCTET_CNT
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

    if not secrets:
        raise ValueError("Invalid secret key data.")

    scp = bytes(commonprefix(secrets))
    if verbosity > 0:
        _info("Secret common prefix:", _uppercase_hexlify(scp))

    if len(secrets) > 2:
        raise NotImplementedError(
            "Multiple subkeys not supported (found %d)" % (len(secrets) - 1),
        )

    if len(scp) < _SECRET_COMMON_PREFIX_OCTET_CNT:
        _warn(
            "sub(key)s do not share a common prefix of length %d" % (
                _SECRET_COMMON_PREFIX_OCTET_CNT,
            ) + _create_recovery_reminder("--prefix-length", len(scp))
        )

        # Warn if any redundancy found outside secret common prefix
        matching_octet_cnt = sum(b1 ^ b2 == 0 for b1, b2 in zip(*map(
            lambda s: s[:_SECRET_COMMON_PREFIX_OCTET_CNT],
            map(bytearray, secrets),
        ))) - len(scp)
        if matching_octet_cnt:
            _warn("%d octets match after secret common prefix %s" % (
                    matching_octet_cnt,
                    _uppercase_hexlify(scp)
            ))

    def strip_s2k_part(secret):
        scp_strip_cnt, secret_len0 = 0, len(secret)
        cipher_algo, mode, digest_algo, count = None, None, None, None
        ret = lambda: (
            secret,
            scp_strip_cnt,
            S2K(cipher_algo, digest_algo, count) if digest_algo else None,
        )
        if not any(secret.startswith(tag) for tag in _SECRET_S2K_TAGS):
            return ret()

        first_octet, secret = secret[0], secret[1:]
        try: # avoid multiple "if len(secret)" by catching IndexError
            cipher_algo, secret = secret[0], secret[1:]

            mode, secret = secret[0], secret[1:]
            if mode != _SECRET_S2K_MODE_ITER_SALTED_OCTET:
                raise NotImplementedError("only --s2k-mode 3 keys supported")

            digest_algo, secret = secret[0], secret[1:]

            # force raising IndexError if prefix too short
            count, secret = (
                secret[_SECRET_S2K_SALT_OCTET_CNT],
                secret[: _SECRET_S2K_SALT_OCTET_CNT] +
                secret[_SECRET_S2K_SALT_OCTET_CNT + 1 :],
            )
        except IndexError:
            raise ValueError("Invalid secret key - incomplete S2K part")
        finally:
            scp_strip_cnt = min(secret_len0 - len(secret), len(scp))
            if _SECRET_S2K_SALT_IND < scp_strip_cnt and (
                len(scp) <= _SECRET_S2K_SALT_IND + _SECRET_S2K_SALT_OCTET_CNT
            ): # handle the case when common prefix does not contain S2K count
                scp_strip_cnt -= 1

            return ret()

    # Strip S2K only from the subkey only (or key if no subkeys),
    # and strip common prefix from the remaining (sub)keys
    # Note that the opposite wouldn't work in case of --export-secret-subkeys,
    # since the first subkey would have a different, non-standard, S2K part
    # and S2K part of the 2nd would not be fully contained in the common prefix:
    # __ __               <- secret common prefix of length <= 2
    # F? ?? 6? ?? ??      <- s2k mode octet (#3) is 0x64-0x6E (experimental)
    # F? ?? 0? ?? ?? ...  <- s2k mode octet (#3) is 0x00, 0x01 or 0x03
    secrets[-1], last_scp_strip_cnt, s2k = strip_s2k_part(secrets[-1])
    secrets[-1] = secrets[-1][len(scp) - last_scp_strip_cnt :]
    secrets[:-1] = map(lambda s: s[len(scp):], secrets[:-1])
    scp, min_scp_strip_cnt, _ = strip_s2k_part(scp) # strip S2K part from SCP

    secret_lens = map(len, secrets)
    if len(set(secret_lens)) != 1:
        len_diffs = [
            sub_len - secret_lens[0] - (last_scp_strip_cnt - min_scp_strip_cnt)
            for sub_len in secret_lens[1:]
        ]
        _warn(
            "(Sub)key lengths not unique; |subkey| - |key| = %s" % len_diffs +
            _create_recovery_reminder("--length-diff", len_diffs)
        )
    del secret_lens

    # Remind for non-default S2K options
    if not last_scp_strip_cnt:
        _warn("key not encrypted" + _create_recovery_reminder("--plaintext"))
    else:
        crr = _create_recovery_reminder # reduce verbosity by aliasing
        if s2k.digest_algo != S2K_DEFAULTS.digest_algo:
            _warn(
                "did not use the %s secret-to-key digest algorithm" % (
                    S2K_DIGEST_OCTETS[S2K_DEFAULTS.digest_algo]
                ) + crr("--s2k-digest-algo", S2K_DIGEST_OCTETS[s2k.digest_algo])
            )
        if s2k.cipher_algo != S2K_DEFAULTS.cipher_algo:
            _warn(
                "did not use the %s secret-to-key cipher algorithm" % (
                    S2K_CIPHER_OCTETS[S2K_DEFAULTS.cipher_algo]
                ) + crr("--s2k-cipher-algo", S2K_CIPHER_OCTETS[s2k.cipher_algo])
            )
        if s2k.count != S2K_DEFAULTS.count:
            count_codec = S2KCountCodec()
            _warn(
                "passphrase was not mangled %d times" % (
                    count_codec.decode(S2K_DEFAULTS.count)
                ) + crr("--s2k-count", count_codec.decode(s2k.count))
            )
        del crr

    out = scp
    for secret in secrets:
        out += secret
    return out, fingerprints, s2k

def unminify(octets, fingerprints, s2k, len_diffs, implicit_scp_len):
    if len(len_diffs) != len(fingerprints):
        raise ValueError("length diffs inconsistent with found fingerprints")
    if not fingerprints:
        raise ValueError("no (sub)key to unminify")

    subkey_cnt = len(len_diffs)      # number of (sub)keys
    if subkey_cnt > 2:
        raise NotImplementedError(
            "Multiple subkeys not supported (requested %d)" % subkey_cnt
        )

    scp_len = implicit_scp_len
    if s2k:
        # scp_len = max(scp_len - _SECRET_S2K_SALT_IND - (
        #     scp_len > _SECRET_S2K_SALT_IND + _SECRET_S2K_SALT_OCTET_CNT), 0)
        # s2k_outside_scp_cnt = max(_SECRET_S2K_SALT_OCTET_CNT - scp_len, 0)
        if scp_len < _SECRET_S2K_SALT_IND + _SECRET_S2K_SALT_OCTET_CNT:
            scp_len = max(scp_len - _SECRET_S2K_SALT_IND, 0)
            s2k_outside_scp_cnt = _SECRET_S2K_SALT_OCTET_CNT - scp_len
        else:
            scp_len -= _SECRET_S2K_SALT_IND
            if scp_len > _SECRET_S2K_SALT_OCTET_CNT: # if S2K count not in scp
                scp_len -= 1
            s2k_outside_scp_cnt = 0
        if verbosity > 1:
            _info("%d octets of S2K salt outside secret common prefix" % (
                s2k_outside_scp_cnt
            ))

    secret_suffix_sum = len(octets) - scp_len
    secret_len_avg = (secret_suffix_sum - sum(len_diffs)) / subkey_cnt
    if (scp_len + sum(len_diffs) + secret_len_avg * subkey_cnt !=
        len(octets)) or secret_suffix_sum < 0:
        raise ValueError("length diffs inconsistent with common prefix length")
    del secret_suffix_sum

    # Strip off (part of) S2K salt from the last subkey (if present)
    if s2k:
        s2k_salt = octets[: min(scp_len, _SECRET_S2K_SALT_OCTET_CNT)]
        if s2k_outside_scp_cnt:
            last_secret_ind = secret_len_avg + len_diffs[-1]
            s2k_salt += octets[
                -last_secret_ind : -last_secret_ind + s2k_outside_scp_cnt
            ]
            octets = (
                octets[:-last_secret_ind] +
                octets[-last_secret_ind + s2k_outside_scp_cnt :]
            )
        if verbosity > 0:
            _info("S2K salt: ", _uppercase_hexlify(s2k_salt))

    s2k_part_len_max = 4 + _SECRET_S2K_SALT_OCTET_CNT + 1
    last_prefix = octets[:implicit_scp_len] if s2k is None else (
        _SECRET_S2K_TAGS[0] + s2k.cipher_algo +
        _SECRET_S2K_MODE_ITER_SALTED_OCTET + s2k.digest_algo +
        s2k_salt + s2k.count
    )
    secret_prefixes = [
        last_prefix[:implicit_scp_len] for i in range(subkey_cnt - 1)
    ] + [last_prefix]

    if verbosity > 2:
        _info("Explicit Common Prefix length:", scp_len)
        _info("Prefixes:", map(_uppercase_hexlify, secret_prefixes))

    ind = scp_len
    out = bytearray(_PAPERKEY_FMT_VERSION_OCTET)
    for len_diff, fp, secret_prefix in zip(
            len_diffs, fingerprints, secret_prefixes
    ):
        out += _PGP_VERSION_OCTET
        out += fp
        if verbosity > 1:
            _info("Fingerprint:", _uppercase_hexlify(fp))

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
        # TODO: is there a more machine-friendly way to retrieve fingerprints?
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
        help="the secret key to (un)minify (will be passed to gpg)",
    )
    parser.add_argument(
        "-v", "--verbose", dest='verbosity',
        help="increase output verbosity (can be repeated)",
        action='count', default=0,
    )
    parser.add_argument(
        "-q", "--quiet", action='store_true',
        help="do not write any errors, warnings or info to stderr",
    )
    coding_group = parser.add_mutually_exclusive_group()
    coding_group.add_argument(
        "-a", "--ascii", action='store_true',
        help="use base64 coding instead of raw (binary)",
    )
    coding_group.add_argument(
        "-x", "--hex", action='store_true',
        help="use base16 coding instead of raw (binary)",
    )

    parser.add_argument(
        "-p", "--otp", action='store_true',
        help="use PBKDF2-based one-time pad",
    )
    parser.add_argument(
        "-i", metavar="N_ITER", type=int, default=65536,
        help="use that many iterations in PBKDF2",
    )
    parser.add_argument(
        "-s", metavar="SALT_SUFFIX", dest='nonce', type=bytes, default="",
        help="append OTP salt suffix to fingerprints (use as nonce)",
    )

    min_unmin_group = parser.add_mutually_exclusive_group()
    min_unmin_group.add_argument(
        "-r", dest='min_key_file', nargs='?', type=argparse.FileType('rb'),
        const='-',              # make stdin the implicit argument
        help="recover the minified key from the path or stdin",
    )
    min_unmin_group.add_argument(
        "--secret-key", metavar="FILE",
        help="read the key to minify from this file (not stdin)",
    )
    parser.add_argument(
        "--paperkey-path", metavar="PATH", default="paperkey",
        help="the path to the paperkey program",
    )
    parser.add_argument(
        "--gpg-path", metavar="PATH", default="gpg",
        help="the path to the gpg program",
    )

    recov_args = parser.add_argument_group("recovery options")
    recov_args.add_argument(
        "--pubring", metavar="PATH",
        help="public keyring used to unminify the key",
    )
    recov_args.add_argument(
        "--fingerprint", metavar="HEX", dest='fingerprints',
        action='append',
        help="(sub)key fingerprint (bypasses gpg, can be repeated)",
    )
    recov_args.add_argument(
        "--length-diff", metavar="DIFF", type=int,
        help="|subkey| - |key| (use only if warned)",
    )
    recov_args.add_argument(
        "--prefix-length", metavar="N",
        type=int, default=_SECRET_COMMON_PREFIX_OCTET_CNT,
        help="secret common prefix length (use only if warned)",
    )
    recov_args.add_argument(
        "--plaintext", action='store_true',
        help="interpret the key to unminify as plaintext",
    )
    recov_args.add_argument(
        "--s2k-cipher-algo", choices=S2K_CIPHER_ALGOS,
        default=S2K_CIPHER_OCTETS[S2K_DEFAULTS.cipher_algo],
        help="cipher algorithm that was used to encrypt the key",
    )
    recov_args.add_argument(
        "--s2k-digest-algo", choices=S2K_DIGEST_ALGOS,
        default=S2K_DIGEST_OCTETS[S2K_DEFAULTS.digest_algo],
        help="digest algorithm that was used to encrypt the key",
    )
    recov_args.add_argument(
        "--s2k-count", metavar="N_ITER",
        type=int, default=S2KCountCodec().decode(S2K_DEFAULTS.count),
        help="number of times the key passphrase was mangled",
    )

    args = parser.parse_args(args)
    def get_arg(name, default_value):
        arg = getattr(args, name)
        return arg if arg is not None else default_value

    verbosity = args.verbosity if not args.quiet else -1

    def export_fingerprints():
        pgp_out = _quiet_check_output([
            args.gpg_path, "--fingerprint", "--fingerprint", args.key,
        ], "gpg failed to match the key")
        if sum(map(lambda s: s.startswith("uid"), pgp_out.split("\n"))) != 1:
            raise parser.error("no unique match for the key: " + args.key)
        return _parse_fingerprints(pgp_out)

    if args.min_key_file:
        if not (args.key or (args.fingerprints and args.pubring)):
            parser.error("not specified the key to unminify")

        fps = args.fingerprints
        if fps is None:
            fps = export_fingerprints()
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

        s2k = None if args.plaintext else S2K(
            cipher_algo=S2K_CIPHER_ALGOS[args.s2k_cipher_algo],
            digest_algo=S2K_DIGEST_ALGOS[args.s2k_digest_algo],
            count=S2KCountCodec().encode(args.s2k_count),
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
        def export_secret_key():
            export_fingerprints() # ensure unique
            return _quiet_check_output([
                args.gpg_path, "--export-secret-key", args.key
            ], "failed to export the secret key: " + args.key)

        octets, fps, s2k = minify(_quiet_check_output(
            [args.paperkey_path] + (
                ["--secret-key", args.secret_key] if args.secret_key else []
            ) + ["--output-type", "raw"],
            "failed to extract secret part of the key using paperkey",
            input=export_secret_key() if args.key else None,
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
        _info("%s:" % __file__, *objs)
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
encrypt other subkeys using the master key.
"""
        )
        _error(4, e)
    except Exception as e:
        _error(5, e)
