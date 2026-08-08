#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Perform a SOCKS5 CONNECT without resolving a hostname locally."""

import ipaddress
import os
import socket
import struct
import sys


def recv_exact(sock: socket.socket, length: int) -> bytes:
    """Receives exactly one bounded SOCKS5 response field.

    Args:
        sock: Connected SOCKS5 socket.
        length: Required byte count.

    Returns:
        The received bytes.

    Raises:
        RuntimeError: The peer closes the connection before `length` bytes.
        OSError: The socket read fails or times out.
    """

    chunks = bytearray()

    while len(chunks) < length:
        chunk = sock.recv(length - len(chunks))

        if not chunk:
            raise RuntimeError("unexpected SOCKS5 EOF")

        chunks.extend(chunk)

    return bytes(chunks)


def target_address(host: str) -> tuple[int, bytes, str]:
    """Encodes a target without performing local DNS resolution.

    Args:
        host: IPv4 literal or IDNA-compatible DNS hostname.

    Returns:
        A tuple of SOCKS5 address type, encoded address, and diagnostic label.

    Raises:
        ValueError: The target is empty, oversized, invalid, or IPv6.
    """

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        encoded = host.encode("idna")

        if not encoded or len(encoded) > 255:
            raise ValueError("TEST_TARGET_HOST is not a valid DNS name")

        return 3, bytes([len(encoded)]) + encoded, "hostname-remote-dns"

    if address.version != 4:
        raise ValueError("IPv6 is outside the v1 compatibility contract")

    return 1, address.packed, "ipv4"


def main() -> int:
    """Checks a configured TCP target through the local SOCKS5 endpoint.

    Returns:
        Zero after a successful SOCKS5 CONNECT negotiation.

    Raises:
        OSError: The local proxy cannot be reached.
        RuntimeError: The proxy returns a malformed or failed response.
        ValueError: TEST_TARGET_HOST or TEST_TARGET_PORT is invalid.
    """

    host = os.environ.get("TEST_TARGET_HOST", "")
    port_text = os.environ.get("TEST_TARGET_PORT", "")

    if not host or not port_text.isascii() or not port_text.isdigit():
        raise ValueError("set TEST_TARGET_HOST and numeric TEST_TARGET_PORT")

    port = int(port_text)

    if not 1 <= port <= 65535:
        raise ValueError("TEST_TARGET_PORT must be between 1 and 65535")

    atyp, address, target_type = target_address(host)

    with socket.create_connection(("127.0.0.1", 11080), timeout=10) as sock:
        sock.settimeout(20)
        sock.sendall(b"\x05\x01\x00")

        if recv_exact(sock, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS5 proxy did not accept no-auth method")

        sock.sendall(
            b"\x05\x01\x00" + bytes([atyp]) + address + struct.pack("!H", port)
        )

        version, reply, reserved, bound_type = recv_exact(sock, 4)

        if version != 5 or reserved != 0:
            raise RuntimeError("invalid SOCKS5 CONNECT response")

        if reply != 0:
            raise RuntimeError(f"SOCKS5 CONNECT failed with reply code {reply}")

        if bound_type == 1:
            recv_exact(sock, 4)
        elif bound_type == 3:
            recv_exact(sock, recv_exact(sock, 1)[0])
        elif bound_type == 4:
            recv_exact(sock, 16)
        else:
            raise RuntimeError("invalid SOCKS5 bound-address type")

        recv_exact(sock, 2)

    print(f"socks_target_check=ok target_type={target_type} port={port}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"socks_target_check=failed reason={exc}", file=sys.stderr)
        raise SystemExit(1)
