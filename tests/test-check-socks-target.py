#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Tests SOCKS5 hostname framing without opening a real network socket."""

import contextlib
import importlib.util
import io
import os
import pathlib

module_path = (
    pathlib.Path(__file__).resolve().parents[1] / "scripts" / "check-socks-target.py"
)

spec = importlib.util.spec_from_file_location("check_socks_target", module_path)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)


class FakeSocket:
    """Captures client writes and returns a deterministic SOCKS5 success."""

    def __init__(self):
        """Initializes a complete successful SOCKS5 response stream."""

        self.responses = bytearray(
            b"\x05\x00"  # no-auth method accepted
            b"\x05\x00\x00\x01"  # CONNECT success, IPv4 bound address
            b"\x00\x00\x00\x00\x00\x00"
        )

        self.requests = []

    def __enter__(self):
        """Returns this fake as a socket context manager."""
        return self

    def __exit__(self, *_args):
        """Leaves the synthetic socket without suppressing exceptions."""
        return False

    def settimeout(self, _timeout):
        """Accepts timeout configuration without waiting on real I/O."""
        pass

    def sendall(self, value):
        """Records one client write for protocol assertions."""
        self.requests.append(value)

    def recv(self, length):
        """Consumes at most `length` bytes from the fixed response stream."""
        value = bytes(self.responses[:length])
        del self.responses[:length]
        return value


fake = FakeSocket()
module.socket.create_connection = lambda address, timeout: fake
os.environ["TEST_TARGET_HOST"] = "campus.example"
os.environ["TEST_TARGET_PORT"] = "22"
output = io.StringIO()

with contextlib.redirect_stdout(output):
    assert module.main() == 0

assert fake.requests[0] == b"\x05\x01\x00"
expected_domain = b"campus.example"

assert fake.requests[1] == (
    b"\x05\x01\x00\x03" + bytes([len(expected_domain)]) + expected_domain + b"\x00\x16"
)

assert "target_type=hostname-remote-dns" in output.getvalue()

try:
    module.target_address("2001:db8::1")
except ValueError:
    pass
else:
    raise AssertionError("IPv6 target was accepted in a v1-only helper")

print("socks_target_test=ok")
