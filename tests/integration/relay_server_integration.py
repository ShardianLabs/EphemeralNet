#!/usr/bin/env python3
"""Simple integration tests for eph-relay-server REGISTER/CONNECT flow."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER_PATH = REPO_ROOT / "build" / "eph-relay-server"
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 49750
TIMEOUT = 5.0


def read_line(sock: socket.socket) -> str:
    data = bytearray()
    while True:
        chunk = sock.recv(1)
        if not chunk:
            raise RuntimeError("socket closed while waiting for newline")
        if chunk == b"\n":
            break
        data.extend(chunk)
    if data.endswith(b"\r"):
        data.pop()
    return data.decode("ascii")


def read_exact(sock: socket.socket, length: int) -> bytes:
    remaining = length
    chunks: list[bytes] = []
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise RuntimeError("socket closed before reading expected bytes")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def wait_for_server(host: str, port: int, deadline: float) -> None:
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.25):
                return
        except (ConnectionRefusedError, OSError):
            time.sleep(0.05)
    raise RuntimeError("relay server did not start listening in time")


def open_client(host: str, port: int) -> socket.socket:
    sock = socket.create_connection((host, port), timeout=TIMEOUT)
    sock.settimeout(TIMEOUT)
    return sock


def assert_equal(actual, expected, label: str) -> None:
    if actual != expected:
        raise AssertionError(f"{label}: expected {expected!r}, got {actual!r}")


def test_register_connect_roundtrip() -> None:
    peer_a = "aa" * 32
    peer_b = "bb" * 32

    registered = open_client(LISTEN_HOST, LISTEN_PORT)
    connector = open_client(LISTEN_HOST, LISTEN_PORT)

    registered.sendall(f"REGISTER {peer_a}\n".encode("ascii"))
    assert_equal(read_line(registered), "OK", "register ack")

    connector.sendall(f"CONNECT {peer_b} {peer_a}\n".encode("ascii"))
    assert_equal(read_line(connector), "OK", "connect ack")

    connector.sendall(bytes.fromhex(peer_b))

    begin_line = read_line(registered)
    assert_equal(begin_line, f"BEGIN {peer_b}", "BEGIN notification")

    identity = read_exact(registered, 32)
    assert_equal(identity, bytes.fromhex(peer_b), "forwarded identity")

    payload = b"ping-through-relay"
    connector.sendall(payload)
    forwarded = read_exact(registered, len(payload))
    assert_equal(forwarded, payload, "forwarded payload")

    response = b"pong-back"
    registered.sendall(response)
    echoed = read_exact(connector, len(response))
    assert_equal(echoed, response, "response payload")

    registered.close()
    connector.close()


def test_connect_to_missing_peer() -> None:
    peer_self = "cc" * 32
    peer_missing = "dd" * 32

    connector = open_client(LISTEN_HOST, LISTEN_PORT)
    connector.sendall(f"CONNECT {peer_self} {peer_missing}\n".encode("ascii"))
    line = read_line(connector)
    if line != "ERROR target-unavailable":
        raise AssertionError(f"expected target-unavailable error, got {line!r}")
    connector.close()


def main() -> int:
    if not SERVER_PATH.exists():
        print(f"Missing eph-relay-server binary at {SERVER_PATH}", file=sys.stderr)
        return 1

    command = [str(SERVER_PATH), "--listen", f"{LISTEN_HOST}:{LISTEN_PORT}"]
    env = os.environ.copy()
    env["EPH_TEST_MODE"] = "relay"

    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        wait_for_server(LISTEN_HOST, LISTEN_PORT, time.time() + 5)
        test_register_connect_roundtrip()
        test_connect_to_missing_peer()
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
    stdout, stderr = process.communicate(timeout=0.1)
    if stdout:
        print(stdout.strip())
    if stderr:
        print(stderr.strip(), file=sys.stderr)
    print("Relay server integration tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
