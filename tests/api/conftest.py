"""
Shared fixtures for API tests.

Every API test runs with the AWS SDK, the Anthropic SDK and outbound
network connections blocked, so no real AWS or Claude calls can happen.
"""

import json
import socket
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cloudsentinel.api.app import create_app

DEMO_DATA_PATH = Path(__file__).resolve().parents[2] / "sample_data" / "demo_iam_data.json"
LOOPBACK_HOSTS = ("127.0.0.1", "::1", "localhost")


@pytest.fixture(autouse=True)
def block_external_calls(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("API tests must not make AWS, Claude or external network calls")

    boto3 = sys.modules.get("boto3")
    if boto3 is not None:
        monkeypatch.setattr(boto3, "Session", fail)
        monkeypatch.setattr(boto3, "client", fail)
    else:
        monkeypatch.setitem(sys.modules, "boto3", None)
        monkeypatch.setitem(sys.modules, "botocore", None)
    monkeypatch.setitem(sys.modules, "anthropic", None)

    # Loopback stays allowed: the event loop may use a local socketpair on Windows
    real_connect = socket.socket.connect

    def guarded_connect(self, address):
        host = address[0] if isinstance(address, tuple) else address
        if host not in LOOPBACK_HOSTS:
            fail()
        return real_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)


@pytest.fixture
def client():
    with TestClient(create_app()) as test_client:
        yield test_client


@pytest.fixture
def demo_data():
    with open(DEMO_DATA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)
