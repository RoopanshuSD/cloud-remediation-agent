"""AWS clients for the agent and the benchmark.

Two backends:
  * moto (default): an in-process AWS emulator. No Docker or network needed, and every
    `cloud_session()` starts from an empty account, so tasks are isolated.
  * LocalStack: set LOCALSTACK_ENDPOINT=http://localhost:4566. State is reset before each session.
"""
from __future__ import annotations

import contextlib
import os
import urllib.request

import boto3

REGION = "us-east-1"


class Cloud:
    def __init__(self, endpoint_url: str | None = None):
        kw = dict(region_name=REGION, aws_access_key_id="test", aws_secret_access_key="test")
        if endpoint_url:
            kw["endpoint_url"] = endpoint_url
        self.s3 = boto3.client("s3", **kw)
        self.ec2 = boto3.client("ec2", **kw)
        self.iam = boto3.client("iam", **kw)


def _reset_localstack(endpoint: str) -> None:
    req = urllib.request.Request(endpoint.rstrip("/") + "/_localstack/state/reset", method="POST")
    urllib.request.urlopen(req, timeout=30).read()


@contextlib.contextmanager
def cloud_session():
    """A fresh, isolated AWS account for one task run."""
    endpoint = os.environ.get("LOCALSTACK_ENDPOINT")
    if endpoint:
        _reset_localstack(endpoint)
        yield Cloud(endpoint)
        return
    from moto import mock_aws

    with mock_aws():
        yield Cloud()
