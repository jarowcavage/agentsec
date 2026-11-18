"""Disposable sample client; never sends credentials to a real service in tests."""

import urllib3


def retry_policy():
    return urllib3.util.Retry(total=2, redirect=2)


def decode_response(body):
    return urllib3.response.HTTPResponse(body=body).data.decode("utf-8")
