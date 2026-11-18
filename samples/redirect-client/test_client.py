import json
import unittest

from client import decode_response, retry_policy


class ClientTests(unittest.TestCase):
    def test_response_compatibility(self):
        self.assertEqual(json.loads(decode_response(b'{"status":"ok"}')), {"status": "ok"})

    def test_redirect_policy_preserved(self):
        self.assertEqual(retry_policy().redirect, 2)

    def test_proxy_credentials_removed_on_redirect(self):
        # Tests the actual urllib3 policy used by this sample, not a version-number assertion.
        self.assertIn("proxy-authorization", retry_policy().remove_headers_on_redirect)


if __name__ == "__main__":
    unittest.main(verbosity=2)
