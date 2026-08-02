# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import ast
import unittest
import urllib.parse
from pathlib import Path


CONNECTOR = Path(__file__).resolve().parents[1] / "office365fed_connector.py"


def _function_source(name):
    source = CONNECTOR.read_text()
    tree = ast.parse(source)
    function = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    return ast.get_source_segment(source, function)


def _load_quote_helper():
    source = CONNECTOR.read_text()
    tree = ast.parse(source)
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_quote_path_segment"
    )
    namespace = {"urllib": urllib}
    exec(
        compile(
            ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[])),
            str(CONNECTOR),
            "exec",
        ),
        namespace,
    )
    return namespace["_quote_path_segment"]


class ValidationFollowupTests(unittest.TestCase):
    def test_path_helper_rejects_encoded_dot_segments(self):
        helper = _load_quote_helper()
        for value in (".", "..", "%2e", "%2E%2e", "%252e%252e"):
            with self.subTest(value=value), self.assertRaisesRegex(
                ValueError, "must not be dot segments"
            ):
                helper(value)

    def test_path_helper_preserves_opaque_identifiers(self):
        self.assertEqual(
            _load_quote_helper()("user/name@example.com"),
            "user%2Fname%40example.com",
        )

    def test_oauth_start_requires_the_pending_flow_nonce(self):
        source = _function_source("_handle_oauth_start")
        self.assertIn('request.GET.get("state_nonce", "")', source)
        self.assertIn("hmac.compare_digest(stored_nonce, presented_nonce)", source)

    def test_oauth_start_link_carries_the_pending_flow_nonce(self):
        source = CONNECTOR.read_text()
        self.assertIn('"state_nonce": flow_nonce', source)
        self.assertIn('url_to_show = f"{app_rest_url}/start_oauth?{start_query}"', source)

    def test_polling_never_advances_past_a_failed_email(self):
        source = _function_source("_handle_on_poll")
        self.assertIn('self._state["failed_email_ids"] = sorted(', source)
        self.assertIn("the polling checkpoint was not advanced", source)
        self.assertIn('self._state["last_time"] = last_time', source)
        self.assertLess(
            source.index("the polling checkpoint was not advanced"),
            source.index('self._state["last_time"] = last_time'),
        )

    def test_polling_retries_failed_existing_containers(self):
        source = _function_source("_process_email_data")
        self.assertIn("retry_existing=False", source)
        self.assertIn("if retry_existing:", source)
        self.assertIn("if not retry_existing:", source)

    def test_latest_first_is_processed_in_lossless_order(self):
        source = _function_source("_handle_on_poll")
        self.assertIn('order = "asc"', source)
        self.assertNotIn('else "desc"', source)


if __name__ == "__main__":
    unittest.main()
