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
import time
import unittest
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

from office365fed_consts import MSGOFFICE365_AUTH_FAILURE_MSG, MSGOFFICE365_TOKEN_REFRESH_BUFFER_SECONDS


ROOT = Path(__file__).resolve().parents[1]
CONNECTOR = ROOT / "office365fed_connector.py"


def _load_method(name, namespace):
    tree = ast.parse(CONNECTOR.read_text())
    method = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == name)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[])), str(CONNECTOR), "exec"), namespace)
    return namespace[name]


class ActionResult:
    def __init__(self):
        self.status = 0
        self.message = ""

    def set_status(self, status, message=""):
        self.status = status
        self.message = message
        return status

    def get_status(self):
        return self.status

    def get_message(self):
        return self.message


class TokenRefreshTests(unittest.TestCase):
    def setUp(self):
        self.phantom = SimpleNamespace(APP_SUCCESS=0, APP_ERROR=-1, is_fail=lambda status: status != 0)
        self.namespace = {
            "phantom": self.phantom,
            "time": time,
            "MSGOFFICE365_TOKEN_REFRESH_BUFFER_SECONDS": MSGOFFICE365_TOKEN_REFRESH_BUFFER_SECONDS,
            "MSGOFFICE365_AUTH_FAILURE_MSG": MSGOFFICE365_AUTH_FAILURE_MSG,
        }

    def _connector(self, expires_at, responses, admin_access=True):
        method = _load_method("_make_rest_call_helper", self.namespace)
        connector = SimpleNamespace(
            _state={"admin_auth" if admin_access else "non_admin_auth": {"expires_at": expires_at}},
            _admin_access=admin_access,
            _graph_base_url="https://graph.microsoft.us",
            _access_token="old-token",
            requests=[],
            refresh_count=0,
            debug_print=lambda *args: None,
        )

        def make_rest_call(action_result, url, verify, headers, params, data, http_method, download=False):
            connector.requests.append((url, headers["Authorization"], download))
            status, body, message = responses.pop(0)
            action_result.set_status(status, message)
            return status, body

        def get_token(action_result):
            connector.refresh_count += 1
            connector._access_token = "new-token"
            return action_result.set_status(self.phantom.APP_SUCCESS)

        connector._make_rest_call = make_rest_call
        connector._get_token = get_token
        connector._make_rest_call_helper = lambda action_result, endpoint, **kwargs: method(connector, action_result, endpoint, **kwargs)
        return connector

    def test_refreshes_before_request_when_token_nears_expiry(self):
        connector = self._connector(time.time() + 30, [(0, {"value": []}, "")], admin_access=False)

        status, body = connector._make_rest_call_helper(ActionResult(), "/me")

        self.assertEqual((status, body), (0, {"value": []}))
        self.assertEqual(connector.refresh_count, 1)
        self.assertEqual(connector.requests[0][1], "Bearer new-token")

    def test_retries_invalid_token_lifetime_once_with_new_token(self):
        for error in ("InvalidAuthenticationToken", "Invalid token lifetime"):
            with self.subTest(error=error):
                connector = self._connector(time.time() + 3600, [(-1, None, f"Error: Status Code: 401 Data from server: {error}"), (0, {}, "")])

                status, body = connector._make_rest_call_helper(ActionResult(), "/users", download=True)

                self.assertEqual((status, body), (0, {}))
                self.assertEqual(connector.refresh_count, 1)
                self.assertEqual([request[1] for request in connector.requests], ["Bearer old-token", "Bearer new-token"])
                self.assertTrue(all(request[2] for request in connector.requests))

    def test_does_not_refresh_for_unrelated_error(self):
        connector = self._connector(time.time() + 3600, [(-1, None, "Error: Status Code: 403 Data from server: Access denied")])

        status, body = connector._make_rest_call_helper(ActionResult(), "/users")

        self.assertEqual((status, body), (-1, None))
        self.assertEqual(connector.refresh_count, 0)
        self.assertEqual(len(connector.requests), 1)

    def test_stops_before_graph_request_when_refresh_fails(self):
        connector = self._connector(time.time() - 1, [])
        connector._get_token = lambda action_result: action_result.set_status(-1, "Token endpoint unavailable")

        status, body = connector._make_rest_call_helper(ActionResult(), "/users")

        self.assertEqual((status, body), (-1, None))
        self.assertEqual(connector.requests, [])

    def test_token_expiry_is_saved_with_new_access_token(self):
        clock = SimpleNamespace(now=1000)
        self.namespace["time"] = SimpleNamespace(time=lambda: clock.now)
        method = _load_method("_get_token", self.namespace)

        def generate_token(action_result):
            clock.now = 1020
            return 0, {"access_token": "new-token", "expires_in": 3600}

        connector = SimpleNamespace(
            _auth_type="cba",
            _client_secret=None,
            _admin_access=True,
            _admin_consent=True,
            _state={},
            _generate_new_cba_access_token=generate_token,
            debug_print=lambda *args: None,
        )
        connector.save_state = lambda state: setattr(connector, "saved_state", deepcopy(state))
        connector.load_state = lambda: connector.saved_state
        status = method(connector, ActionResult())

        self.assertEqual(status, 0)
        self.assertEqual(connector.saved_state["admin_auth"]["access_token"], "new-token")
        self.assertEqual(connector.saved_state["admin_auth"]["expires_at"], 4600)

    def test_download_error_is_processed_for_token_retry(self):
        namespace = {
            "phantom": self.phantom,
            "requests": SimpleNamespace(get=lambda *args, **kwargs: SimpleNamespace(status_code=401)),
            "MSGOFFICE365_DEFAULT_REQUEST_TIMEOUT": 30,
        }
        method = _load_method("_make_rest_call", namespace)
        connector = SimpleNamespace(
            _number_of_retries=1,
            _process_response=lambda response, action_result: (
                action_result.set_status(-1, "InvalidAuthenticationToken. Invalid token lifetime"),
                None,
            ),
            debug_print=lambda *args: None,
        )
        result = ActionResult()

        status, body = method(connector, result, "https://graph.microsoft.us/v1.0/me", download=True)

        self.assertEqual((status, body), (-1, None))
        self.assertIn("InvalidAuthenticationToken", result.get_message())


if __name__ == "__main__":
    unittest.main()
