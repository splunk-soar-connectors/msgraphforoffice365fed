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

from office365fed_consts import (
    MSGOFFICE365_AUTH_FAILURE_MSG,
    MSGOFFICE365_CBA_ADMIN_CONSENT_ERROR,
    MSGOFFICE365_CBA_AUTH_ERROR,
    MSGOFFICE365_TOKEN_REFRESH_BUFFER_SECONDS,
)


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

    def test_preflight_uses_current_auth_mode_when_both_states_exist(self):
        connector = self._connector(time.time() + 3600, [(0, {}, "")])
        connector._state["non_admin_auth"] = {"expires_at": time.time() - 1}

        status, _ = connector._make_rest_call_helper(ActionResult(), "/users")

        self.assertEqual(status, 0)
        self.assertEqual(connector.refresh_count, 0)
        self.assertEqual(connector.requests[0][1], "Bearer old-token")

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

    def test_stops_when_refresh_status_is_not_recorded_on_action_result(self):
        connector = self._connector(time.time() - 1, [])
        connector._get_token = lambda action_result: -1

        status, body = connector._make_rest_call_helper(ActionResult(), "/users")

        self.assertEqual((status, body), (-1, None))
        self.assertEqual(connector.requests, [])

    def test_legacy_token_retries_invalid_lifetime_response(self):
        connector = self._connector(None, [(-1, None, "InvalidAuthenticationToken. Invalid token lifetime"), (0, {}, "")])

        status, body = connector._make_rest_call_helper(ActionResult(), "/users")

        self.assertEqual((status, body), (0, {}))
        self.assertEqual(connector.refresh_count, 1)
        self.assertEqual([request[1] for request in connector.requests], ["Bearer old-token", "Bearer new-token"])

    def test_token_failure_sets_action_result_status(self):
        method = _load_method("_get_token", self.namespace)
        connector = SimpleNamespace(
            _auth_type="cba",
            _client_secret=None,
            _generate_new_cba_access_token=lambda action_result: (-1, None),
        )
        result = ActionResult()

        status = method(connector, result)

        self.assertEqual(status, -1)
        self.assertEqual(result.get_status(), -1)
        self.assertEqual(result.get_message(), "Unable to generate access token")

    def test_preflight_stops_after_cba_token_generator_failure(self):
        method = _load_method("_get_token", self.namespace)
        connector = self._connector(time.time() - 1, [])
        connector._auth_type = "cba"
        connector._client_secret = None
        connector._generate_new_cba_access_token = lambda action_result: (-1, None)
        connector._get_token = lambda action_result: method(connector, action_result)
        result = ActionResult()

        status, body = connector._make_rest_call_helper(result, "/users")

        self.assertEqual((status, body), (-1, None))
        self.assertEqual(result.get_status(), -1)
        self.assertEqual(connector.requests, [])

    def test_cba_validation_failures_set_action_result_status(self):
        namespace = {
            "phantom": self.phantom,
            "MSGOFFICE365_CBA_AUTH_ERROR": MSGOFFICE365_CBA_AUTH_ERROR,
            "MSGOFFICE365_CBA_ADMIN_CONSENT_ERROR": MSGOFFICE365_CBA_ADMIN_CONSENT_ERROR,
        }
        method = _load_method("_generate_new_cba_access_token", namespace)
        for thumbprint, private_key, admin_consent, expected_message in (
            (None, None, True, MSGOFFICE365_CBA_AUTH_ERROR),
            ("thumbprint", "private-key", False, MSGOFFICE365_CBA_ADMIN_CONSENT_ERROR),
        ):
            with self.subTest(expected_message=expected_message):
                connector = SimpleNamespace(
                    _state={"admin_auth": {"access_token": "old"}},
                    _thumbprint=thumbprint,
                    _certificate_private_key=private_key,
                    _admin_consent=admin_consent,
                    save_progress=lambda message: None,
                )
                result = ActionResult()

                status, body = method(connector, result)

                self.assertEqual((status, body), (-1, None))
                self.assertEqual(result.get_message(), expected_message)

    def test_msal_token_failure_sets_action_result_status(self):
        class MsalApplication:
            def __init__(self, *args, **kwargs):
                pass

            def acquire_token_for_client(self, scopes):
                return {"error": "invalid_client", "error_description": "certificate rejected"}

        namespace = {
            "phantom": self.phantom,
            "msal": SimpleNamespace(ConfidentialClientApplication=MsalApplication),
            "MSGOFFICE365_AUTHORITY_URL": "{base_url}/{tenant}",
        }
        method = _load_method("_generate_new_cba_access_token", namespace)
        connector = SimpleNamespace(
            _state={},
            _thumbprint="123456",
            _certificate_private_key="configured",
            _admin_consent=True,
            _client_id="client",
            _entra_base_url="https://login.microsoftonline.us",
            _tenant="tenant",
            _default_scope="https://graph.microsoft.us/.default",
            _get_private_key=lambda action_result: (0, "private-key"),
            save_progress=lambda message: None,
            debug_print=lambda message: None,
        )
        result = ActionResult()

        status, body = method(connector, result)

        self.assertEqual((status, body), (-1, None))
        self.assertEqual(result.get_status(), -1)
        self.assertIn("invalid_client", result.get_message())

    def test_oauth_without_refresh_token_returns_error_tuple(self):
        namespace = {"phantom": self.phantom, "SERVER_TOKEN_URL": "{base_url}/{tenant}/oauth2/v2.0/token"}
        method = _load_method("_generate_new_oauth_access_token", namespace)
        connector = SimpleNamespace(
            _admin_access=False,
            _scope="User.Read",
            _client_id="client",
            _client_secret="secret",
            _tenant="tenant",
            _entra_base_url="https://login.microsoftonline.us",
            _state={},
            _refresh_token=None,
            save_progress=lambda message: None,
        )
        result = ActionResult()

        status, body = method(connector, result)

        self.assertEqual((status, body), (-1, None))
        self.assertEqual(result.get_message(), "Unexpected details retrieved from the state file.")

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
        class Soup:
            def __init__(self, text, parser):
                self.text = text

            def __call__(self, tags):
                return []

        response = SimpleNamespace(
            status_code=401,
            headers={"Content-Type": "application/json"},
            text='{"error": {"code": "InvalidAuthenticationToken", "message": "Invalid token lifetime"}}',
            json=lambda: {"error": {"code": "InvalidAuthenticationToken", "message": "Invalid token lifetime"}},
        )
        namespace = {
            "phantom": self.phantom,
            "requests": SimpleNamespace(get=lambda *args, **kwargs: response),
            "RetVal": lambda *values: values,
            "BeautifulSoup": Soup,
            "MSGOFFICE365_DEFAULT_REQUEST_TIMEOUT": 30,
        }
        make_rest_call = _load_method("_make_rest_call", namespace)
        process_response = _load_method("_process_response", namespace)
        process_json_response = _load_method("_process_json_response", namespace)
        connector = SimpleNamespace(
            _number_of_retries=1,
            debug_print=lambda *args: None,
        )
        connector._process_json_response = lambda response, action_result: process_json_response(connector, response, action_result)
        connector._process_response = lambda response, action_result: process_response(connector, response, action_result)
        result = ActionResult()

        status, body = make_rest_call(connector, result, "https://graph.microsoft.us/v1.0/me", download=True)

        self.assertEqual((status, body), (-1, None))
        self.assertIn("InvalidAuthenticationToken", result.get_message())
        self.assertIn("Invalid token lifetime", result.get_message())


if __name__ == "__main__":
    unittest.main()
