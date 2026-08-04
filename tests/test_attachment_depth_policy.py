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
from pathlib import Path


CONNECTOR = Path(__file__).resolve().parents[1] / "office365fed_connector.py"


class AttachmentDepthPolicyTests(unittest.TestCase):
    def test_federal_recursive_path_enforces_and_propagates_depth_limit(self):
        source = CONNECTOR.read_text()
        tree = ast.parse(source)
        handler = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "_extract_attachments")
        handler_source = ast.get_source_segment(source, handler)

        depth_arg = next(arg for arg in handler.args.args if arg.arg == "depth")
        self.assertIsNotNone(depth_arg)
        self.assertIn("if depth >= MSGOFFICE365_MAX_ATTACHMENT_DEPTH", handler_source)
        self.assertIn("depth=depth + 1", handler_source)
        self.assertIn("return action_result.get_status()", handler_source)

        recursive_calls = [
            node
            for node in ast.walk(handler)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "_extract_attachments"
        ]
        self.assertEqual(len(recursive_calls), 1)
        depth_keyword = next((keyword for keyword in recursive_calls[0].keywords if keyword.arg == "depth"), None)
        self.assertIsNotNone(depth_keyword)
        self.assertIsInstance(depth_keyword.value, ast.BinOp)


if __name__ == "__main__":
    unittest.main()
