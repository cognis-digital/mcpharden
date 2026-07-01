"""Edge-case tests for the stdio MCP server (mcpharden.mcp_server).

Drives the JSON-RPC surface directly (handle_request) and through the
newline-delimited transport (run_mcp_server) to pin the protocol contract:
initialize / tools/list / tools/call, notifications get no response, malformed
input yields the right JSON-RPC error code, and the three tools work + error.
"""

import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcpharden import mcp_server  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(REPO_ROOT, "demos", "fixtures")


def _fx(*p):
    return os.path.join(FIXTURES, *p)


class TestHandshake(unittest.TestCase):
    def test_initialize(self):
        res = mcp_server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        self.assertEqual(res["result"]["serverInfo"]["name"], "mcpharden")
        self.assertIn("capabilities", res["result"])

    def test_initialized_notification_no_response(self):
        self.assertIsNone(mcp_server.handle_request({"method": "notifications/initialized"}))

    def test_ping(self):
        res = mcp_server.handle_request({"jsonrpc": "2.0", "id": 2, "method": "ping"})
        self.assertEqual(res["result"], {})

    def test_unknown_method_method_not_found(self):
        res = mcp_server.handle_request({"jsonrpc": "2.0", "id": 3, "method": "nope"})
        self.assertEqual(res["error"]["code"], -32601)

    def test_notification_unknown_method_no_response(self):
        self.assertIsNone(mcp_server.handle_request({"method": "nope"}))


class TestToolsList(unittest.TestCase):
    def test_lists_three_tools(self):
        res = mcp_server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        names = {t["name"] for t in res["result"]["tools"]}
        self.assertEqual(names, {"scan", "audit_manifest", "posture"})

    def test_tools_have_schemas(self):
        res = mcp_server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        for t in res["result"]["tools"]:
            self.assertIn("inputSchema", t)
            self.assertEqual(t["inputSchema"]["additionalProperties"], False)


class TestToolsCall(unittest.TestCase):
    def _call(self, name, arguments):
        return mcp_server.handle_request({
            "jsonrpc": "2.0", "id": 9, "method": "tools/call",
            "params": {"name": name, "arguments": arguments}})

    def test_scan_file(self):
        res = self._call("scan", {"target": _fx("hardened-server.json")})
        payload = json.loads(res["result"]["content"][0]["text"])
        self.assertIn("servers_scanned", payload)
        self.assertFalse(res["result"]["isError"])

    def test_scan_failing_sets_iserror(self):
        res = self._call("scan", {"target": _fx("public-rce-server.json")})
        self.assertTrue(res["result"]["isError"])

    def test_scan_missing_target_arg(self):
        res = self._call("scan", {})
        self.assertEqual(res["error"]["code"], -32602)

    def test_scan_nonexistent_path(self):
        res = self._call("scan", {"target": "/no/such/path-xyz"})
        # scan() of a missing dir raises ManifestError -> JSON-RPC invalid params
        self.assertEqual(res["error"]["code"], -32602)

    def test_audit_manifest_inline(self):
        m = {"name": "x", "transport": {"type": "http", "host": "0.0.0.0"}}
        res = self._call("audit_manifest", {"manifest": m})
        payload = json.loads(res["result"]["content"][0]["text"])
        rules = {f["rule"] for f in payload["findings"]}
        self.assertIn("transport.bind_all", rules)

    def test_audit_manifest_requires_object(self):
        res = self._call("audit_manifest", {"manifest": "not-an-object"})
        self.assertEqual(res["error"]["code"], -32602)

    def test_posture_tool(self):
        res = self._call("posture", {"target": _fx("fleet")})
        payload = json.loads(res["result"]["content"][0]["text"])
        self.assertIn("grade", payload)

    def test_unknown_tool(self):
        res = self._call("frobnicate", {})
        self.assertEqual(res["error"]["code"], -32602)


class TestTransport(unittest.TestCase):
    def test_run_loop_initialize_and_list(self):
        lines = (
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) + "\n"
            + json.dumps({"method": "notifications/initialized"}) + "\n"
            + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}) + "\n"
        )
        out = io.StringIO()
        mcp_server.run_mcp_server(stdin=io.StringIO(lines), stdout=out)
        responses = [json.loads(l) for l in out.getvalue().splitlines() if l.strip()]
        # initialize + tools/list respond; the notification does not.
        self.assertEqual(len(responses), 2)
        self.assertEqual(responses[0]["id"], 1)
        self.assertEqual(responses[1]["id"], 2)

    def test_parse_error_on_bad_line(self):
        out = io.StringIO()
        mcp_server.run_mcp_server(stdin=io.StringIO("{not json\n"), stdout=out)
        resp = json.loads(out.getvalue().strip())
        self.assertEqual(resp["error"]["code"], -32700)

    def test_blank_lines_ignored(self):
        out = io.StringIO()
        mcp_server.run_mcp_server(stdin=io.StringIO("\n\n   \n"), stdout=out)
        self.assertEqual(out.getvalue().strip(), "")


if __name__ == "__main__":
    unittest.main()
