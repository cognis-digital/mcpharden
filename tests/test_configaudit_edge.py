"""Edge-case tests for MCP client-config auditing (mcpharden.configaudit).

Covers the multiple config shapes (Claude Desktop / Cursor / VS Code / list),
unpinned launchers, shell-exec, secrets in env (and the env-reference negative),
remote no-auth / cleartext endpoints, blanket auto-approve, and malformed /
empty / wrong-root error handling.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcpharden.configaudit import (  # noqa: E402
    audit_config,
    audit_config_path,
    default_config_paths,
)


def _rules(doc):
    return {f.rule for f in audit_config(doc).findings}


def _write(tmp, content, name="cfg.json"):
    p = os.path.join(tmp, name)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(content if isinstance(content, str) else json.dumps(content))
    return p


class TestConfigShapes(unittest.TestCase):
    def test_claude_desktop_mcpservers(self):
        doc = {"mcpServers": {"s": {"command": "node", "args": ["server.js"]}}}
        # clean stdio node server with no secrets -> no high findings
        self.assertNotIn("config.unpinned_command", _rules(doc))

    def test_vscode_mcp_servers_nested(self):
        doc = {"mcp": {"servers": {"s": {"command": "npx", "args": ["some-pkg"]}}}}
        self.assertIn("config.unpinned_command", _rules(doc))

    def test_top_level_servers(self):
        doc = {"servers": {"s": {"command": "uvx", "args": ["pkg"]}}}
        self.assertIn("config.unpinned_command", _rules(doc))

    def test_servers_as_list(self):
        doc = {"servers": [{"name": "s", "command": "npx", "args": ["pkg"]}]}
        self.assertIn("config.unpinned_command", _rules(doc))

    def test_no_servers_block_is_info(self):
        self.assertIn("config.no_servers", _rules({"unrelated": True}))

    def test_servers_list_of_non_dict_ignored(self):
        # a list of strings: no real servers -> no_servers info, no crash
        self.assertIn("config.no_servers", _rules({"mcpServers": ["x", "y"]}))


class TestUnpinnedLauncher(unittest.TestCase):
    def test_npx_unpinned(self):
        self.assertIn("config.unpinned_command",
                      _rules({"mcpServers": {"s": {"command": "npx", "args": ["pkg"]}}}))

    def test_npx_pinned_version_clean(self):
        self.assertNotIn("config.unpinned_command",
                         _rules({"mcpServers": {"s": {"command": "npx", "args": ["pkg@1.2.3"]}}}))

    def test_npx_pinned_hash_clean(self):
        self.assertNotIn("config.unpinned_command",
                         _rules({"mcpServers": {"s": {"command": "npx",
                                 "args": ["pkg@abcdef1234567"]}}}))

    def test_uvx_unpinned(self):
        self.assertIn("config.unpinned_command",
                      _rules({"mcpServers": {"s": {"command": "uvx", "args": ["tool"]}}}))

    def test_bunx_unpinned(self):
        self.assertIn("config.unpinned_command",
                      _rules({"mcpServers": {"s": {"command": "bunx", "args": ["tool"]}}}))

    def test_args_as_string_does_not_crash(self):
        # malformed: args should be a list. Must not raise.
        rules = _rules({"mcpServers": {"s": {"command": "npx", "args": "pkg"}}})
        self.assertIsInstance(rules, set)

    def test_direct_binary_not_flagged(self):
        self.assertNotIn("config.unpinned_command",
                         _rules({"mcpServers": {"s": {"command": "/usr/local/bin/myserver"}}}))


class TestShellExec(unittest.TestCase):
    def test_sh_dash_c(self):
        self.assertIn("config.shell_exec",
                      _rules({"mcpServers": {"s": {"command": "sh", "args": ["-c", "do thing"]}}}))

    def test_bash_dash_c(self):
        self.assertIn("config.shell_exec",
                      _rules({"mcpServers": {"s": {"command": "bash", "args": ["-c", "x"]}}}))

    def test_cmd_slash_c(self):
        self.assertIn("config.shell_exec",
                      _rules({"mcpServers": {"s": {"command": "cmd", "args": ["/c", "x"]}}}))

    def test_powershell_command(self):
        self.assertIn("config.shell_exec",
                      _rules({"mcpServers": {"s": {"command": "powershell",
                              "args": ["-Command", "x"]}}}))

    def test_shell_without_dash_c_not_flagged(self):
        self.assertNotIn("config.shell_exec",
                         _rules({"mcpServers": {"s": {"command": "bash", "args": ["script.sh"]}}}))


class TestSecretsInEnv(unittest.TestCase):
    def test_openai_key(self):
        self.assertIn("config.secret_in_env",
                      _rules({"mcpServers": {"s": {"command": "node",
                              "env": {"OPENAI_API_KEY": "sk-" + "A" * 24}}}}))

    def test_github_pat_in_env(self):
        self.assertIn("config.secret_in_env",
                      _rules({"mcpServers": {"s": {"command": "node",
                              "env": {"GH": "ghp_" + "B" * 24}}}}))

    def test_literal_under_secret_keyname(self):
        self.assertIn("config.secret_in_env",
                      _rules({"mcpServers": {"s": {"command": "node",
                              "env": {"API_TOKEN": "literalsecretvalue123"}}}}))

    def test_env_reference_not_flagged(self):
        for ref in ("${MY_TOKEN}", "$MY_TOKEN", "%MY_TOKEN%"):
            self.assertNotIn("config.secret_in_env",
                             _rules({"mcpServers": {"s": {"command": "node",
                                     "env": {"API_TOKEN": ref}}}}),
                             f"{ref} is an env reference, not a literal")

    def test_short_non_secret_value_clean(self):
        self.assertNotIn("config.secret_in_env",
                         _rules({"mcpServers": {"s": {"command": "node",
                                 "env": {"DEBUG": "1"}}}}))

    def test_redaction_in_message(self):
        findings = audit_config({"mcpServers": {"s": {"command": "node",
                   "env": {"API_TOKEN": "supersecretvalue99"}}}}).findings
        msg = " ".join(f.message for f in findings if f.rule == "config.secret_in_env")
        self.assertNotIn("supersecretvalue99", msg)  # full secret must not leak


class TestRemoteServers(unittest.TestCase):
    def test_remote_http_no_auth(self):
        rules = _rules({"mcpServers": {"s": {"url": "http://example.com/mcp"}}})
        self.assertIn("config.cleartext_endpoint", rules)
        self.assertIn("config.remote_no_auth", rules)

    def test_remote_https_no_auth(self):
        rules = _rules({"mcpServers": {"s": {"url": "https://example.com/mcp"}}})
        self.assertIn("config.remote_no_auth", rules)
        self.assertNotIn("config.cleartext_endpoint", rules)

    def test_remote_with_auth_header_clean(self):
        rules = _rules({"mcpServers": {"s": {"url": "https://example.com/mcp",
                        "headers": {"Authorization": "Bearer x"}}}})
        self.assertNotIn("config.remote_no_auth", rules)

    def test_sse_type_treated_remote(self):
        rules = _rules({"mcpServers": {"s": {"type": "sse", "url": "https://x.example"}}})
        self.assertIn("config.remote_no_auth", rules)


class TestAutoApprove(unittest.TestCase):
    def test_auto_approve_true(self):
        self.assertIn("config.auto_approve",
                      _rules({"mcpServers": {"s": {"command": "node", "autoApprove": True}}}))

    def test_always_allow_wildcard(self):
        self.assertIn("config.auto_approve",
                      _rules({"mcpServers": {"s": {"command": "node", "alwaysAllow": ["*"]}}}))

    def test_always_allow_long_list(self):
        self.assertIn("config.auto_approve",
                      _rules({"mcpServers": {"s": {"command": "node",
                              "alwaysAllow": [f"t{i}" for i in range(9)]}}}))

    def test_short_allow_list_clean(self):
        self.assertNotIn("config.auto_approve",
                         _rules({"mcpServers": {"s": {"command": "node",
                                 "alwaysAllow": ["safe_read"]}}}))


class TestConfigErrorHandling(unittest.TestCase):
    def test_non_dict_root_flagged(self):
        self.assertIn("config.malformed", {f.rule for f in audit_config([1, 2, 3]).findings})

    def test_string_root_flagged(self):
        self.assertIn("config.malformed", {f.rule for f in audit_config("nope").findings})

    def test_path_invalid_json_raises_valueerror(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _write(tmp, "{bad json")
            with self.assertRaises(ValueError):
                audit_config_path(p)

    def test_path_empty_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _write(tmp, "")
            with self.assertRaises(ValueError):
                audit_config_path(p)

    def test_path_directory_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                audit_config_path(tmp)

    def test_path_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _write(tmp, {"mcpServers": {"s": {"command": "npx", "args": ["pkg"]}}})
            r = audit_config_path(p)
            self.assertIn("config.unpinned_command", {f.rule for f in r.findings})


class TestDefaultPaths(unittest.TestCase):
    def test_returns_list_of_paths(self):
        paths = default_config_paths()
        self.assertIsInstance(paths, list)
        self.assertTrue(all(isinstance(p, str) for p in paths))
        self.assertTrue(any("claude_desktop_config.json" in p for p in paths))


if __name__ == "__main__":
    unittest.main()
