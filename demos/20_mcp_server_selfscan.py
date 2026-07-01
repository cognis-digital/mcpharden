"""Scenario 20 - integrators.

mcpharden ships as an MCP server itself (stdio JSON-RPC) so an agent host can
call it as a tool. This demo speaks the protocol end to end in-process — no
sockets — driving initialize, tools/list, and tools/call against the real
handler, and asserting the `scan` tool returns structured findings the way
Claude Desktop / Cursor would receive them.
"""
import json

from _common import fixture, rule

from mcpharden import mcp_server


def _call(method, params=None, req_id=1):
    return mcp_server.handle_request({
        "jsonrpc": "2.0", "id": req_id, "method": method, "params": params or {}})


def main() -> None:
    rule("MCP SERVER  -  mcpharden as a tool an agent can call")

    init = _call("initialize")
    info = init["result"]["serverInfo"]
    print(f"\ninitialize -> {info['name']} {info['version']}, "
          f"protocol {init['result']['protocolVersion']}")

    tools = _call("tools/list")["result"]["tools"]
    print(f"tools/list -> {', '.join(t['name'] for t in tools)}")

    call = _call("tools/call", {"name": "scan",
                                "arguments": {"target": fixture("poisoned-server.json")}})
    payload = json.loads(call["result"]["content"][0]["text"])
    print(f"\ntools/call scan('poisoned-server.json'):")
    print(f"   servers_scanned : {payload['servers_scanned']}")
    print(f"   total_findings  : {payload['total_findings']}")
    print(f"   failed          : {payload['failed']}  (isError={call['result']['isError']})")

    posture_call = _call("tools/call", {"name": "posture",
                                        "arguments": {"target": fixture("fleet")}})
    p = json.loads(posture_call["result"]["content"][0]["text"])
    print(f"\ntools/call posture('fleet'): grade {p['grade']} ({p['fleet_score']}/100)")

    print("\nRegister it in any MCP client with:")
    print('   {"command": "python", "args": ["-m", "mcpharden", "mcp"]}')


if __name__ == "__main__":
    main()
