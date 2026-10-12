"""Call one tool on the demo server, through the gate. No dependencies.

    python examples/call.py whoami                     # no key -> 401
    python examples/call.py whoami --key sk_...        # -> runs
    python examples/call.py run_query --key sk_... -a sql="select 1"
    python examples/call.py drop_everything --key sk_...   # -> refused, and logged

The same request as the curl in the README, minus the JSON typing.
"""
import argparse
import json
import urllib.error
import urllib.request

p = argparse.ArgumentParser()
p.add_argument("tool")
p.add_argument("--key", help="sk_... (sent as x-api-key)")
p.add_argument("--bearer", action="store_true", help="send the key as Authorization: Bearer")
p.add_argument("--url", default="http://localhost:8080/mcp")
p.add_argument("-a", "--arg", action="append", default=[], metavar="NAME=VALUE",
               help='tool argument, repeatable: -a sql="select 1"')
args = p.parse_args()
tool_args = dict(a.split("=", 1) for a in args.arg)

headers = {"content-type": "application/json",
           "accept": "application/json, text/event-stream"}
if args.key:
    if args.bearer:
        headers["authorization"] = "Bearer " + args.key
    else:
        headers["x-api-key"] = args.key

body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": args.tool, "arguments": tool_args}}).encode()
req = urllib.request.Request(args.url, data=body, headers=headers, method="POST")

try:
    with urllib.request.urlopen(req) as r:
        status, payload = r.status, json.loads(r.read())
except urllib.error.HTTPError as e:
    status, payload = e.code, json.loads(e.read() or b"{}")

if "result" in payload:
    res = payload["result"]
    text = " ".join(c.get("text", "") for c in res.get("content", []))
    print("%d  %-5s  %s" % (status, "error" if res.get("isError") else "ok", text))
else:
    print("%d  %s — %s" % (status, payload.get("error", ""), payload.get("message", "")))
