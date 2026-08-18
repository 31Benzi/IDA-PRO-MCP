# Security Policy

## Overview

`ida-mcp` connects AI assistants (via the Model Context Protocol) to IDA Pro over a local JSON-RPC socket (`127.0.0.1:13337` by default).

Because this server allows executing IDAPython code, modifying database entries, and interacting with active debugger sessions, please observe the following security considerations:

### Localhost Binding
- By default, the JSON-RPC server binds exclusively to `127.0.0.1` (localhost).
- **Do not expose this port to public networks or untrusted local networks.** Anyone with access to the port can execute IDAPython scripts and read/write the IDA database.

### Untrusted Binaries & Code Execution
- The `execute_idapython` tool executes arbitrary Python within the IDA Pro context.
- When working with malicious or untrusted binaries, ensure IDA Pro itself is running within an isolated analysis virtual machine or sandbox environment.

## Reporting Security Issues

If you discover a security vulnerability in this project, please report it responsibly by opening a private security advisory on GitHub or contacting the maintainers directly.
