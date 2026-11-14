# ssh-mcp

ssh-mcp is a local [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that lets an AI agent inspect and manage files and run commands on your SSH hosts. It connects using your existing OpenSSH configuration and keeps persistent SSH sessions open while the agent works. No helper software is installed on remote hosts.

## Install

You need Rust 1.89 or later to build from source. OpenSSH (`ssh`) must be available on the computer running the agent. Remote hosts need SSH access, a POSIX shell, and SFTP.

```sh
git clone https://github.com/jrmdev/ssh-mcp.git
cd ssh-mcp
cargo install --path . --locked
```

Check that it is available with `ssh-mcp --help`.

Before using the agent, connect to each host with `ssh <alias>` to verify its host key and authentication. ssh-mcp requires a host key already trusted in your known-hosts file. Encrypted keys must be loaded into your local SSH agent; ssh-mcp does not prompt for passwords, passphrases, or MFA.

## Add to an AI agent

Add ssh-mcp as a **stdio MCP server** in your agent's MCP settings:

```json
{
  "mcpServers": {
    "ssh": {
      "command": "ssh-mcp",
      "args": []
    }
  }
}
```

If the agent cannot find the command, set `command` to the full path of the installed executable. On Windows, use `ssh-mcp.exe`. The server reads your normal `~/.ssh/config` (or `%USERPROFILE%\\.ssh\\config` on Windows). To select a different config or OpenSSH executable, pass `--config PATH` or `--ssh PATH` in `args`.

## Tools

Call `list_hosts` to see configured aliases, then `connect` with an alias. Use the returned `session_id` with the remote tools. Sessions are reused until disconnected or the server exits.

| Tool | What it does |
| --- | --- |
| `list_hosts` | List host aliases from your SSH configuration. |
| `connect`, `list_sessions`, `disconnect` | Open, inspect, and close SSH sessions. |
| `read_file`, `write_file`, `edit_file` | Read and update remote files over SFTP. |
| `upload_file`, `download_file` | Transfer files between your computer and a remote host. |
| `execute_command`, `get_job`, `cancel_job` | Run a remote shell command, check its output, and request cancellation. |

Tool schemas provide the arguments and options. Remote file paths are literal; relative paths start in the remote home directory. Commands run in a noninteractive POSIX shell. File transfers refuse to overwrite by default, and command output is retained in local memory while the server is running.

## Security and compatibility

Authentication and private-key signing stay on the computer running ssh-mcp; SSH agent forwarding is never requested. Unknown, changed, or revoked host keys are rejected. Only configured authentication is supported; ssh-mcp does not prompt for credentials.

The client can run on Linux, macOS, and Windows. Remote command execution requires a POSIX shell, so Windows hosts are not supported as SSH targets. Standard OpenSSH host settings and chained `ProxyJump` are supported; see your OpenSSH configuration for connection details.
