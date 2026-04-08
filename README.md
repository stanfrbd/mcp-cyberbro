<!-- mcp-server: cyberbro | tools: 5 | resources: 0 | transport: stdio,sse,streamable-http | auth: none | framework: fastmcp -->
<!-- mcp-name: io.github.stanfrbd/mcp-cyberbro -->

[![MseeP.ai Security Assessment Badge](https://mseep.net/pr/stanfrbd-mcp-cyberbro-badge.png)](https://mseep.ai/app/stanfrbd-mcp-cyberbro)

<h1 align="center">Cyberbro MCP Server</h1>

<p align="center">
<img src="https://github.com/user-attachments/assets/5e5a4406-99c1-47f1-a726-de176baa824c" width="90" /><br />
<b><i>Extract IoCs from messy text and analyze them with Cyberbro.</i></b>
<br />
<b>🌐 <a href="https://demo.cyberbro.net/">demo.cyberbro.net</a></b><br />
</p>

![mcp-cyberbro-demo](https://github.com/user-attachments/assets/99ee5538-c95a-40ca-bff5-3cdf3aa86235)

Model Context Protocol server for Cyberbro.

This project is packaged as a standard Python distribution and can be launched with:

- `uvx mcp-cyberbro`
- `pip install mcp-cyberbro` then `mcp-cyberbro`

## Why this server

- Analyze observables (IP, domain, URL, hash, etc.) via Cyberbro engines.
- Integrate threat-analysis actions directly in MCP-capable assistants.
- Run with `stdio`, `sse`, or `streamable-http` transports.
- Compatible with any MCP client that supports one of these transports.

## Installation

### Use with `uvx` (standalone)

```bash
uvx mcp-cyberbro --cyberbro_url http://localhost:5000
```

### Use with `pip`

```bash
pip install mcp-cyberbro
mcp-cyberbro --cyberbro_url http://localhost:5000
```

### Local development

```bash
pip install -e .
mcp-cyberbro --cyberbro_url http://localhost:5000
```

## Docker

Default container command starts in `streamable-http` mode on port `8000`.

```bash
docker run --rm -p 8000:8000 \
  -e CYBERBRO_URL=http://host.docker.internal:5000 \
  ghcr.io/stanfrbd/mcp-cyberbro:latest
```

To force `stdio` transport:

```bash
docker run -i --rm \
  -e CYBERBRO_URL=http://host.docker.internal:5000 \
  ghcr.io/stanfrbd/mcp-cyberbro:latest \
  --transport stdio
```

## Configuration

Copy `.env.example` and set at least:

- `CYBERBRO_URL` (required)

Supported environment variables:

- `CYBERBRO_URL`
- `API_PREFIX` (default: `api`)
- `SSL_VERIFY` (`true`/`false`)
- `MCP_TRANSPORT` (`stdio`, `sse`, `streamable-http`)
- `MCP_HOST`
- `MCP_PORT`
- `MCP_MOUNT_PATH`
- `MCP_SSE_PATH`
- `MCP_STREAMABLE_HTTP_PATH`

CLI flags are also available and override env values.

## MCP Client Integration

You can use this server with Claude Desktop, Claude Code, Cursor, OpenAI-compatible MCP clients, or any other MCP client.

Example config using `uvx`:

```json
{
  "mcpServers": {
    "cyberbro": {
      "command": "uvx",
      "args": ["mcp-cyberbro"],
      "env": {
        "CYBERBRO_URL": "http://localhost:5000"
      }
    }
  }
}
```

Example with Docker + `stdio`:

```json
{
  "mcpServers": {
    "cyberbro": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-e",
        "CYBERBRO_URL",
        "ghcr.io/stanfrbd/mcp-cyberbro:latest",
        "--transport",
        "stdio"
      ],
      "env": {
        "CYBERBRO_URL": "http://localhost:5000"
      }
    }
  }
}
```

### Usage in VSCode - Example

Create `.vscode/mcp.json`  

```json
{
	"servers": {
		"mcp-cyberbro": {
			"type": "stdio",
			"command": "uvx",
			"args": [
				"mcp-cyberbro"
			],
			"env": {
				"CYBERBRO_URL": "http://127.0.0.1:5000"
			}
		}
	}
}
```

## MCP Registry Metadata

`server.json` is included for MCP Registry publication and points to PyPI package `mcp-cyberbro`.

## Release Pipelines

Release-created workflows:

- `.github/workflows/publish-test-pypi.yml`
- `.github/workflows/publish-pypi.yml`
- `.github/workflows/publish-mcp-plugin.yml`

## Available Tools

- `analyze_observable`
- `is_analysis_complete`
- `get_analysis_results`
- `get_engines`
- `get_web_url`

## Example Prompts

Here are practical prompt examples you can use with any MCP-capable assistant connected to Cyberbro.

### Getting Indicator Details

- Cyberbro: Check indicators for target.com
- Can you check this IP reputation with Cyberbro? 192.168.1.1. Use github, google and virustotal engines.
- I want to analyze the domain example.com. What can Cyberbro tell me about it? Use max 3 engines.
- Analyze these observables with Cyberbro: suspicious-domain.com, 8.8.8.8, and 44d88612fea8a8f36de82e1278abb02f. Use all available engines.

### Observable Analysis

- I found this (hash|domain|url|ip|extension). Can you submit it for analysis to Cyberbro and analyze the results?

### OSINT Investigation

- Create an OSINT report for the domain example.com using Cyberbro. Use all available engines and pivot on the results for more information. Use a maximum of 10 analysis requests.

## Acknowledgements

- [Model Context Protocol](https://modelcontextprotocol.io)
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
- [Cyberbro](https://github.com/stanfrbd/cyberbro)

## License

MIT
