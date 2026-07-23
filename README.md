# ghidra-mcp-c64

C64-specific MCP tools layered over the public `ghidra-mcp` HTTP API and the
separately installed Ghidra VICE connector.

The server uses stdio transport by default. It does not open a VICE binary
monitor socket; the connector remains the sole owner of that connection.

