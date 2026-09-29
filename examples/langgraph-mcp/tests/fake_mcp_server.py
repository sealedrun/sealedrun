"""A one-tool MCP server over stdio for the example's test."""

from mcp.server.fastmcp import FastMCP

server = FastMCP("fake-files")


@server.tool()
def read_file(path: str) -> str:
    """Return the file's text."""
    return f"contents of {path}"


if __name__ == "__main__":
    server.run()
