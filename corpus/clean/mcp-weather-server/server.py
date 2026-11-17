"""A small weather MCP server (read-only, one public API)."""
import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("weather")
API = "https://api.weather.gov"


@mcp.tool()
async def forecast(latitude: float, longitude: float) -> str:
    """Get the short-term forecast for a US location."""
    async with httpx.AsyncClient(timeout=10, headers={"User-Agent": "weather-mcp/1.0"}) as client:
        points = (await client.get(f"{API}/points/{latitude},{longitude}")).json()
        periods = (await client.get(points["properties"]["forecast"])).json()["properties"]["periods"]
    return "\n".join(f"{p['name']}: {p['detailedForecast']}" for p in periods[:3])


if __name__ == "__main__":
    mcp.run()
