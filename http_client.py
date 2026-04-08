"""
Simple HTTP-only client for VulnNet environment (no WebSocket dependency)
"""

import aiohttp
import asyncio
import json
from typing import Dict, Any, Optional
from models import VulnNetObservation


class HTTPVulnNetEnv:
    """Direct HTTP client for VulnNet environment."""

    def __init__(self, base_url: str = "http://localhost:7860"):
        self.base_url = base_url.rstrip("/")
        self.session: Optional[aiohttp.ClientSession] = None

    async def _ensure_session(self):
        """Ensure aiohttp session is created."""
        if self.session is None or self.session.closed:
            # Create new session with proper timeout and connection settings
            timeout = aiohttp.ClientTimeout(total=60, connect=10, sock_read=30)
            # Use keepalive and don't force close connections
            connector = aiohttp.TCPConnector(
                limit=100, 
                limit_per_host=30,
                ttl_dns_cache=300,
                force_close=True,  # Force close to avoid connection reuse issues
                enable_cleanup_closed=True
            )
            self.session = aiohttp.ClientSession(timeout=timeout, connector=connector)
            print(f"[DEBUG] Created new aiohttp session", flush=True)

    async def _request(self, method: str, endpoint: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make HTTP request to environment."""
        await self._ensure_session()
        url = f"{self.base_url}{endpoint}"
        
        try:
            if method == "POST":
                async with self.session.post(url, json=data) as resp:
                    if resp.status != 200:
                        text = await resp.text()
                        print(f"[DEBUG] HTTP {resp.status} from {endpoint}: {text}", flush=True)
                        return {"error": f"HTTP {resp.status}"}
                    return await resp.json()
            elif method == "GET":
                async with self.session.get(url) as resp:
                    if resp.status != 200:
                        text = await resp.text()
                        print(f"[DEBUG] HTTP {resp.status} from {endpoint}: {text}", flush=True)
                        return {"error": f"HTTP {resp.status}"}
                    return await resp.json()
        except Exception as e:
            print(f"[DEBUG] Request exception on {endpoint}: {type(e).__name__}: {e}", flush=True)
            import traceback
            traceback.print_exc()
            return {"error": str(e)}

    async def reset(self, task_id: str = "task_1_scout", seed: int = 42) -> VulnNetObservation:
        """Reset environment."""
        result = await self._request("POST", "/reset", {"task_id": task_id, "seed": seed})
        if "error" in result:
            raise RuntimeError(f"Reset failed: {result['error']}")
        
        # Extract observation dict from response
        if isinstance(result, dict) and "observation" in result:
            obs_data = result["observation"]
        else:
            obs_data = result
        
        # Construct VulnNetObservation
        try:
            return VulnNetObservation(**obs_data)
        except Exception as e:
            print(f"[DEBUG] Failed to construct VulnNetObservation: {e}", flush=True)
            print(f"[DEBUG] obs_data: {obs_data}", flush=True)
            raise RuntimeError(f"Failed to parse observation: {e}")

    async def step(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """Execute step in environment."""
        print(f"[DEBUG] Sending step request with action: {action}", flush=True)
        result = await self._request("POST", "/step", {"action": action})
        print(f"[DEBUG] Received step response: {result.get('done')}, reward={result.get('reward')}", flush=True)
        
        if "error" in result:
            raise RuntimeError(f"Step failed: {result['error']}")
        
        # Extract observation dict from response
        if isinstance(result, dict) and "observation" in result:
            obs_data = result["observation"]
        else:
            obs_data = result
        
        # Construct VulnNetObservation
        try:
            obs = VulnNetObservation(**obs_data)
        except Exception as e:
            print(f"[DEBUG] Failed to construct VulnNetObservation: {e}", flush=True)
            print(f"[DEBUG] obs_data: {obs_data}", flush=True)
            raise RuntimeError(f"Failed to parse observation: {e}")
        
        return {
            "observation": obs,
            "reward": result.get("reward", 0.0),
            "done": result.get("done", False),
        }

    async def close(self):
        """Close session."""
        if self.session and not self.session.closed:
            await self.session.close()
            # Wait for all connections to close
            await asyncio.sleep(0.25)
