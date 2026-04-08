import sys
import typing
import os
from typing import Optional

from fastapi import FastAPI, Request
from pydantic import BaseModel

# Fix imports - add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import VulnNetAction, VulnNetObservation
from server.vulnnet_environment import VulnNetEnvironment


# Persistent singleton environment
_env_instance = VulnNetEnvironment()

# Create FastAPI app manually - NOT using create_fastapi_app 
app = FastAPI()


class ActionRequest(BaseModel):
    action: dict


class ResetRequest(BaseModel):
    task_id: Optional[str] = None
    seed: Optional[int] = None


@app.get("/health")
def health() -> dict:
    return {"status": "healthy", "env": "vulnnet-env", "version": "1.0.0"}


@app.post("/reset")
def reset_endpoint(req: Optional[ResetRequest] = None) -> dict:
    """Reset the environment with persistent singleton."""
    try:
        # Handle empty body or missing fields
        if req is None:
            req = ResetRequest()
        
        task_id = req.task_id or "task_1_scout"
        seed = req.seed or 42
        
        obs = _env_instance.reset(task_id=task_id, seed=seed)
        return {
            "observation": obs.model_dump(),
            "reward": obs.reward,
            "done": obs.done,
        }
    except Exception as e:
        print(f"[ERROR] Reset failed: {e}", flush=True)
        import traceback
        print(traceback.format_exc(), flush=True)
        return {"error": str(e)}


@app.post("/step")
def step_endpoint(req: ActionRequest) -> dict:
    """Execute step with persistent singleton."""
    try:
        # Validate action - use model_validate instead of the old __init__ validation
        action_dict = req.action
        
        # Pass the dict directly to the environment without strict pydantic validation
        # The environment will handle validation internally
        from models import VulnNetAction
        
        # Validate using Pydantic but allow extra fields
        action = VulnNetAction.model_validate(action_dict)
        
        obs = _env_instance.step(action)
        return {
            "observation": obs.model_dump(),
            "reward": obs.reward,
            "done": obs.done,
        }
    except Exception as e:
        print(f"[ERROR] Step failed: {e}", flush=True)
        import traceback
        print(traceback.format_exc(), flush=True)
        return {"error": str(e)}


@app.on_event("startup")
def startup_event():
    """Initialize environment on server startup."""
    print("[INFO] Initializing VulnNet environment...", flush=True)
    try:
        _env_instance.reset()
        print("[INFO] Environment initialized successfully", flush=True)
    except Exception as e:
        print(f"[ERROR] Failed to initialize environment: {e}", flush=True)
        import traceback
        print(traceback.format_exc(), flush=True)


def main():
    import uvicorn
    import logging
    
    # Configure logging
    logging.basicConfig(level=logging.DEBUG)
    
    uvicorn.run(app, host="0.0.0.0", port=7860, log_level="debug")


if __name__ == "__main__":
    main()
