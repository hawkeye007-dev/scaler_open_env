from openenv.core.env_client import EnvClient
from openenv.core.client_types import StepResult
from models import VulnNetAction, VulnNetObservation, VulnNetState

class VulnNetEnv(EnvClient[VulnNetAction, VulnNetObservation, VulnNetState]):
    def _step_payload(self, action: VulnNetAction) -> dict:
        return action.model_dump()

    def _parse_result(self, payload: dict) -> StepResult[VulnNetObservation]:
        obs = VulnNetObservation(**payload.get("observation", {}))
        return StepResult(
            observation=obs,
            reward=payload.get("reward", 0.0),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: dict) -> VulnNetState:
        return VulnNetState(**payload)
