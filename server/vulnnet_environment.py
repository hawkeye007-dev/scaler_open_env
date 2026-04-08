from __future__ import annotations

import sys
import typing
import os
from uuid import uuid4

# Fix imports - add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from openenv.core.env_server.interfaces import Environment

from models import VulnNetAction, VulnNetObservation, VulnNetState
from server.network_generator import NetworkGenerator
from server.state_machine import NetworkStateMachine

# Import graders at the top to catch import errors early
try:
	from server.graders import grade
except ImportError as e:
	print(f"[WARNING] Failed to import graders: {e}", flush=True)
	grade = None


class VulnNetEnvironment(Environment):
	"""Stateful cyber-range environment for penetration-testing agents."""

	TASKS = ["task_1_scout", "task_2_breaker", "task_3_ghost"]
	MAX_STEPS = {
		"task_1_scout": 20,
		"task_2_breaker": 35,
		"task_3_ghost": 50,
	}

	def __init__(self) -> None:
		self._state: typing.Optional[VulnNetState] = None
		self._machine: typing.Optional[NetworkStateMachine] = None
		self._task_id: str = "task_1_scout"

	def reset(
		self,
		task_id: typing.Optional[str] = "task_1_scout",
		seed: typing.Optional[int] = 42,
	) -> VulnNetObservation:
		"""Reset the environment and start a new episode."""
		task_id = task_id or "task_1_scout"
		seed = seed if seed is not None else 42

		# Generate network topology
		generator = NetworkGenerator(seed=seed)
		network_config = generator.build()

		# Determine starting UID based on task difficulty
		start_uid = "www-data" if task_id == "task_3_ghost" else "anonymous"

		# Create state machine with network and task config
		max_steps = self.MAX_STEPS.get(task_id, 20)
		print(f"[DEBUG] reset() - task_id={task_id}, max_steps={max_steps}", flush=True)
		self._machine = NetworkStateMachine(
			network_config=network_config,
			task_id=task_id,
			max_steps=max_steps,
			start_uid=start_uid,
		)

		# Initialize episode state
		self._state = VulnNetState(
			episode_id=str(uuid4()),
			step_count=0,
			task_id=task_id,
			seed=seed,
			current_uid=start_uid,
			alert_level=0.0,
			ids_triggered=False,
			action_history=[],
			exfil_log=[],
			discovered_privesc_vectors=[],
		)
		self._task_id = task_id

		return self._machine.get_initial_observation()

	def step(self, action: VulnNetAction) -> VulnNetObservation:
		"""Execute an action and return the resulting observation."""
		# Auto-initialize if not reset yet
		if self._machine is None:
			self.reset()
		
		if self._machine is None:
			raise RuntimeError("Environment initialization failed")

		self._state.step_count += 1
		obs = self._machine.transition(action)

		# Sync state from machine back to VulnNetState
		self._state.current_uid = self._machine.current_uid
		self._state.alert_level = self._machine.alert_level
		self._state.ids_triggered = self._machine.ids_triggered
		self._state.action_history = list(self._machine.action_history)
		self._state.exfil_log = list(self._machine.exfil_log)
		self._state.discovered_privesc_vectors = list(
			self._machine.discovered_privesc_vectors
		)

		# Wire grader score into final observation
		if obs.done:
			if grade is not None:
				try:
					network_config = NetworkGenerator(seed=self._state.seed).build()
					final_score = grade(self._task_id, self._machine, network_config)
					print(f"[DEBUG] Task {self._task_id} completed - Final score: {final_score}", flush=True)
					print(f"[DEBUG] Network map: {len(self._machine.network_map)} hosts discovered", flush=True)
					print(f"[DEBUG] Alert level: {self._machine.alert_level}, IDS triggered: {self._machine.ids_triggered}", flush=True)
					obs = obs.model_copy(update={'reward': final_score})
				except Exception as e:
					print(f"[ERROR] Grading failed: {e}", flush=True)
					import traceback
					print(traceback.format_exc(), flush=True)
					# Keep the observation as-is if grading fails

		return obs

	async def reset_async(
		self,
		task_id: typing.Optional[str] = "task_1_scout",
		seed: typing.Optional[int] = 42,
	) -> VulnNetObservation:
		"""Async version of reset."""
		return self.reset(task_id=task_id, seed=seed)

	def close(self) -> None:
		"""Clean up resources."""
		self._machine = None
		self._state = None

	@property
	def state(self) -> typing.Optional[VulnNetState]:
		"""Get current episode state."""
		return self._state
