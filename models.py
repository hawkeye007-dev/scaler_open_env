from __future__ import annotations

import typing
import pydantic
import uuid


# Action models for agent requests
class ScanAction(pydantic.BaseModel):
	action_type: typing.Literal["scan"]
	target_ip: str
	port_range: str = "1-1024"
	scan_mode: typing.Literal["stealth", "aggressive"] = "stealth"


class ExploitAction(pydantic.BaseModel):
	action_type: typing.Literal["exploit"]
	target_ip: str
	target_port: int
	cve_id: str
	payload_type: typing.Literal["rce", "lfi", "sqli", "bof"]


class SystemAction(pydantic.BaseModel):
	action_type: typing.Literal["system"]
	command: str


class ExfiltrateAction(pydantic.BaseModel):
	action_type: typing.Literal["exfiltrate"]
	file_path: str


class VulnNetAction(pydantic.BaseModel):
	"""Discriminated union of action types."""
	
	model_config = pydantic.ConfigDict(extra='forbid')
	
	action_type: typing.Literal["scan", "exploit", "system", "exfiltrate"]
	target_ip: typing.Optional[str] = None
	port_range: typing.Optional[str] = None
	scan_mode: typing.Optional[typing.Literal["stealth", "aggressive"]] = None
	target_port: typing.Optional[int] = None
	cve_id: typing.Optional[str] = None
	payload_type: typing.Optional[typing.Literal["rce", "lfi", "sqli", "bof"]] = None
	command: typing.Optional[str] = None
	file_path: typing.Optional[str] = None

	@pydantic.model_validator(mode='after')
	def validate_action_fields(self) -> 'VulnNetAction':
		"""Validate that required fields are present for each action type."""
		if self.action_type == "scan":
			if not self.target_ip:
				raise ValueError("scan action requires target_ip")
			if not self.scan_mode:
				self.scan_mode = "stealth"  # Default to stealth
		elif self.action_type == "exploit":
			if not all([self.target_ip, self.target_port, self.cve_id, self.payload_type]):
				raise ValueError("exploit requires target_ip, target_port, cve_id, payload_type")
		elif self.action_type == "system":
			if not self.command:
				raise ValueError("system requires command")
		elif self.action_type == "exfiltrate":
			if not self.file_path:
				raise ValueError("exfiltrate requires file_path")
		return self


ActionType = typing.Annotated[
	typing.Union[ScanAction, ExploitAction, SystemAction, ExfiltrateAction],
	pydantic.Field(discriminator="action_type"),
]


class DiscoveredHost(pydantic.BaseModel):
	ip: str
	open_ports: typing.List[int]
	os_fingerprint: str
	service_banners: typing.Dict[int, str]


class SystemContext(pydantic.BaseModel):
	current_ip: str
	current_uid: str
	cwd: str
	alert_level: float
	ids_triggered: bool


# Observation payload returned to the agent
class VulnNetObservation(pydantic.BaseModel):
	done: bool
	reward: float
	network_map: typing.List[DiscoveredHost] = pydantic.Field(default_factory=list)
	system_context: SystemContext
	terminal_buffer: str = ""
	vulnerability_indicators: typing.List[str] = pydantic.Field(default_factory=list)
	step_count: int = 0
	task_id: str = ""
	info: typing.Dict[str, typing.Any] = pydantic.Field(default_factory=dict)


class VulnNetState(pydantic.BaseModel):
	episode_id: str = pydantic.Field(default_factory=lambda: str(uuid.uuid4()))
	step_count: int = 0
	task_id: str = ""
	seed: int = 42
	current_uid: str = "anonymous"
	alert_level: float = 0.0
	ids_triggered: bool = False
	action_history: typing.List[str] = pydantic.Field(default_factory=list)
	exfil_log: typing.List[str] = pydantic.Field(default_factory=list)
	discovered_privesc_vectors: typing.List[str] = pydantic.Field(default_factory=list)
