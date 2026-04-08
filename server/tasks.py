from dataclasses import dataclass
from typing import Dict, List


@dataclass
class Task:
	"""Task definition for a cyber-range challenge."""

	task_id: str
	name: str
	difficulty: str
	max_steps: int
	alert_threshold: float
	milestones: List[str]
	score_weights: Dict[str, float]


TASK_REGISTRY: Dict[str, Task] = {
	"task_1_scout": Task(
		task_id="task_1_scout",
		name="The Scout",
		difficulty="easy",
		max_steps=20,
		alert_threshold=1.0,
		milestones=[
			"node_gateway_scanned",
			"node_webserver_scanned",
			"node_db_scanned",
		],
		score_weights={
			"node_gateway_scanned": 0.20,
			"node_webserver_scanned": 0.20,
			"node_db_scanned": 0.20,
			"node_gateway_ports_correct": 0.10,
			"node_webserver_ports_correct": 0.10,
			"node_db_ports_correct": 0.10,
			"node_gateway_os_correct": 0.03,
			"node_webserver_os_correct": 0.04,
			"node_db_os_correct": 0.03,
		},
	),
	"task_2_breaker": Task(
		task_id="task_2_breaker",
		name="The Breaker",
		difficulty="medium",
		max_steps=35,
		alert_threshold=0.80,
		milestones=[
			"webserver_found",
			"cve_41773_attempted",
			"uid_www_data",
			"passwd_exfiltrated",
		],
		score_weights={
			"webserver_found": 0.20,
			"cve_41773_attempted": 0.20,
			"uid_www_data": 0.35,
			"passwd_exfiltrated": 0.25,
		},
	),
	"task_3_ghost": Task(
		task_id="task_3_ghost",
		name="The Ghost",
		difficulty="hard",
		max_steps=50,
		alert_threshold=0.60,
		milestones=[
			"id_checked",
			"sudo_l_checked",
			"suid_discovered",
			"uid_root",
			"shadow_exfiltrated",
			"logs_cleared",
		],
		score_weights={
			"id_checked": 0.05,
			"sudo_l_checked": 0.10,
			"suid_discovered": 0.15,
			"uid_root": 0.45,
			"shadow_exfiltrated": 0.20,
			"logs_cleared": 0.05,
		},
	),
}
