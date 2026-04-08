STEP_REWARDS = {
	"new_host_discovered": +0.050,
	"new_port_discovered": +0.030,
	"uid_www_data": +0.300,
	"uid_root": +0.500,
	"file_exfiltrated": +0.100,
	"exploit_failed": -0.100,
	"command_not_allowed": -0.050,
	"step_decay": -0.002,
}


def compute_step_reward(
	prev_network_map_len: int,
	new_network_map_len: int,
	prev_uid: str,
	new_uid: str,
	prev_exfil_len: int,
	new_exfil_len: int,
	outcome: str,
) -> float:
	"""Compute per-step reward based on state transitions.
	
	Args:
		prev_network_map_len: Number of discovered hosts before action
		new_network_map_len: Number of discovered hosts after action
		prev_uid: privilege level before action
		new_uid: privilege level after action
		prev_exfil_len: Number of exfiltrated files before action
		new_exfil_len: Number of exfiltrated files after action
		outcome: Action outcome ('exploit_failed', 'command_not_allowed', 'success', etc)
	
	Returns:
		Reward value, rounded to 4 decimal places. Includes:
		- Step decay penalty (-0.002 per step)
		- Host discovery bonus (+0.050 per new host)
		- Privilege escalation bonus (+0.300 for www-data, +0.500 for root)
		- Data exfiltration bonus (+0.100 per file)
		- Failure penalties (-0.100 or -0.050)
	"""
	r = STEP_REWARDS["step_decay"]

	# Host discovery rewards
	new_hosts = new_network_map_len - prev_network_map_len
	r += new_hosts * STEP_REWARDS["new_host_discovered"]

	# Privilege escalation rewards
	if prev_uid != "www-data" and new_uid == "www-data":
		r += STEP_REWARDS["uid_www_data"]
	if prev_uid != "root" and new_uid == "root":
		r += STEP_REWARDS["uid_root"]

	# Data exfiltration rewards
	new_files = new_exfil_len - prev_exfil_len
	r += new_files * STEP_REWARDS["file_exfiltrated"]

	# Outcome penalties
	if outcome == "exploit_failed":
		r += STEP_REWARDS["exploit_failed"]
	if outcome == "command_not_allowed":
		r += STEP_REWARDS["command_not_allowed"]

	return round(r, 4)
