from __future__ import annotations

import sys
import typing
import os

# Fix imports - add parent directory to path  
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import (
    DiscoveredHost,
    ExfiltrateAction,
    ExploitAction,
    ScanAction,
    SystemAction,
    SystemContext,
    VulnNetAction,
    VulnNetObservation,
)
from server.network_generator import NetworkConfig, NodeConfig

ALLOWED_COMMANDS = {
    "id",
    "whoami",
    "hostname",
    "uname -a",
    "ps aux",
    "env",
    "ls",
    "cat /etc/passwd",
    "cat /etc/shadow",
    "sudo -l",
    "find / -perm -u=s -type f 2>/dev/null",
    "find . -exec /bin/sh -p \\; -quit",
    "sudo -u#-1 /bin/bash",
    "vim -c :!/bin/sh",
    "python3 -c import os; os.system(/bin/sh)",
    "nmap --script=sudo",
    "clear_logs",
}


# CVE metadata mapping
CVE_META = {
    "CVE-2021-41773": {"uid_grant": "www-data", "payload_type": "lfi"},
    "CVE-2021-4034": {"uid_grant": "root", "payload_type": "rce"},
    "CVE-2019-14287": {"uid_grant": "root", "payload_type": "system"},
}


class NetworkStateMachine:
    """State machine managing a cyber-range network and agent interactions."""

    def __init__(
        self,
        network_config: NetworkConfig,
        task_id: str,
        max_steps: int,
        start_uid: str = "anonymous",
    ) -> None:
        self.nodes: typing.Dict[str, NodeConfig] = {
            n.ip: n for n in network_config.nodes
        }
        self.task_id = task_id
        self.max_steps = max_steps
        self.current_uid = start_uid
        self.current_ip = network_config.entry_point
        self.alert_level = 0.0
        self.ids_triggered = False
        self.network_map: typing.List[DiscoveredHost] = []
        self.action_history: typing.List[str] = []
        self.exfil_log: typing.List[str] = []
        self.discovered_privesc_vectors: typing.List[str] = []
        self.step_count = 0
        self.sudo_l_checked = False

    def get_initial_observation(self) -> VulnNetObservation:
        """Return the initial observation at episode start."""
        system_context = SystemContext(
            current_ip=self.current_ip,
            current_uid=self.current_uid,
            cwd="/",
            alert_level=self.alert_level,
            ids_triggered=self.ids_triggered,
        )
        return VulnNetObservation(
            done=False,
            reward=0.0,
            network_map=[],
            system_context=system_context,
            terminal_buffer="",
            vulnerability_indicators=[],
            step_count=0,
            task_id=self.task_id,
            info={},
        )

    def transition(self, action: VulnNetAction) -> VulnNetObservation:
        """Process an action and return the resulting observation."""
        self.step_count += 1
        print(f"[DEBUG] transition() START: step_count={self.step_count}, max_steps={self.max_steps}", flush=True)
        result: typing.Dict[str, typing.Any] = {"buffer": "", "reward": 0.0}

        if action.action_type == "scan":
            result = self._handle_scan(action)
        elif action.action_type == "exploit":
            result = self._handle_exploit(action)
        elif action.action_type == "system":
            result = self._handle_system(action)
        elif action.action_type == "exfiltrate":
            result = self._handle_exfiltrate(action)

        # Check task completion
        task_complete = self._check_task_complete()
        done = self.ids_triggered or self.step_count >= self.max_steps or task_complete
        print(f"[DEBUG] Task {self.task_id}: task_complete={task_complete}, done={done}", flush=True)
        print(f"[DEBUG] Step {self.step_count}/{self.max_steps}: IDS={self.ids_triggered}, alert={self.alert_level:.2f}, done={done}", flush=True)
        return self._build_obs(result["buffer"], result["reward"], done)

    def _handle_scan(self, action: ScanAction) -> typing.Dict[str, typing.Any]:
        """Handle a scan action against a target IP."""
        if action.target_ip not in self.nodes:
            return {"buffer": f"Target {action.target_ip} not found on network", "reward": -0.05}

        node = self.nodes[action.target_ip]

        # Alert cost based on scan mode
        alert_cost = 0.05 if action.scan_mode == "stealth" else 0.30
        self.alert_level = min(1.0, self.alert_level + alert_cost)
        self._check_ids()

        # Track discovery
        already_known = any(h.ip == action.target_ip for h in self.network_map)
        step_reward = 0.0

        if not already_known:
            self.network_map.append(
                DiscoveredHost(
                    ip=node.ip,
                    open_ports=node.open_ports,
                    os_fingerprint=node.os,
                    service_banners=node.services,
                )
            )
            step_reward += 0.05
            role_flag = f"node_{node.role}_scanned"
            if role_flag not in self.action_history:
                self.action_history.append(role_flag)
                if (
                    node.role == "webserver"
                    and "webserver_found" not in self.action_history
                ):
                    self.action_history.append("webserver_found")
        else:
            # Known host: give small reward for updating information
            step_reward += 0.01

        buf = (
            f"Scan complete: {node.ip} | ports={node.open_ports} | OS={node.os}"
        )
        return {"buffer": buf, "reward": step_reward}

    def _handle_exploit(self, action: ExploitAction) -> typing.Dict[str, typing.Any]:
        """Handle an exploit action with 4 gates."""
        # Gate 1: IP must be in scanned network_map
        ip_in_map = any(h.ip == action.target_ip for h in self.network_map)
        if not ip_in_map:
            self.alert_level = min(1.0, self.alert_level + 0.25)
            self._check_ids()
            return {
                "buffer": f"Cannot exploit {action.target_ip}: host not discovered",
                "reward": -0.05,
            }

        if action.target_ip not in self.nodes:
            return {"buffer": f"Target {action.target_ip} not found", "reward": -0.1}

        node = self.nodes[action.target_ip]

        # Gate 2: Port must be open
        if action.target_port not in node.open_ports:
            self.alert_level = min(1.0, self.alert_level + 0.10)
            self._check_ids()
            return {
                "buffer": f"Port {action.target_port} not open on {action.target_ip}",
                "reward": -0.02,
            }

        # Gate 3: CVE must exist on node
        if action.cve_id not in node.vulnerabilities:
            self.alert_level = min(1.0, self.alert_level + 0.25)
            self._check_ids()
            return {
                "buffer": f"Exploit {action.cve_id} not applicable to {action.target_ip}",
                "reward": -0.10,
            }

        # Gate 4: Payload type must match CVE
        if action.cve_id not in CVE_META:
            return {
                "buffer": f"Unknown CVE: {action.cve_id}",
                "reward": -0.05,
            }

        cve_info = CVE_META[action.cve_id]
        if action.payload_type != cve_info["payload_type"]:
            return {
                "buffer": f"Payload type {action.payload_type} mismatch for {action.cve_id}",
                "reward": -0.05,
            }

        # All gates pass: exploit succeeds
        if action.cve_id == "CVE-2021-41773":
            self.action_history.append("cve_41773_attempted")

        uid_grant = cve_info["uid_grant"]
        self.current_uid = uid_grant
        self.current_ip = action.target_ip  # Update current IP to the compromised host

        uid_flag = "uid_www_data" if uid_grant == "www-data" else "uid_root"
        if uid_flag not in self.action_history:
            self.action_history.append(uid_flag)

        reward = 0.30 if uid_grant == "www-data" else 0.50
        self.alert_level = min(1.0, self.alert_level + 0.05)
        self._check_ids()

        buf = f"Exploit successful. Shell obtained as {uid_grant}"
        return {"buffer": buf, "reward": reward}

    def _handle_system(self, action: SystemAction) -> typing.Dict[str, typing.Any]:
        """Handle a system command with permission and escalation logic."""
        if action.command not in ALLOWED_COMMANDS:
            return {
                "buffer": f"Command not allowed: {action.command}",
                "reward": -0.05,
            }

        # Permission check: anonymous cannot run most commands
        if self.current_uid == "anonymous" and action.command not in {
            "id",
            "whoami",
            "hostname",
        }:
            return {
                "buffer": "Permission denied: no shell",
                "reward": -0.02,
            }

        self.alert_level = min(1.0, self.alert_level + 0.01)

        # Command dispatch
        if action.command in ("id", "whoami"):
            self.action_history.append("id_checked")
            buf = f"uid={self.current_uid}"
            return {"buffer": buf, "reward": 0.01}

        if action.command == "hostname":
            buf = "vulnnet-range"
            return {"buffer": buf, "reward": 0.0}

        if action.command == "sudo -l":
            self.sudo_l_checked = True
            self.action_history.append("sudo_l_checked")
            buf = "User www-data may run (ALL) NOPASSWD: ALL"
            return {"buffer": buf, "reward": 0.02}

        if action.command == "find / -perm -u=s -type f 2>/dev/null":
            node = self.nodes.get(self.current_ip)
            if node and node.suid_binary:
                self.discovered_privesc_vectors.append(node.suid_binary)
                self.action_history.append("suid_discovered")
                buf = f"{node.suid_binary}"
                self._check_ids()
                return {"buffer": buf, "reward": 0.03}
            return {"buffer": "No SUID binaries found", "reward": 0.0}

        # Escalation commands
        if action.command in (
            "find . -exec /bin/sh -p \\; -quit",
            "vim -c :!/bin/sh",
            "python3 -c import os; os.system(/bin/sh)",
            "nmap --script=sudo",
        ):
            node = self.nodes.get(self.current_ip)
            if (
                node
                and node.suid_binary
                and self.current_uid != "anonymous"
            ):
                self.current_uid = "root"
                self.action_history.append("uid_root")
                self._check_ids()
                return {
                    "buffer": "Privilege escalation successful. UID: root",
                    "reward": 0.50,
                }
            return {
                "buffer": "Command failed: prerequisites not met",
                "reward": -0.02,
            }

        if action.command == "sudo -u#-1 /bin/bash":
            if self.sudo_l_checked:
                self.current_uid = "root"
                self.action_history.append("uid_root")
                self._check_ids()
                return {
                    "buffer": "Privilege escalation successful. UID: root",
                    "reward": 0.50,
                }
            return {
                "buffer": "sudo: no sudo -l output to escalate",
                "reward": -0.02,
            }

        if action.command == "clear_logs":
            self.alert_level = max(0.0, self.alert_level - 0.10)
            self.action_history.append("logs_cleared")
            self._check_ids()
            return {"buffer": "Logs cleared.", "reward": 0.02}

        if action.command == "cat /etc/passwd":
            if self.current_uid != "anonymous":
                node = self.nodes.get(self.current_ip)
                if node and "/etc/passwd" in node.filesystem:
                    buf = node.filesystem["/etc/passwd"]
                    return {"buffer": buf, "reward": 0.05}
            return {"buffer": "Permission denied", "reward": -0.02}

        if action.command == "cat /etc/shadow":
            if self.current_uid == "root":
                node = self.nodes.get(self.current_ip)
                if node and "/etc/shadow" in node.filesystem:
                    buf = node.filesystem["/etc/shadow"]
                    return {"buffer": buf, "reward": 0.10}
            return {"buffer": "Permission denied", "reward": -0.02}

        # Default: return stub output
        self._check_ids()
        return {"buffer": f"Command output: {action.command}\nOK", "reward": 0.01}

    def _handle_exfiltrate(
        self, action: ExfiltrateAction
    ) -> typing.Dict[str, typing.Any]:
        """Handle file exfiltration with permission checks."""
        node = self.nodes.get(self.current_ip)
        if not node or action.file_path not in node.filesystem:
            return {
                "buffer": f"File not found: {action.file_path}",
                "reward": -0.02,
            }

        # Permission checks
        if action.file_path == "/etc/shadow" and self.current_uid != "root":
            return {
                "buffer": f"Permission denied: {action.file_path}",
                "reward": -0.02,
            }

        if "/etc/passwd" in action.file_path and self.current_uid == "anonymous":
            return {
                "buffer": f"Permission denied: {action.file_path}",
                "reward": -0.02,
            }

        exfil_flag = f"exfil_{action.file_path}"
        if exfil_flag in self.exfil_log:
            return {
                "buffer": f"File already exfiltrated: {action.file_path}",
                "reward": 0.0,
            }

        self.exfil_log.append(exfil_flag)
        self.alert_level = min(1.0, self.alert_level + 0.02)
        self._check_ids()

        reward = 0.10 if "/etc/shadow" in action.file_path else 0.05

        buf = f"Exfiltration complete: {action.file_path} ({len(node.filesystem[action.file_path])} bytes)"
        return {"buffer": buf, "reward": reward}

    def _check_ids(self) -> None:
        """Trigger IDS if alert level reaches or exceeds 1.0."""
        if self.alert_level >= 1.0 and not self.ids_triggered:
            self.ids_triggered = True
            self.action_history.append("IDS ALERT: Connection terminated.")

    def _check_task_complete(self) -> bool:
        """Check if task objectives are met."""
        if self.task_id == "task_1_scout":
            # Task complete when all 3 nodes discovered
            return len(self.network_map) >= 3
        elif self.task_id == "task_2_breaker":
            # Task complete when www-data shell obtained AND /etc/passwd exfiltrated
            return (self.current_uid == "www-data" and "exfil_/etc/passwd" in self.exfil_log)
        elif self.task_id == "task_3_ghost":
            # Task complete when root obtained AND /etc/shadow exfiltrated
            return (self.current_uid == "root" and "exfil_/etc/shadow" in self.exfil_log)
        return False

    def _build_obs(
        self, buffer: str, reward: float, done: bool
    ) -> VulnNetObservation:
        """Construct a VulnNetObservation from current state."""
        # Include IDS alert in terminal buffer when triggered
        if self.ids_triggered and "IDS ALERT" not in buffer:
            buffer = "IDS ALERT: Anomalous traffic detected. Connection terminated.\n" + buffer
        
        system_context = SystemContext(
            current_ip=self.current_ip,
            current_uid=self.current_uid,
            cwd="/home",
            alert_level=self.alert_level,
            ids_triggered=self.ids_triggered,
        )
        return VulnNetObservation(
            done=done,
            reward=reward,
            network_map=list(self.network_map),
            system_context=system_context,
            terminal_buffer=buffer,
            vulnerability_indicators=self.discovered_privesc_vectors,
            step_count=self.step_count,
            task_id=self.task_id,
            info={},
        )
