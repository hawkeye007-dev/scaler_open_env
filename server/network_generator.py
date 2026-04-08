from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class NodeConfig:
    """Configuration for a single network node."""

    ip: str
    role: str
    os: str
    open_ports: List[int]
    services: Dict[int, str]
    vulnerabilities: List[str]
    filesystem: Dict[str, str]
    suid_binary: str


@dataclass
class NetworkConfig:
    """Complete network configuration."""

    nodes: List[NodeConfig]
    subnet: str
    entry_point: str


class NetworkGenerator:
    """Generate deterministic network topologies seeded by a fixed value."""

    def __init__(self, seed: int = 42) -> None:
        self.seed = seed
        self.rng = random.Random(seed)

    def build(self) -> NetworkConfig:
        """Build and return a 3-node network configuration."""
        # CVE pool: rotates among nodes based on seed
        cve_assignments = [
            {
                "target_ip": "192.168.1.20",
                "cve_id": "CVE-2021-41773",
                "service": "Apache/2.4.49",
                "payload_type": "lfi",
            },
            {
                "target_ip": "192.168.1.10",
                "cve_id": "CVE-2021-4034",
                "service": "pkexec",
                "payload_type": "rce",
            },
            {
                "target_ip": "192.168.1.30",
                "cve_id": "CVE-2019-14287",
                "service": "sudo<1.8.28",
                "payload_type": "system",
            },
        ]

        # SUID binary pool: rotates based on seed
        suid_binaries = [
            "/usr/bin/find",
            "/usr/bin/vim",
            "/usr/bin/python3",
            "/usr/bin/nmap",
        ]

        # Select CVE and SUID based on seed
        cve_idx = self.seed % 3
        suid_idx = self.seed % 4
        assigned_cve = cve_assignments[cve_idx]
        assigned_suid = suid_binaries[suid_idx]

        # Node A: Gateway
        node_a = NodeConfig(
            ip="192.168.1.10",
            role="gateway",
            os="Linux",
            open_ports=[22, 80],
            services={22: "OpenSSH/7.4", 80: "nginx/1.14"},
            vulnerabilities=(
                [assigned_cve["cve_id"]]
                if assigned_cve["target_ip"] == "192.168.1.10"
                else []
            ),
            filesystem={
                "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:admin:/home/admin:/bin/bash",
                "/root/.ssh/authorized_keys": "ssh-rsa AAAA...",
            },
            suid_binary=assigned_suid
            if assigned_cve["target_ip"] == "192.168.1.10"
            else "",
        )

        # Node B: Web Server
        node_b = NodeConfig(
            ip="192.168.1.20",
            role="webserver",
            os="Linux",
            open_ports=[80, 443, 8080],
            services={
                80: "Apache/2.4.49",
                443: "Apache/2.4.49",
                8080: "Python/3.8",
            },
            vulnerabilities=(
                [assigned_cve["cve_id"]]
                if assigned_cve["target_ip"] == "192.168.1.20"
                else []
            ),
            filesystem={
                "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33::/var/www:/bin/sh",
                "/etc/shadow": "root:$6$salt$hash:18000:0:99999:7:::",
                "/var/www/html/index.html": "Apache Default Page",
            },
            suid_binary=assigned_suid
            if assigned_cve["target_ip"] == "192.168.1.20"
            else "",
        )

        # Node C: Database
        node_c = NodeConfig(
            ip="192.168.1.30",
            role="db",
            os="Linux",
            open_ports=[3306, 5432],
            services={3306: "MySQL/5.7", 5432: "PostgreSQL/10"},
            vulnerabilities=(
                [assigned_cve["cve_id"]]
                if assigned_cve["target_ip"] == "192.168.1.30"
                else []
            ),
            filesystem={
                "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nmysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false",
                "/var/lib/mysql/config": "[mysqld]\nport=3306",
            },
            suid_binary=assigned_suid
            if assigned_cve["target_ip"] == "192.168.1.30"
            else "",
        )

        return NetworkConfig(
            nodes=[node_a, node_b, node_c],
            subnet="192.168.1.0/24",
            entry_point="192.168.1.1",
        )
