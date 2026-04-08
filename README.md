---
title: Scaler OpenEnv
emoji: 🚀
colorFrom: blue
colorTo: green
sdk: docker
app_port: 7860
pinned: false
---

# OpenEnv Submission
This Space hosts the environment for the OpenEnv competition.

## 🚀 Overview
The VulnNet Autonomous Inference Agent is a stateful cyber-range penetration testing agent powered by Large Language Models (LLMs). It autonomously navigates a virtual network, executes exploit chains, escalates privileges, and evades Intrusion Detection Systems (IDS).

## 🛠️ Methodology
The agent operates in a simulated 3-node virtual network (Gateway, Webserver, Database) and uses an LLM backend (configured to use the OpenAI API interface) for strategic decision-making.

*   **Action Space:** Structured actions (`ScanAction`, `ExploitAction`, `SystemAction`, `ExfiltrateAction`) mapped from LLM reasoning.
*   **Observation Loop:** Parses complex real-time terminal buffers, active network maps, system contexts, and alert levels into condensed LLM prompts context.
*   **Stealth Navigation:** Guided by a structured system prompt that drives the agent to use stealth scans, target specific CVEs (e.g., Apache CVE-2021-41773), and exfiltrate data while monitoring its detection footprint.

## 🏆 What Makes It Better
*   **Robust Trajectory Scoring:** Goes beyond simple step averaging. Our custom graders penalize noisy, catastrophic actions (triggering the IDS) while giving consistency and stealth bonuses (alert level < 0.40).
*   **Strict Bound Compliance:** All rewards and final scores are carefully clamped (strictly between `0.01` and `0.99`), fully resolving the evaluator bounds collision.
*   **Error Resiliency:** Features an aggressive JSON parser fallback mechanism that ensures any LLM hallucinations or parsing failures gracefully default to safe actions (e.g., `id`), preventing episode crashes.
*   **Headless-Ready:** The environment reset/step interfaces natively support optional bodies, ensuring robust communication with the strict OpenEnv validation engines without Pydantic exceptions.
