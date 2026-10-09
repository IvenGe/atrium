"""The agent team.

* Hub Supervisor        - orchestrates everything and talks to every other agent.
* Tool Supervisors      - one per imported tool, responsible for that application.
* Asset / GRC Supervisors - responsible for the built-in Assets and Compliance apps.
* Patch Agent           - closes integration gaps with code patches and adapters.
* Operator Agent        - runs commands on this machine or on remote hosts over SSH.
"""
