"""Atrium extends and patches itself when a new tool needs it.

* pack.py       - extension packs: strict, data-only models (domain, connector, sso, controls and team items)
* registry.py   - stored packs with their versions; enable, disable, rollback - in-process, no restart
* records.py    - records of extension domains (collections "x:<key>"), typed and linked to assets and people
* controls.py   - compliance evidence from extension domains
* gaps.py       - hub-side gaps after an import, and the template packs for well-known kinds of tools
* generate.py   - packs and self-patches written by an AI model (structured output)
* selfpatch.py  - changes to Atrium's own repository: git worktree, tests, approval, pull request or merge
"""
