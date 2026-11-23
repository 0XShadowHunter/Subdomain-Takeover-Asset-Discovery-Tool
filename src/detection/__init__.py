"""Phase 3 — takeover detection & verification.

Four detectors over the Phase 2 data (fingerprint match, dangling CNAME,
NS delegation, best-effort dangling A), confidence/severity scoring, and
false-positive reduction per AGENT_PLAN.md §5. Detection and reporting only —
nothing in this package claims, registers, or exploits any resource.
"""
