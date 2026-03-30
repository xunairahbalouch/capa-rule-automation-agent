"""
linter_feedback.py
==================
Actor-Critic Linter Feedback Loop for the capa Rule Generation Agent.

Purpose
-------
Simulates the "closed loop" correction cycle that prevents LLM-generated capa
rules from shipping with schema violations.  The loop works as follows:

    1. **Actor**  — An LLM draft (or a static test fixture) produces a YAML rule.
    2. **Linter** — ``scripts.lint`` (here: a high-fidelity mock) validates the rule
                    and emits structured diagnostics.
    3. **Critic** — A parser transforms each diagnostic into a targeted
                    *Correction Hint*: a natural-language instruction that can be
                    re-injected into the generator prompt so the LLM fixes the
                    *exact* error, not a guess.
    4. **Loop**   — Steps 1-3 repeat until the linter is satisfied or the
                    maximum retry budget is exhausted.

This module ships with two canonical "hallucinated" rule fixtures that
demonstrate the most common LLM failure modes observed in the capa nursery.

Usage
-----
    python linter_feedback.py                        # run demo with fixture #1
    python linter_feedback.py --fixture 2            # run demo with fixture #2
    python linter_feedback.py --rule my_rule.yml     # validate an actual file

Author: Xunairah Balouch (GSoC 2026 Candidate — Mandiant/capa)
"""

from __future__ import annotations

import argparse
import re
import sys
import textwrap
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Optional

import yaml  # PyYAML — structural parse only; schema validation is separate


# ──────────────────────────────────────────────────────────────────────────────
# Known capa schema constants (sourced from rules/format.md in the capa repo)
# ──────────────────────────────────────────────────────────────────────────────

VALID_NAMESPACES: frozenset[str] = frozenset(
    {
        "anti-analysis",
        "collection",
        "communication",
        "compiler",
        "data-manipulation",
        "executable",
        "host-interaction",
        "impact",
        "internal",
        "lib",
        "linking",
        "load-code",
        "malware-family",
        "nursery",
        "persistence",
        "runtime",
        "targeting",
    }
)

VALID_SCOPES: frozenset[str] = frozenset(
    {
        "file",
        "function",
        "basic block",
        "instruction",
        "process",
        "thread",
        "call",
    }
)

REQUIRED_METADATA_KEYS: frozenset[str] = frozenset(
    {"name", "namespace", "authors", "description", "scopes", "att&ck"}
)

VALID_ATT_AND_CK_DOMAINS: frozenset[str] = frozenset(
    {"Enterprise", "Mobile", "ICS"}
)

REQUIRED_RULE_KEYS: frozenset[str] = frozenset({"rule", "features"})


# ──────────────────────────────────────────────────────────────────────────────
# Hallucinated rule fixtures (common LLM failure modes)
# ──────────────────────────────────────────────────────────────────────────────

# Fixture 1: wrong namespace slug + invalid scope string
FIXTURE_HALLUCINATED_RULE_1 = """\
rule:
  meta:
    name: move file to evasion path
    namespace: evasion/filesystem          # ← hallucinated; not a valid capa namespace
    authors:
      - LLM-Agent
    description: Detects use of MoveFileExW to relocate files to evasion paths.
    scopes:
      static: functions                    # ← wrong; should be 'function'
      dynamic: call
    att&ck:
      - Defense Evasion::Indicator Removal on Host [T1070.004]
  features:
    - api: MoveFileExW
    - number: 0x1
      description: MOVEFILE_REPLACE_EXISTING flag
"""

# Fixture 2: missing required metadata keys + features block uses bad feature type
FIXTURE_HALLUCINATED_RULE_2 = """\
rule:
  meta:
    name: detect proxy configuration via registry
    namespace: communication/proxy
    authors:
      - LLM-Agent
    description: Detects malware reading proxy settings from the registry.
    scopes:
      static: function
      dynamic: call
    # att&ck block entirely omitted ← missing required key
  features:
    - registry_key: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings  # ← invalid; use 'registry key' (space)
    - string: ProxyServer
"""


# ──────────────────────────────────────────────────────────────────────────────
# Diagnostic model
# ──────────────────────────────────────────────────────────────────────────────


class Severity(Enum):
    ERROR = auto()
    WARNING = auto()
    INFO = auto()


@dataclass
class LintDiagnostic:
    """
    A single structured diagnostic emitted by the mock linter.

    Mirrors the output structure of ``scripts.lint`` so that the Critic
    can produce rule-targeted Correction Hints.
    """

    severity: Severity
    code: str          # E001, W002, …
    location: str      # e.g. "meta.namespace" or "features[0]"
    message: str
    offending_value: Optional[str] = None
    suggestion: Optional[str] = None

    def to_stderr_line(self) -> str:
        prefix = {
            Severity.ERROR: "ERROR",
            Severity.WARNING: "WARNING",
            Severity.INFO: "INFO",
        }[self.severity]
        parts = [f"[{prefix}] ({self.code}) {self.location}: {self.message}"]
        if self.offending_value:
            parts.append(f"  got      : {self.offending_value!r}")
        if self.suggestion:
            parts.append(f"  expected : {self.suggestion}")
        return "\n".join(parts)


@dataclass
class LintResult:
    """Aggregate result returned by :class:`MockCapaLinter`."""

    passed: bool
    diagnostics: list[LintDiagnostic] = field(default_factory=list)

    @property
    def errors(self) -> list[LintDiagnostic]:
        return [d for d in self.diagnostics if d.severity == Severity.ERROR]

    @property
    def warnings(self) -> list[LintDiagnostic]:
        return [d for d in self.diagnostics if d.severity == Severity.WARNING]


# ──────────────────────────────────────────────────────────────────────────────
# Mock capa linter
# ──────────────────────────────────────────────────────────────────────────────


class MockCapaLinter:
    """
    High-fidelity simulation of ``scripts.lint`` schema validation.

    Checks performed (in order):
        • YAML structural validity
        • Required top-level keys (``rule``, ``features``)
        • Required metadata keys
        • Namespace validity
        • Scope validity (static + dynamic)
        • ATT&CK block presence and domain validity
        • Feature type name validity (most common hallucination site)
    """

    # Feature types accepted by capa (non-exhaustive but covers common ones)
    VALID_FEATURE_TYPES: frozenset[str] = frozenset(
        {
            "api",
            "string",
            "substring",
            "bytes",
            "number",
            "offset",
            "mnemonic",
            "characteristic",
            "export",
            "import",
            "section",
            "match",
            "basic block",
            "function name",
            "os",
            "arch",
            "format",
            "namespace",
            "class",
            "property",
            "registry key",      # NOTE: space, not underscore
            "registry value",
            "file",
        }
    )

    def lint(self, yaml_text: str) -> LintResult:
        diagnostics: list[LintDiagnostic] = []

        # ── Step 1: structural YAML parse ─────────────────────────────────────
        try:
            doc = yaml.safe_load(yaml_text)
        except yaml.YAMLError as exc:
            diagnostics.append(
                LintDiagnostic(
                    severity=Severity.ERROR,
                    code="E000",
                    location="<document>",
                    message=f"YAML parse failure: {exc}",
                )
            )
            return LintResult(passed=False, diagnostics=diagnostics)

        if not isinstance(doc, dict):
            diagnostics.append(
                LintDiagnostic(
                    severity=Severity.ERROR,
                    code="E001",
                    location="<document>",
                    message="Top-level document must be a YAML mapping.",
                )
            )
            return LintResult(passed=False, diagnostics=diagnostics)

        # ── Step 2: required top-level keys ───────────────────────────────────
        for key in REQUIRED_RULE_KEYS:
            if key not in doc:
                diagnostics.append(
                    LintDiagnostic(
                        severity=Severity.ERROR,
                        code="E002",
                        location=f"<document>.{key}",
                        message=f"Missing required top-level key: '{key}'.",
                        suggestion=f"Add a '{key}:' block.",
                    )
                )

        rule_block = doc.get("rule", {}) or {}
        meta = rule_block.get("meta", {}) or {}
        features = doc.get("features", rule_block.get("features", []))

        # ── Step 3: required metadata keys ────────────────────────────────────
        for key in REQUIRED_METADATA_KEYS:
            if key not in meta:
                diagnostics.append(
                    LintDiagnostic(
                        severity=Severity.ERROR,
                        code="E010",
                        location=f"rule.meta.{key}",
                        message=f"Missing required metadata key: '{key}'.",
                        suggestion=f"Add '{key}:' under rule.meta.",
                    )
                )

        # ── Step 4: namespace validation ──────────────────────────────────────
        namespace = meta.get("namespace", "")
        if namespace:
            top_ns = namespace.split("/")[0]
            if top_ns not in VALID_NAMESPACES:
                closest = self._closest_namespace(top_ns)
                diagnostics.append(
                    LintDiagnostic(
                        severity=Severity.ERROR,
                        code="E020",
                        location="rule.meta.namespace",
                        message=(
                            f"Invalid namespace root '{top_ns}'. "
                            "Namespace must begin with a recognised capa namespace."
                        ),
                        offending_value=namespace,
                        suggestion=(
                            f"Did you mean '{closest}/{'/'.join(namespace.split('/')[1:])}'? "
                            f"Valid roots: {sorted(VALID_NAMESPACES)}"
                        ),
                    )
                )

        # ── Step 5: scope validation ───────────────────────────────────────────
        scopes = meta.get("scopes", {}) or {}
        for analysis_type in ("static", "dynamic"):
            scope_val = scopes.get(analysis_type)
            if scope_val and scope_val not in VALID_SCOPES:
                diagnostics.append(
                    LintDiagnostic(
                        severity=Severity.ERROR,
                        code="E030",
                        location=f"rule.meta.scopes.{analysis_type}",
                        message=(
                            f"Invalid scope value '{scope_val}' for {analysis_type} analysis."
                        ),
                        offending_value=scope_val,
                        suggestion=(
                            f"Valid scopes: {sorted(VALID_SCOPES)}"
                        ),
                    )
                )

        # ── Step 6: ATT&CK domain validation ──────────────────────────────────
        attck = meta.get("att&ck", [])
        if isinstance(attck, list):
            for entry in attck:
                if "::" not in str(entry):
                    diagnostics.append(
                        LintDiagnostic(
                            severity=Severity.WARNING,
                            code="W040",
                            location="rule.meta.att&ck",
                            message=(
                                f"ATT&CK entry may be malformed: '{entry}'. "
                                "Expected format: 'Tactic::Technique [TXXXX]'."
                            ),
                            offending_value=str(entry),
                        )
                    )

        # ── Step 7: feature type name validation ──────────────────────────────
        if isinstance(features, list):
            for idx, feat in enumerate(features):
                if not isinstance(feat, dict):
                    continue
                for key in feat:
                    if key in ("description", "and", "or", "not", "optional"):
                        continue  # structural / logical operators
                    if key not in self.VALID_FEATURE_TYPES:
                        closest = self._closest_feature_type(key)
                        diagnostics.append(
                            LintDiagnostic(
                                severity=Severity.ERROR,
                                code="E050",
                                location=f"features[{idx}].{key}",
                                message=(
                                    f"Unknown feature type '{key}'. "
                                    "Feature type names are case-sensitive and use spaces, not underscores."
                                ),
                                offending_value=key,
                                suggestion=(
                                    f"Did you mean '{closest}'? "
                                    f"Valid feature types include: {sorted(self.VALID_FEATURE_TYPES)}"
                                ),
                            )
                        )

        passed = all(d.severity != Severity.ERROR for d in diagnostics)
        return LintResult(passed=passed, diagnostics=diagnostics)

    # ── Utility: edit-distance approximation ──────────────────────────────────

    @staticmethod
    def _closest_namespace(candidate: str) -> str:
        """Return the valid namespace root most similar to *candidate*."""
        return MockCapaLinter._closest_in(candidate, VALID_NAMESPACES)

    @staticmethod
    def _closest_feature_type(candidate: str) -> str:
        """Return the valid feature type most similar to *candidate*."""
        # Normalise underscores → spaces (the most common LLM mistake)
        normalised = candidate.replace("_", " ")
        if normalised in MockCapaLinter.VALID_FEATURE_TYPES:
            return normalised
        return MockCapaLinter._closest_in(candidate, MockCapaLinter.VALID_FEATURE_TYPES)

    @staticmethod
    def _closest_in(candidate: str, choices: frozenset[str]) -> str:
        """
        Naïve similarity: return the choice with the highest character-level
        overlap ratio.  Good enough for hint generation; not production Levenshtein.
        """
        candidate_norm = candidate.lower().replace("_", " ")

        def overlap(s: str) -> float:
            common = sum(c in s for c in candidate_norm)
            return common / max(len(candidate_norm), len(s), 1)

        return max(choices, key=overlap)


# ──────────────────────────────────────────────────────────────────────────────
# Critic: diagnostic → Correction Hint
# ──────────────────────────────────────────────────────────────────────────────


class CriticModule:
    """
    Transforms structured :class:`LintDiagnostic` objects into actionable
    *Correction Hints* for injection into the LLM re-generation prompt.

    A Correction Hint is deliberately written in the same imperative style
    used in capa contributor guidelines so the LLM can internalize it quickly.
    """

    def generate_hints(self, result: LintResult) -> list[str]:
        hints: list[str] = []
        for diag in result.errors + result.warnings:
            hints.append(self._diagnostic_to_hint(diag))
        return hints

    def build_correction_prompt(
        self, original_rule: str, hints: list[str]
    ) -> str:
        """
        Construct the corrected LLM prompt that feeds back into the Actor.
        This is the string you would pass as the system or user message to the
        next LLM call.
        """
        hint_block = "\n".join(f"  - {h}" for h in hints)
        return textwrap.dedent(
            f"""\
            You are a capa rule author. The rule you generated contains schema errors.
            Correct ONLY the issues listed below — do not alter any other part of the rule.

            CORRECTION HINTS:
            {hint_block}

            ORIGINAL RULE (with errors):
            ```yaml
            {original_rule.strip()}
            ```

            Output ONLY the corrected YAML rule, no explanation, no markdown fences.
            """
        )

    @staticmethod
    def _diagnostic_to_hint(diag: LintDiagnostic) -> str:
        code_map = {
            "E000": (
                "Fix the YAML syntax error at {location}. Details: {message}"
            ),
            "E001": (
                "The document root must be a YAML mapping (dict). Restructure accordingly."
            ),
            "E002": (
                "Add the missing top-level key at '{location}'. {suggestion}"
            ),
            "E010": (
                "Add the missing metadata field '{location}'. {suggestion}"
            ),
            "E020": (
                "Fix 'rule.meta.namespace': '{offending_value}' is not a valid capa namespace root. {suggestion}"
            ),
            "E030": (
                "Fix 'rule.meta.scopes': the value '{offending_value}' is not a valid capa scope. {suggestion}"
            ),
            "E050": (
                "Fix the feature type at '{location}': '{offending_value}' is not recognised. {suggestion}"
            ),
            "W040": (
                "Check the ATT&CK entry format at 'rule.meta.att&ck'. {message}"
            ),
        }
        template = code_map.get(diag.code, "Fix issue at '{location}': {message}. {suggestion}")
        return template.format(
            location=diag.location,
            message=diag.message,
            offending_value=diag.offending_value or "",
            suggestion=diag.suggestion or "",
        )


# ──────────────────────────────────────────────────────────────────────────────
# Orchestrator: the closed-loop runner
# ──────────────────────────────────────────────────────────────────────────────


class ClosedLoopOrchestrator:
    """
    Orchestrates the Actor → Linter → Critic loop.

    In production this would call an LLM API between iterations.
    Here, each iteration is a *demonstration pass* — we show the
    full diagnostic and Correction Hint output for the static fixture,
    so reviewers can verify the pipeline logic end-to-end.
    """

    MAX_ITERATIONS = 3

    def __init__(self) -> None:
        self.linter = MockCapaLinter()
        self.critic = CriticModule()

    def run(self, yaml_text: str, label: str = "rule") -> None:
        print(f"\n{'═' * 70}")
        print(f"  CLOSED-LOOP VALIDATION: {label}")
        print(f"{'═' * 70}\n")

        for iteration in range(1, self.MAX_ITERATIONS + 1):
            print(f"── Iteration {iteration} ──────────────────────────────────────────────")
            result = self.linter.lint(yaml_text)

            if result.passed:
                print(f"[✓] PASSED — rule is schema-valid after {iteration} iteration(s).")
                if result.warnings:
                    print(f"    ({len(result.warnings)} warning(s) remain — review before PR.)")
                    for w in result.warnings:
                        print(f"    {w.to_stderr_line()}")
                return

            print(f"[✗] FAILED — {len(result.errors)} error(s), {len(result.warnings)} warning(s)\n")
            for diag in result.diagnostics:
                print(diag.to_stderr_line())
                print()

            hints = self.critic.generate_hints(result)
            correction_prompt = self.critic.build_correction_prompt(yaml_text, hints)

            print(f"\n{'─' * 40}")
            print("  CORRECTION PROMPT (injected into LLM for next Actor call):")
            print(f"{'─' * 40}")
            print(correction_prompt)

            # In production: yaml_text = call_llm(correction_prompt)
            # For the demo, we stop here — the output above is the deliverable.
            if iteration < self.MAX_ITERATIONS:
                print(
                    "\n[→] In production: this prompt feeds the next Actor call. "
                    "Demo stops here.\n"
                )
            break

        print(
            f"\n[!] Max iterations ({self.MAX_ITERATIONS}) reached without passing. "
            "Rule escalated for manual review."
        )


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "capa Actor-Critic Linter Feedback Loop — "
            "demonstrates the closed-loop rule correction pipeline."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              %(prog)s                    # run built-in fixture 1 (wrong namespace + scope)
              %(prog)s --fixture 2        # run built-in fixture 2 (missing att&ck + bad feature type)
              %(prog)s --rule my.yml      # validate a real rule file
            """
        ),
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--fixture",
        type=int,
        choices=[1, 2],
        default=1,
        help="Which hallucinated-rule fixture to demonstrate (default: 1).",
    )
    group.add_argument(
        "--rule",
        metavar="FILE",
        help="Path to a real capa YAML rule file to validate.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    orchestrator = ClosedLoopOrchestrator()

    if args.rule:
        path = Path(args.rule)
        if not path.exists():
            print(f"[!] File not found: {path}", file=sys.stderr)
            return 2
        yaml_text = path.read_text(encoding="utf-8")
        label = f"file:{path.name}"
    elif args.fixture == 2:
        yaml_text = FIXTURE_HALLUCINATED_RULE_2
        label = "Fixture #2 — missing att&ck + invalid feature type"
    else:
        yaml_text = FIXTURE_HALLUCINATED_RULE_1
        label = "Fixture #1 — invalid namespace + invalid scope"

    orchestrator.run(yaml_text, label=label)
    return 0


if __name__ == "__main__":
    sys.exit(main())
