# Automated High-Fidelity Rule Generation Agent: Prototype

**Track:** 350 Hours (Large Project) · **Discussion Thread:** [flare-gsoc#106](https://github.com/mandiant/flare-gsoc/discussions/106)

---

## Overview

This repository contains two prototype modules that prove the feasibility of the
**Closed-Loop Rule Generation Pipeline** proposed in my GSoC 2026 application.

The central insight driving this work: the bottleneck in capa rule maintenance is
not _generating_ YAML, it is _verifying_ it.  LLMs routinely produce plausible-looking
rules that fail the linter, reference non-existent namespaces, or trigger on nothing
in the test corpus.  These prototypes demonstrate how to eliminate that noise
systematically.

```
┌──────────────────────────────────────────────────────────────┐
│                  Closed-Loop Pipeline                        │
│                                                              │
│   User / Issue   ──►  [ grounding_scraper.py ]               │
│                               │                              │
│                    Structured API Context                    │
│                               │                              │
│                               ▼                              │
│                         [ LLM Actor ]                        │
│                               │                              │
│                       Draft YAML Rule                        │
│                               │                              │
│                               ▼                              │
│                    [ linter_feedback.py ]                    │
│                      MockCapaLinter                          │
│                               │                              │
│             ┌─── PASS ────────┴──── FAIL ───┐                │
│             │                               │                │
│             ▼                               ▼                │
│       PR-Ready Rule              [ Critic Module ]           │
│                                  Correction Hints            │
│                                       │                      │
│                                       └──► [ LLM Actor ]     │
│                                           (next iteration)   │
└──────────────────────────────────────────────────────────────┘
```

---

Module 1: `grounding_scraper.py`

- What It Solves

LLMs hallucinate DLL names, parameter counts, and flag constants because their
training data contains noisy, sometimes contradictory documentation.  The scraper
eliminates this noise at the source.

Architecture:

| Component | Role |
|---|---|
| `MsdnGroundingScraper` | Fetches and parses `learn.microsoft.com` pages |
| `ApiGroundingContext` | Typed dataclass holding all extracted signal |
| `to_llm_prompt_block()` | Serialises context to an LLM-injectable Markdown block |

Extraction Strategy:

The scraper uses **landmark anchors** — heading IDs that Microsoft bakes into every
function page (`#syntax`, `#parameters`, `#return-value`, `#requirements`) — rather
than brittle XPaths.  This makes it resilient to front-end redesigns.

```
Raw HTML (learn.microsoft.com)
        │
        ▼  BeautifulSoup + landmark anchors
        │
   Structured ApiGroundingContext
        │
        ├── syntax          → injected into "Function Syntax" LLM prompt section
        ├── parameters      → injected into "Parameter Descriptions" section
        ├── dll_library     → written to capa rule 'lib:' line
        ├── header          → written to capa rule comments
        └── min_client_os   → informs 'os:' feature if relevant
```

### Example: `MoveFileExW` Extraction

Running against the official Microsoft page:

```bash
python grounding_scraper.py \
  --url "https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw"
```

Produces:

```markdown
## Windows API Grounding Context: `MoveFileExW`
**Source:** https://learn.microsoft.com/...

### Syntax
```c
BOOL MoveFileExW(
  LPCWSTR lpExistingFileName,
  LPCWSTR lpNewFileName,
  DWORD   dwFlags
);
```

### Requirements (for capa rule metadata)
| Field | Value |
|---|---|
| DLL / Library | `Kernel32.dll` |
| Header | `winbase.h` |
| Min. Client OS | Windows XP |
```

This block is then prepended to the LLM system prompt, giving the Actor
authoritative facts before it writes a single line of YAML.

### Why This Matters for capa Rules

The `communication/` and `host-interaction/` namespaces contain many rules that
depend on precise Windows API signatures.  A wrong flag value (e.g. `0x2` vs `0x1`
for `MOVEFILE_REPLACE_EXISTING`) produces a rule that never fires.  Grounding
prevents this class of error entirely.

---

## Module 2: `linter_feedback.py`

### What It Solves

Even with grounded context, LLMs make systematic schema mistakes:

| Failure Mode | Example | Frequency (observed in nursery) |
|---|---|---|
| Invalid namespace root | `evasion/filesystem` | Very common |
| Wrong scope spelling | `functions` instead of `function` | Common |
| Missing required metadata | `att&ck` block omitted | Common |
| Feature type underscore | `registry_key` instead of `registry key` | Very common |
| Malformed ATT&CK entry | Missing `::` separator | Occasional |

### Architecture

```
                   ┌─────────────────┐
  Draft YAML ────► │ MockCapaLinter  │ ─── LintResult ──► [ Critic Module ]
                   └─────────────────┘                           │
                                                       Correction Hints
                                                                 │
                                                    ┌────────────▼────────────┐
                                                    │  build_correction_prompt │
                                                    └──────────────────────────┘
                                                                 │
                                                       Injected back into LLM
```

#### `MockCapaLinter`

Validates rules through a deterministic, layered check sequence:

1. **Structural parse** — YAML syntax validity
2. **Top-level keys** — `rule:` and `features:` present
3. **Required metadata** — `name`, `namespace`, `authors`, `description`, `scopes`, `att&ck`
4. **Namespace validity** — root must be in the official capa namespace registry
5. **Scope validity** — values checked against the enumerated capa scope set
6. **ATT&CK format** — entries must follow `Tactic::Technique [TXXXX]` convention
7. **Feature type names** — checked against the complete capa feature vocabulary

Each check emits a typed `LintDiagnostic` with a machine-readable `code` (e.g. `E020`),
a precise `location` (e.g. `rule.meta.namespace`), and the offending value.

#### `CriticModule`

Consumes `LintDiagnostic` objects and produces **Correction Hints**: imperative,
YAML-field-targeted instructions written to match the register capa uses in its
own contributor guidelines.  Example:

> Fix 'rule.meta.namespace': 'evasion/filesystem' is not a valid capa namespace root.
> Did you mean 'anti-analysis/filesystem'? Valid roots: ['anti-analysis', 'collection', ...]

These hints are assembled into a **Correction Prompt** that replaces the original
generation prompt for the next Actor call.  The LLM is told to fix only the
enumerated issues, preventing regression on already-correct sections.

### Demo Run: Fixture 1

```bash
python linter_feedback.py --fixture 1
```

```
══════════════════════════════════════════════════════════════════════
  CLOSED-LOOP VALIDATION: Fixture #1 — invalid namespace + invalid scope
══════════════════════════════════════════════════════════════════════

── Iteration 1 ────────────────────────────────────────────────────────
[✗] FAILED — 2 error(s), 0 warning(s)

[ERROR] (E020) rule.meta.namespace: Invalid namespace root 'evasion'. ...
  got      : 'evasion/filesystem'
  expected : Did you mean 'anti-analysis/filesystem'? Valid roots: [...]

[ERROR] (E030) rule.meta.scopes.static: Invalid scope value 'functions' ...
  got      : 'functions'
  expected : Valid scopes: ['basic block', 'call', 'file', 'function', ...]

──────────────────────────────────────────────
  CORRECTION PROMPT (injected into LLM for next Actor call):
──────────────────────────────────────────────
You are a capa rule author. The rule you generated contains schema errors.
Correct ONLY the issues listed below — do not alter any other part of the rule.

CORRECTION HINTS:
  - Fix 'rule.meta.namespace': 'evasion/filesystem' is not a valid capa namespace root. ...
  - Fix 'rule.meta.scopes': the value 'functions' is not a valid capa scope. ...
...
```

---

## Installation

```bash
# Clone this prototype repository
git clone <repo-url>
cd capa-rule-agent-prototype

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install dependencies
pip install requests beautifulsoup4 pyyaml

# Optional: faster HTML extraction
pip install trafilatura
```

### Dependencies

| Package | Version | Purpose |
|---|---|---|
| `requests` | ≥2.31 | HTTP fetching for MSDN scraper |
| `beautifulsoup4` | ≥4.12 | HTML landmark parsing |
| `pyyaml` | ≥6.0 | Structural YAML parse in linter |

---

## Relationship to the Full GSoC Pipeline

These prototypes implement **Phase 2** (Core Agent) and **Phase 3** (Grounding &
Validation) of the 12-week roadmap.

| Phase | Weeks | Status |
|---|---|---|
| 1 — Nursery & Environment | 1–3 | Manual rule PRs submitted |
| **2 — Core Agent Development** | **4–7** | **`linter_feedback.py` ← this prototype** |
| **3 — Grounding & Validation** | **8–10** | **`grounding_scraper.py` ← this prototype** |
| 4 — Integration & Docs | 11–12 | GitHub Action / CLI wrapper |

The missing piece in these prototypes — the LLM Actor call itself — is the only
integration point that would require an API key and is deliberately left as a
stub (`# In production: yaml_text = call_llm(correction_prompt)`).  Every other
component is fully implemented and testable without external services.

---

## Technical Notes for Reviewers

Why `scripts.lint` is mocked rather than called directly:
The mock is intentionally higher-signal for a prototype: it emits structured,
typed diagnostics that the Critic can parse without regex.  Production integration
will parse the actual `scripts.lint` stderr using the same `LintDiagnostic` model.

**Why BeautifulSoup over Trafilatura:**  
Trafilatura excels at article-style content extraction but discards the structured
HTML tables that carry Requirements data.  BeautifulSoup's landmark-anchor approach
preserves table structure while still ignoring navigation, ads, and sidebar noise.

Namespace and scope lists:
These are sourced directly from `rules/format.md` in the `mandiant/capa` repository
and `capa/rules.py` (the `Scope` enum).  They will be kept in sync via a nightly
CI job that diffs the canonical sources against the agent's internal constants.


