# GSoC 2026: Automated High-Fidelity Rule Generation Agent for capa

A technical proposal and proof-of-concept for a closed-loop verification pipeline 
designed to automate the production of verified malware detection rules.

---

### Contributor Information

| Detail | Information |
| :--- | :--- |
| Name | Xunairah Balouch |
| Organization | Mandiant (capa) |
| Track | 350 Hours (Large Project) |
| Graduation | June 2026 |
| Linkedin   | https://www.linkedin.com/in/xunairah-balouch/ |
| Email | xunairahbalouch@gmail.com |

---

### Project Abstract

The current bottleneck in malware rule creation is not the generation of logic, but the verification of it. While Large Language Models (LLMs) are capable of generating YAML-based rules, they frequently produce noisy outputs that fail syntax validation or lack grounding in official documentation. This leads to logically flawed signatures that do not trigger on real malware samples.

This project proposes an Autonomous AI Agent utilizing a Closed-Loop Verification Pipeline. By integrating the `scripts.lint` utility, an automated MSDN grounding scraper, and empirical validation against the `capa-testfiles` repository, the agent provides maintainers with pre-validated Pull Requests that meet production standards.

---

### Technical Specification

#### 1. Actor-Critic Architecture
The system is built on a modular Python-based feedback loop. The generation engine (Actor) produces the initial YAML rule, while the verification logic (Critic) provides automated technical correction based on real-time engine feedback and schema requirements.

#### 2. Automated Grounding (Source Normalization)
To prevent logical hallucinations, the agent employs a source-agnostic preprocessing pipeline. Using `BeautifulSoup`, the agent extracts function syntax and library requirements (DLLs) from Microsoft Windows API documentation. This ensures that the generated rules are grounded in official technical specifications.

#### 3. Linter Feedback Loop
The agent parses `stderr` output from the `capa` linter to identify schema violations, such as incorrect namespaces or scopes. These errors are isolated and injected as a technical correction hint back into the generator, facilitating autonomous self-healing of the YAML syntax.

#### 4. Semantic Validation
Rules are empirically cross-checked by executing `capa -r` against the `capa-testfiles` repository. If a rule intended to detect a specific behavior (e.g., File Deletion) fails to trigger on a known sample, it is flagged as a semantic failure and sent back to the drafting phase.

---

### Proof of Concept (PoC)

The repository contains functional prototypes demonstrating the core verification components:

*   **grounding_scraper.py**: A Python CLI utility that extracts technical specifications from Win32 API documentation.
*   **linter_feedback.py**: A logic loop that simulates rule-matching failures and generates technical correction prompts.
*   **Research Documentation**: Analysis of the `capa-rules/nursery` folder and logic maps for rule promotion located in the `/research` directory.

---

### Implementation Timeline (12-Week Plan)

#### Phase 1: Foundation (Weeks 1-3)
*   Audit the `rules/nursery` directory to identify common rejection patterns and "example-less" rules.
*   Configure local development environments and master the `capa` rule schema through manual PR submissions.

#### Phase 2: Core Development (Weeks 4-6)
*   Develop the Python wrapper for the `scripts.lint` feedback loop.
*   Implement autonomous logic for the correction of YAML syntax errors.

#### Phase 3: Grounding and Validation (Weeks 7-9)
*   Integrate the `BeautifulSoup` scraper for MSDN-based grounding.
*   Develop logic to identify and prevent logically "dead" rules through semantic cross-checking.

#### Phase 4: Integration (Weeks 10-12)
*   Integrate the `capa -r` test suite into the final agent workflow.
*   Deliver a CLI tool capable of taking a malware description and outputting a verified .yml rule.

---

### Use Cases and Architectural Considerations

*   **Nursery Promotion:** Automatically identifies and promotes unverified rules from the nursery to the main ruleset by finding matching samples in the `capa-testfiles` repository.
*   **Audit Logging:** Every logical failure of the generator is logged, providing engineers with data on specific logical edge cases and schema inconsistencies.
*   **Scaling Production:** Reduces the manual workload of Mandiant analysts by providing verified first-draft rules for high-volume malware campaigns.
*   **Domain Expertise:** Leverages architectural knowledge of proxy infrastructure and network routing to generate high-fidelity rules for communication and socket namespaces.

---
© 2026 Xunairah Balouch | GSoC Work Submission
