"""
grounding_scraper.py
====================
Automated MSDN Grounding Scraper for capa Rule Generation Agent.

Purpose
-------
Extracts structured, LLM-ready context from Microsoft documentation pages
(learn.microsoft.com) for a given Windows API function. Strips HTML noise,
isolates function syntax, parameter definitions, return values, and DLL/lib
requirements — the exact signal needed to ground a capa rule in authoritative
documentation.

This module is Phase 3 of the Closed-Loop Rule Generation Pipeline.

Usage
-----
    python grounding_scraper.py --url "https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw"
    python grounding_scraper.py --url <MSDN_URL> --output grounding_context.md

Author: Xunairah Balouch (GSoC 2026 Candidate — Mandiant/capa)
"""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup, Tag

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

REQUEST_TIMEOUT = 15  # seconds
REQUEST_HEADERS = {
    # Mimic a real browser to avoid bot-detection on learn.microsoft.com
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}

# CSS selectors / landmark IDs used by learn.microsoft.com as of 2025-2026.
# These are the high-signal anchors; we fall back gracefully if absent.
SYNTAX_SECTION_ID = "syntax"
PARAMETERS_SECTION_ID = "parameters"
RETURN_VALUE_SECTION_ID = "return-value"
REQUIREMENTS_SECTION_ID = "requirements"


# ──────────────────────────────────────────────────────────────────────────────
# Data Model
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class ApiGroundingContext:
    """
    Structured extraction result for a single Windows API function.

    All fields are optional; callers should check for None before use.
    This object is serialisable to JSON for pipeline handoff.
    """

    url: str
    function_name: str = ""
    syntax: str = ""
    parameters: list[dict[str, str]] = field(default_factory=list)
    return_value: str = ""
    dll_library: str = ""          # e.g. "Kernel32.dll"
    minimum_supported_client: str = ""
    header: str = ""               # e.g. "winbase.h"
    raw_requirements_block: str = ""

    def to_llm_prompt_block(self) -> str:
        """
        Serialize this context into a clean Markdown block suitable for
        injection into an LLM system prompt.

        The format is intentionally terse — every token must earn its place.
        """
        lines: list[str] = [
            f"## Windows API Grounding Context: `{self.function_name}`",
            f"**Source:** {self.url}",
            "",
        ]

        if self.syntax:
            lines += ["### Syntax", "```c", self.syntax, "```", ""]

        if self.parameters:
            lines.append("### Parameters")
            for param in self.parameters:
                lines.append(
                    f"- **`{param.get('name', '?')}`** — {param.get('description', '')}"
                )
            lines.append("")

        if self.return_value:
            lines += ["### Return Value", self.return_value, ""]

        lines.append("### Requirements (for capa rule metadata)")
        lines.append(f"| Field | Value |")
        lines.append(f"|---|---|")
        lines.append(f"| DLL / Library | `{self.dll_library or 'unknown'}` |")
        lines.append(f"| Header | `{self.header or 'unknown'}` |")
        lines.append(
            f"| Min. Client OS | {self.minimum_supported_client or 'unknown'} |"
        )

        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "function_name": self.function_name,
            "syntax": self.syntax,
            "parameters": self.parameters,
            "return_value": self.return_value,
            "dll_library": self.dll_library,
            "minimum_supported_client": self.minimum_supported_client,
            "header": self.header,
            "raw_requirements_block": self.raw_requirements_block,
        }


# ──────────────────────────────────────────────────────────────────────────────
# Core Scraper
# ──────────────────────────────────────────────────────────────────────────────


class MsdnGroundingScraper:
    """
    Source-agnostic scraper targeting Microsoft learn.microsoft.com pages.

    Design philosophy
    -----------------
    Use *landmark anchors* (heading IDs baked into MSDN's HTML) rather than
    brittle XPaths.  If a landmark is absent, degrade gracefully — partial
    context is still more valuable than a crash.
    """

    def __init__(self, timeout: int = REQUEST_TIMEOUT) -> None:
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(REQUEST_HEADERS)

    # ── Public API ────────────────────────────────────────────────────────────

    def scrape(self, url: str) -> ApiGroundingContext:
        """
        Fetch *url*, parse the page, and return a populated
        :class:`ApiGroundingContext`.

        Raises
        ------
        ValueError
            If *url* does not appear to be an MSDN/learn.microsoft.com page.
        requests.HTTPError
            On non-2xx HTTP responses.
        """
        self._validate_url(url)
        soup = self._fetch(url)

        ctx = ApiGroundingContext(url=url)
        ctx.function_name = self._extract_function_name(soup)
        ctx.syntax = self._extract_section_code(soup, SYNTAX_SECTION_ID)
        ctx.parameters = self._extract_parameters(soup)
        ctx.return_value = self._extract_section_text(soup, RETURN_VALUE_SECTION_ID)
        self._extract_requirements(soup, ctx)

        return ctx

    # ── Private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _validate_url(url: str) -> None:
        parsed = urlparse(url)
        if "microsoft.com" not in parsed.netloc:
            raise ValueError(
                f"URL does not appear to be an MSDN/learn.microsoft.com page: {url!r}"
            )

    def _fetch(self, url: str) -> BeautifulSoup:
        response = self.session.get(url, timeout=self.timeout)
        response.raise_for_status()
        return BeautifulSoup(response.text, "html.parser")

    @staticmethod
    def _extract_function_name(soup: BeautifulSoup) -> str:
        """Pull the canonical function name from the <h1> or <title>."""
        h1 = soup.find("h1")
        if h1:
            # MSDN titles look like "MoveFileExW function (winbase.h)"
            return h1.get_text(strip=True).split(" function")[0].strip()
        title = soup.find("title")
        if title:
            return title.get_text(strip=True).split("|")[0].strip()
        return "UnknownFunction"

    @staticmethod
    def _find_section_heading(soup: BeautifulSoup, section_id: str) -> Optional[Tag]:
        """
        Locate a heading element whose *id* matches *section_id*.
        MSDN anchors headings directly (e.g. <h2 id="syntax">Syntax</h2>).
        """
        return soup.find(id=section_id)

    def _extract_section_code(self, soup: BeautifulSoup, section_id: str) -> str:
        """Return the text of the first <code> block that follows *section_id*."""
        heading = self._find_section_heading(soup, section_id)
        if not heading:
            return ""
        # Walk siblings until we hit the next heading or end of parent
        for sibling in heading.find_next_siblings():
            if sibling.name and sibling.name.startswith("h"):
                break
            code = sibling.find("code")
            if code:
                return code.get_text(separator="\n").strip()
            pre = sibling.find("pre")
            if pre:
                return pre.get_text(separator="\n").strip()
        return ""

    def _extract_section_text(self, soup: BeautifulSoup, section_id: str) -> str:
        """Return concatenated paragraph text that follows *section_id*."""
        heading = self._find_section_heading(soup, section_id)
        if not heading:
            return ""
        paragraphs: list[str] = []
        for sibling in heading.find_next_siblings():
            if sibling.name and sibling.name.startswith("h"):
                break
            if sibling.name == "p":
                paragraphs.append(sibling.get_text(separator=" ").strip())
        return " ".join(paragraphs)

    def _extract_parameters(self, soup: BeautifulSoup) -> list[dict[str, str]]:
        """
        Parse the Parameters section into a list of {name, description} dicts.

        MSDN renders parameters as definition lists (<dl>) where <dt> holds the
        param name and <dd> holds the description.
        """
        heading = self._find_section_heading(soup, PARAMETERS_SECTION_ID)
        if not heading:
            return []

        params: list[dict[str, str]] = []
        for sibling in heading.find_next_siblings():
            if sibling.name and sibling.name.startswith("h"):
                break
            if sibling.name == "dl":
                dt_tags = sibling.find_all("dt")
                dd_tags = sibling.find_all("dd")
                for dt, dd in zip(dt_tags, dd_tags):
                    params.append(
                        {
                            "name": dt.get_text(strip=True),
                            "description": dd.get_text(separator=" ").strip(),
                        }
                    )
        return params

    def _extract_requirements(
        self, soup: BeautifulSoup, ctx: ApiGroundingContext
    ) -> None:
        """
        Parse the Requirements table at the bottom of every MSDN function page.

        Fields extracted: DLL, Header, Minimum supported client.
        """
        heading = self._find_section_heading(soup, REQUIREMENTS_SECTION_ID)
        if not heading:
            return

        # Collect raw text for debugging / passthrough
        raw_parts: list[str] = []
        for sibling in heading.find_next_siblings():
            if sibling.name and sibling.name.startswith("h"):
                break
            raw_parts.append(sibling.get_text(separator=" ").strip())
        ctx.raw_requirements_block = " | ".join(filter(None, raw_parts))

        # MSDN requirements are usually a <table> with <td> label / value pairs
        req_table = heading.find_next("table")
        if not req_table:
            # Some pages use <dl> instead
            req_dl = heading.find_next("dl")
            if req_dl:
                self._parse_requirements_dl(req_dl, ctx)
            return

        for row in req_table.find_all("tr"):
            cells = row.find_all(["th", "td"])
            if len(cells) < 2:
                continue
            label = cells[0].get_text(strip=True).lower()
            value = cells[1].get_text(separator=" ").strip()

            if "dll" in label or "library" in label:
                ctx.dll_library = value
            elif "header" in label:
                ctx.header = value
            elif "minimum supported client" in label:
                ctx.minimum_supported_client = value

    @staticmethod
    def _parse_requirements_dl(dl: Tag, ctx: ApiGroundingContext) -> None:
        dt_tags = dl.find_all("dt")
        dd_tags = dl.find_all("dd")
        for dt, dd in zip(dt_tags, dd_tags):
            label = dt.get_text(strip=True).lower()
            value = dd.get_text(separator=" ").strip()
            if "dll" in label or "library" in label:
                ctx.dll_library = value
            elif "header" in label:
                ctx.header = value
            elif "minimum supported client" in label:
                ctx.minimum_supported_client = value


# ──────────────────────────────────────────────────────────────────────────────
# CLI Entry Point
# ──────────────────────────────────────────────────────────────────────────────


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "MSDN Grounding Scraper — extracts Windows API metadata for "
            "capa rule generation."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              %(prog)s --url "https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw"
              %(prog)s --url <URL> --output grounding.md
              %(prog)s --url <URL> --format json
            """
        ),
    )
    parser.add_argument(
        "--url",
        required=True,
        metavar="MSDN_URL",
        help="Full URL to the Windows API function page on learn.microsoft.com.",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Write output to FILE instead of stdout.",
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format (default: markdown).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)

    scraper = MsdnGroundingScraper()
    print(f"[*] Fetching: {args.url}", file=sys.stderr)

    try:
        ctx = scraper.scrape(args.url)
    except ValueError as exc:
        print(f"[!] Validation error: {exc}", file=sys.stderr)
        return 2
    except requests.HTTPError as exc:
        print(f"[!] HTTP error: {exc}", file=sys.stderr)
        return 3
    except requests.ConnectionError:
        print("[!] Network unreachable. Check connectivity.", file=sys.stderr)
        return 4

    print(f"[+] Extracted context for: {ctx.function_name!r}", file=sys.stderr)
    print(f"    DLL        : {ctx.dll_library or 'not found'}", file=sys.stderr)
    print(f"    Header     : {ctx.header or 'not found'}", file=sys.stderr)
    print(f"    Min Client : {ctx.minimum_supported_client or 'not found'}", file=sys.stderr)
    print(f"    Parameters : {len(ctx.parameters)} extracted", file=sys.stderr)

    if args.format == "json":
        output = json.dumps(ctx.to_dict(), indent=2)
    else:
        output = ctx.to_llm_prompt_block()

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)
        print(f"[+] Output written to: {args.output}", file=sys.stderr)
    else:
        print(output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
