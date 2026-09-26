#!/usr/bin/env python3
"""Render the correlation demo to a standalone SVG for the README / socials.

Regenerate with:  python examples/generate_demo_svg.py
Writes docs/correlation-demo.svg — a static "screenshot" of the demo output,
no terminal recorder required.
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from examples.correlation_demo import TARGET, _scripted_results
from modules.correlation import CorrelationEngine, build_graph, load_rules
from modules.correlation.rules import _SEVERITY_RANK

OUT = Path(__file__).resolve().parents[1] / "docs" / "correlation-demo.svg"


def main() -> None:
    console = Console(record=True, width=100)
    results = _scripted_results()
    findings = [f for r in results for f in r.findings]
    graph = build_graph(TARGET, results)
    engine = CorrelationEngine(load_rules())
    correlations = engine.evaluate(findings, graph)

    console.print(
        f"\n[bold]$ secsuite correlate {TARGET}[/bold]\n"
        f"[dim]{len(findings)} findings · {len(engine.rules)} rules → "
        f"{len(correlations)} correlations[/dim]\n"
    )
    sev_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "blue", "info": "green"}
    for c in sorted(correlations, key=lambda x: _SEVERITY_RANK[x.severity], reverse=True):
        color = sev_color.get(c.severity.value, "white")
        body = c.description.strip()
        if c.attack_path:
            body += f"\n\n[bold]Path:[/bold] {c.attack_path}"
        body += f"\n[dim]Evidence: {', '.join(f.title for f in c.evidence)}[/dim]"
        if c.mitre:
            body += f"\n[dim]MITRE: {', '.join(c.mitre)}[/dim]"
        console.print(Panel(body, title=f"[{color}]{c.severity.value.upper()}[/{color}] {c.name}"))

    OUT.parent.mkdir(parents=True, exist_ok=True)
    console.save_svg(str(OUT), title="SecSuite — correlation")
    print(f"wrote {OUT} ({OUT.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
