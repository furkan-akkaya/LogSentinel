"""Export a self-contained experiment with results measured by the real engine."""

import argparse
import json
from pathlib import Path

from logsentinel.detection import DEFAULTS
from logsentinel.lab import SCENARIOS, replay, scenario_events


def export(output):
    windows = [10, 60, 120, 225, 299, 300, 301, 600]
    scenarios = []
    for scenario in SCENARIOS:
        events = scenario_events(scenario["id"])
        results = {}
        for threshold in range(2, 9):
            for window in windows:
                # Vary failure-only thresholds together; success threshold stays at 3.
                settings = {
                    **DEFAULTS,
                    "ssh_threshold": threshold,
                    "windows_threshold": threshold,
                    "sudo_threshold": threshold,
                    "window_seconds": window,
                }
                measured = replay(events, settings)
                results[f"{threshold}:{window}"] = [
                    {
                        "count": step["alerts_total"],
                        "eligible": step["eligible"],
                        "reasons": [
                            a["reason"] for a in step["triggered"] + step["updated"]
                        ],
                    }
                    for step in measured["steps"]
                ]
        scenarios.append({**scenario, "events": events, "results": results})
    data = json.dumps(
        {"windows": windows, "scenarios": scenarios}, ensure_ascii=False
    ).replace("<", "\\u003c")
    template = (Path(__file__).parent / "learning_demo_template.html").read_text()
    output.write_text(template.replace("__MEASURED_RESULTS__", data))
    print(
        f"Exported {len(scenarios) * 7 * len(windows)} measured parameter combinations to {output}"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    export(parser.parse_args().output)
