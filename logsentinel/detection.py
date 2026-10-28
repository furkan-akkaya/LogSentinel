"""Deterministic event-time rules. No ingestion-time correlation."""

from collections import defaultdict, deque
from datetime import datetime
import hashlib
import json

DEFAULTS = {
    "ssh_threshold": 5,
    "windows_threshold": 5,
    "sudo_threshold": 3,
    "success_threshold": 3,
    "window_seconds": 300,
}
RULES = {
    "ssh_brute_force": ("SSH password guessing", "high", ["T1110.001"]),
    "ssh_success_after_failures": (
        "SSH success after failures",
        "critical",
        ["T1110.001", "T1078"],
    ),
    "windows_brute_force": ("Windows repeated logon failures", "high", ["T1110.001"]),
    "windows_success_after_failures": (
        "Windows success after failures",
        "critical",
        ["T1110.001", "T1078"],
    ),
    "sudo_failures": ("Repeated sudo authentication failures", "medium", ["T1110.001"]),
}
THRESHOLD_SETTINGS = {
    "ssh_brute_force": "ssh_threshold",
    "windows_brute_force": "windows_threshold",
    "sudo_failures": "sudo_threshold",
    "ssh_success_after_failures": "success_threshold",
    "windows_success_after_failures": "success_threshold",
}


def seconds(stamp):
    return datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()


def correlation_key(event):
    """Unknown identities never join; Windows domain and logon type are required."""
    if not event["host"] or not event["user"]:
        return None
    meta = event["metadata"]
    if event["event_type"] == "ssh_failure" and meta.get("method") == "publickey":
        # Trying several SSH keys is not evidence of password guessing.
        return None
    if event["event_type"] == "sudo_failure":
        # PAM detail and sudo summaries can describe the same attempts.
        # Ignore summaries rather than double counting.
        if meta.get("aggregate_summary") or not meta.get("tty"):
            return None
        return (event["host"], event["user"], meta.get("tty"))
    if not event["source_ip"]:
        return None
    if event["source"] == "windows":
        if not meta.get("domain") or not meta.get("logon_type"):
            return None
        return (
            event["host"].casefold(),
            event["source_ip"],
            event["user"].casefold(),
            meta["domain"].casefold(),
            meta["logon_type"],
        )
    return (event["host"], event["source_ip"], event["user"])


def detect(events, settings):
    alerts = []
    window = settings["window_seconds"]

    def alert(rule, evidence, key, anchor):
        title, severity, mitre = RULES[rule]
        last = evidence[-1]
        # Stable ID for an episode while its evidence grows.
        identifier = hashlib.sha256(
            json.dumps([rule, key, anchor]).encode()
        ).hexdigest()
        count = sum(e["event_type"].endswith("failure") for e in evidence)
        reason = f"{count} matching authentication failure records within {window}s"
        if "success_after" in rule:
            reason += ", followed by a strictly later successful logon. Review for possible account compromise."
        else:
            reason += ". The configured threshold was reached; review the evidence."
        alerts.append(
            {
                "id": identifier,
                "rule": rule,
                "title": title,
                "severity": severity,
                "mitre": mitre,
                "first_seen": evidence[0]["timestamp"],
                "last_seen": last["timestamp"],
                "host": last["host"],
                "source_ip": last["source_ip"],
                "user": last["user"],
                "reason": reason,
                "parameters": {
                    "threshold": settings[THRESHOLD_SETTINGS[rule]],
                    "window_seconds": window,
                },
                "evidence": [e["id"] for e in evidence],
            }
        )

    for family, failure, success, threshold in [
        ("ssh", "ssh_failure", "ssh_success", settings["ssh_threshold"]),
        (
            "windows",
            "windows_failure",
            "windows_success",
            settings["windows_threshold"],
        ),
        ("sudo", "sudo_failure", None, settings["sudo_threshold"]),
    ]:
        groups = defaultdict(list)
        for event in events:
            if event["event_type"] in (failure, success):
                key = correlation_key(event)
                if key:
                    groups[key].append(event)
        for key, group in groups.items():
            group.sort(key=lambda e: (e["timestamp"], e["id"]))
            recent = deque()
            episode = []
            episode_alert = None
            for event in group:
                t = seconds(event["timestamp"])
                while recent and seconds(recent[0]["timestamp"]) < t - window:
                    recent.popleft()
                if event["event_type"] == failure:
                    if not episode or t - seconds(episode[0]["timestamp"]) > window:
                        episode, episode_alert = [], None
                    episode.append(event)
                    recent.append(event)
                    if episode_alert is None and len(recent) >= threshold:
                        # Evidence spans a bounded window, even across old episode boundaries.
                        episode = list(recent)
                        rule = (
                            "sudo_failures"
                            if family == "sudo"
                            else f"{family}_brute_force"
                        )
                        alert(rule, episode, key, episode[0]["id"])
                        episode_alert = alerts[-1]
                    elif episode_alert is not None:
                        episode_alert["last_seen"] = event["timestamp"]
                        episode_alert["evidence"] = [e["id"] for e in episode]
                        episode_alert["reason"] = (
                            f"{len(episode)} matching authentication failure records within {window}s. The configured threshold was reached; review the evidence."
                        )
                else:
                    # Equal-time records do not establish temporal precedence.
                    preceding = [
                        e for e in recent if e["timestamp"] < event["timestamp"]
                    ]
                    if len(preceding) >= settings["success_threshold"]:
                        alert(
                            f"{family}_success_after_failures",
                            preceding + [event],
                            key,
                            event["id"],
                        )
                    # Keep equal-time failures for a subsequent, strictly later
                    # success: their ordering relative to this success is unknown.
                    recent = deque(
                        e for e in recent if e["timestamp"] == event["timestamp"]
                    )
                    episode, episode_alert = [], None
    return sorted(alerts, key=lambda a: (a["last_seen"], a["id"]))
