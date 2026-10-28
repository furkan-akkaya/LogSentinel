"""Short investigation context; counts and parameters come from real alerts."""

from .detection import correlation_key, THRESHOLD_SETTINGS

GUIDANCE = {
    "ssh_brute_force": {
        "importance": "Repeated password or keyboard-interactive failures can indicate guessing against one account.",
        "benign": "A mistyped password or stale automation credential can produce the same pattern.",
        "checks": [
            "Confirm the source IP and account are expected.",
            "Review adjacent SSH outcomes and authentication configuration.",
        ],
        "limits": "Does not aggregate different users or IPs. Slow attempts outside the window and public-key failures are excluded.",
    },
    "ssh_success_after_failures": {
        "importance": "Authentication succeeded after repeated matching failures. This warrants review, not a compromise verdict.",
        "benign": "The legitimate user may have corrected a password or switched authentication methods.",
        "checks": [
            "Verify the login with the account owner and compare expected source addresses.",
            "Review session activity in separately collected host logs.",
        ],
        "limits": "Misses changed IPs/users and slow attempts. It cannot identify the operator or inspect post-login commands.",
    },
    "windows_brute_force": {
        "importance": "Repeated 4625 events show failed logons. They do not by themselves establish wrong passwords.",
        "benign": "Stale service credentials, account lockout, or logon restrictions may cause repeated failures.",
        "checks": [
            "Inspect Status and SubStatus in the raw record when present.",
            "Check account state, expected logon type, and service configuration.",
        ],
        "limits": "Requires matching domain, logon type, user, host, and IP. It does not aggregate distributed attempts or infer failure causes.",
    },
    "windows_success_after_failures": {
        "importance": "A 4624 logon follows matching 4625 failures. A created session is not proof of account takeover.",
        "benign": "A user may recover from a typo, or an administrator may fix an account or service configuration.",
        "checks": [
            "Inspect raw failure codes and confirm the expected user, domain, and logon type.",
            "Correlate session activity using additional host logs and confirm the login with its owner.",
        ],
        "limits": "Changing domain, logon type, host, account, or IP splits the sequence. Session behavior is outside this rule.",
    },
    "sudo_failures": {
        "importance": "Repeated local sudo PAM failures can indicate attempts to authenticate for privileged actions.",
        "benign": "The invoking user may have mistyped a password or misunderstood the sudo policy.",
        "checks": [
            "Confirm the invoking user's activity and inspect the terminal context.",
            "Review sudo policy and additional command/session logs if available.",
        ],
        "limits": "Requires invoking user and terminal. Summary records do not count; activity across terminals is not combined.",
    },
}


def explain_alert(alert, events, current_settings):
    key = correlation_key(events[-1])
    fields = (
        ("host", "user", "terminal")
        if alert["rule"] == "sudo_failures"
        else (
            ("host", "source_ip", "user", "domain", "logon_type")
            if events[-1]["source"] == "windows"
            else ("host", "source_ip", "user")
        )
    )
    setting_key = THRESHOLD_SETTINGS[alert["rule"]]
    # v1.0 alerts lack parameter snapshots. Config and alerts were updated in
    # one transaction, so that version's current config describes those alerts.
    parameters = alert.get("parameters") or {
        "threshold": current_settings[setting_key],
        "window_seconds": current_settings["window_seconds"],
    }
    return {
        **GUIDANCE[alert["rule"]],
        "failure_count": sum(e["event_type"].endswith("failure") for e in events),
        "success_count": sum(e["event_type"].endswith("success") for e in events),
        "evidence_count": len(events),
        "identity": dict(zip(fields, key or [])),
        "parameters": parameters,
        "threshold_setting": setting_key,
        "guide_url": f"/static/guides/docs/detections/{alert['rule']}.html",
    }
