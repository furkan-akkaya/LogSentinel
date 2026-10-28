from tools.verify_examples import collect, verify


def test_documented_examples_match_engine_and_evidence():
    verify()


def test_demo_rules_have_expected_independent_counts():
    result = collect()
    assert result["first_import"] == {
        "inserted": 85,
        "duplicates": 0,
        "alerts_total": 5,
    }
    assert result["second_import"] == {
        "inserted": 0,
        "duplicates": 85,
        "alerts_total": 5,
    }
    expected = {
        "ssh_brute_force": (7, 0),
        "ssh_success_after_failures": (4, 1),
        "windows_brute_force": (6, 0),
        "windows_success_after_failures": (4, 1),
        "sudo_failures": (4, 0),
    }
    assert set(result["scenarios"]) == set(expected)
    for rule, (failures, successes) in expected.items():
        summary = result["scenarios"][rule]["summary"]
        assert (summary["failure_count"], summary["success_count"]) == (
            failures,
            successes,
        )
