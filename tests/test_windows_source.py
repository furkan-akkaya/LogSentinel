"""Explicit Windows source contradictions must never enter correlation."""

from copy import deepcopy
import json
import xml.etree.ElementTree as ET

import pytest
from logsentinel.parsers import parse, SECURITY_PROVIDER

GUID = "{54849625-5478-4994-A5BA-3E3B0328C30D}"


def record():
    return {
        "System": {
            "EventID": 4625,
            "Computer": "ws01",
            "TimeCreated": {"SystemTime": "2026-10-26T12:00:00Z"},
            "Channel": "Security",
            "EventRecordID": "1",
        },
        "EventData": {
            "TargetUserName": "alice",
            "TargetDomainName": "LAB",
            "LogonType": "10",
            "IpAddress": "192.0.2.1",
        },
    }


def xml(value):
    root = ET.Element(
        "Event", xmlns="http://schemas.microsoft.com/win/2004/08/events/event"
    )
    system = ET.SubElement(root, "System")
    for name, data in value["System"].items():
        item = ET.SubElement(system, name)
        if isinstance(data, dict):
            item.attrib.update(data)
        else:
            item.text = str(data)
    data = ET.SubElement(root, "EventData")
    for name, value in value["EventData"].items():
        ET.SubElement(data, "Data", Name=name).text = value
    return ET.tostring(root, encoding="unicode")


@pytest.mark.parametrize("format", ["json", "xml"])
@pytest.mark.parametrize(
    "change",
    [
        {"Channel": "Application"},
        {"Provider": {"Name": "Other-Provider"}},
        {"Provider": {"Guid": "{00000000-0000-0000-0000-000000000000}"}},
        {"Provider": {"Name": SECURITY_PROVIDER, "Guid": "not-a-guid"}},
        {"Provider": {"Name": "Other", "Guid": GUID}},
        {"Provider": {}},
        {"Channel": ""},
    ],
)
def test_conflicting_source_rejected(format, change):
    value = record()
    value["System"].update(change)
    result = parse(xml(value) if format == "xml" else json.dumps(value), format)
    assert result.events == [] and result.rejected == 1
    assert result.errors[0]["reason"].startswith("Windows source rejected:")


@pytest.mark.parametrize(
    "provider",
    [
        SECURITY_PROVIDER,
        {"Name": SECURITY_PROVIDER, "Guid": GUID},
        {"@Name": SECURITY_PROVIDER, "@Guid": GUID.lower()},
        {"Guid": GUID},
        {"Name": SECURITY_PROVIDER.lower()},
    ],
)
def test_json_valid_provider_forms_preserve_identity(provider):
    baseline = record()
    candidate = deepcopy(baseline)
    candidate["System"].update(Provider=provider, Channel="security")
    assert (
        parse(json.dumps(candidate)).events[0].id
        == parse(json.dumps(baseline)).events[0].id
    )


@pytest.mark.parametrize("channel", [True, None, {}, []])
def test_explicit_invalid_channel_is_not_absence(channel):
    value = record()
    value["System"]["Channel"] = channel
    assert parse(json.dumps(value)).rejected == 1


@pytest.mark.parametrize(
    "provider",
    [None, [], "", {"Name": None}, {"Name": SECURITY_PROVIDER, "@Name": "Other"}],
)
def test_explicit_invalid_provider_is_not_absence(provider):
    value = record()
    value["System"]["Provider"] = provider
    assert parse(json.dumps(value)).rejected == 1


@pytest.mark.parametrize("missing", ["Channel", "Provider", "both"])
@pytest.mark.parametrize("format", ["json", "xml"])
def test_absent_source_fields_keep_compatibility(missing, format):
    value = record()
    value["System"]["Provider"] = {"Name": SECURITY_PROVIDER, "Guid": GUID}
    if missing in ("Channel", "both"):
        value["System"].pop("Channel")
    if missing in ("Provider", "both"):
        value["System"].pop("Provider")
    result = parse(xml(value) if format == "xml" else json.dumps(value), format)
    assert len(result.events) == 1 and result.rejected == 0


def test_xml_provider_attributes_reach_validation_and_json_equivalence():
    value = record()
    value["System"]["Provider"] = {"Name": SECURITY_PROVIDER, "Guid": GUID}
    assert (
        parse(xml(value), "xml").events[0].id == parse(json.dumps(value)).events[0].id
    )


@pytest.mark.parametrize(
    "field,value", [("ProviderName", "Other"), ("ProviderGuid", "bad")]
)
def test_flat_provider_alias_checked(field, value):
    obj = record()
    obj["System"][field] = value
    assert parse(json.dumps(obj)).rejected == 1


def test_wrong_source_cannot_generate_alert_and_partial_import_survives(client):
    bad = []
    for i in range(5):
        obj = record()
        obj["System"].update(
            Channel="Application", Provider={"Name": "Other"}, EventRecordID=str(i)
        )
        bad.append(obj)
    result = client.post(
        "/api/import", files={"file": ("bad.json", json.dumps(bad))}
    ).json()
    assert (
        result["rejected"] == 5
        and result["inserted"] == 0
        and result["alerts_total"] == 0
    )
    good = record()
    good["System"]["Provider"] = {"Name": SECURITY_PROVIDER, "Guid": GUID}
    result = client.post(
        "/api/import", files={"file": ("mixed.json", json.dumps([bad[0], good]))}
    ).json()
    assert result["inserted"] == 1 and result["rejected"] == 1
