"""Bounded, platform-independent authentication log parsers.

Timestamps are UTC in storage. Missing RFC3164 year and naive timestamps use
the explicit import context; they are never inferred from ingestion order.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import re
from uuid import UUID

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

MAX_RECORDS = 20_000
MAX_LINE = 65_536
SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing"
SECURITY_PROVIDER_GUID = UUID("54849625-5478-4994-a5ba-3e3b0328c30d")


class SourceMismatch(ValueError):
    """Explicit source fields contradict the Windows Security event contract."""


def validate_windows_source(system):
    # Absence retains the documented simplified JSON/XML compatibility.
    # Presence, including empty or malformed fields, must never imply trust.
    if "Channel" in system:
        channel = system["Channel"]
        if not isinstance(channel, str) or channel.strip().casefold() != "security":
            raise SourceMismatch("Windows source rejected: Channel must be Security")
    names, guids = [], []
    if "Provider" in system:
        provider = system["Provider"]
        if isinstance(provider, str):
            names.append(provider)
        elif isinstance(provider, dict):
            names.extend(provider[k] for k in ("Name", "@Name") if k in provider)
            guids.extend(provider[k] for k in ("Guid", "@Guid") if k in provider)
            if not names and not guids:
                raise SourceMismatch(
                    "Windows source rejected: Provider needs Name or Guid"
                )
        else:
            raise SourceMismatch("Windows source rejected: invalid Provider")
    if "ProviderName" in system:
        names.append(system["ProviderName"])
    if "ProviderGuid" in system:
        guids.append(system["ProviderGuid"])
    for name in names:
        if (
            not isinstance(name, str)
            or name.strip().casefold() != SECURITY_PROVIDER.casefold()
        ):
            raise SourceMismatch("Windows source rejected: unexpected provider name")
    for guid in guids:
        try:
            if (
                not isinstance(guid, str)
                or UUID(guid.strip()) != SECURITY_PROVIDER_GUID
            ):
                raise ValueError
        except (ValueError, AttributeError):
            raise SourceMismatch(
                "Windows source rejected: unexpected provider GUID"
            ) from None


def timestamp(value: str, offset: str = "+00:00") -> str:
    if not re.fullmatch(r"[+-](?:0\d|1[0-4]):[0-5]\d", offset) or (
        offset[1:3] == "14" and offset[-2:] != "00"
    ):
        raise ValueError("Timezone must be an offset between -14:00 and +14:00")
    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        minutes = int(offset[1:3]) * 60 + int(offset[4:])
        dt = dt.replace(
            tzinfo=timezone(
                timedelta(minutes=minutes if offset[0] == "+" else -minutes)
            )
        )
    return (
        dt.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def ip(value):
    if not value or value in ("-", "unknown"):
        return None
    try:
        address = ipaddress.ip_address(str(value))
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            return str(address.ipv4_mapped)
        return str(address)
    except ValueError:
        return None


def clean(value):
    return (
        str(value).strip()
        if value is not None and str(value).strip() not in ("", "-")
        else None
    )


@dataclass
class Event:
    timestamp: str
    source: str
    event_type: str
    host: str
    user: str | None
    source_ip: str | None
    raw: str
    metadata: dict = field(default_factory=dict)

    @property
    def id(self):
        # Raw formatting and upload filename are deliberately excluded.
        fields = [
            self.timestamp,
            self.source,
            self.event_type,
            self.host,
            self.user,
            self.source_ip,
            self.metadata,
        ]
        return hashlib.sha256(
            json.dumps(fields, sort_keys=True, ensure_ascii=True).encode()
        ).hexdigest()


@dataclass
class ParseResult:
    events: list = field(default_factory=list)
    rejected: int = 0
    ignored: int = 0
    errors: list = field(default_factory=list)

    def reject(self, number, message):
        self.rejected += 1
        if len(self.errors) < 10:
            self.errors.append({"record": number, "reason": message})


PREFIX = re.compile(
    r"^(?:<\d+>)?(?P<stamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT\S+)\s+(?P<host>\S+)\s+(?P<process>sshd|sudo)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)
SSH = re.compile(
    r"(?P<status>Failed|Accepted) (?P<method>password|publickey|keyboard-interactive(?:/pam)?) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)(?: port (?P<port>\d+))?"
)


def linux_event(line, year, offset):
    m = PREFIX.match(line)
    if not m:
        # Supported syslog but unrelated daemon, or a malformed record.
        if re.match(
            r"^(?:<\d+>)?(?:[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT\S+)\s+\S+\s+[^ :]+(?:\[\d+\])?:",
            line,
        ):
            return None
        raise ValueError("Unsupported Linux record or missing syslog prefix")
    stamp = m["stamp"]
    if not stamp[0].isdigit():
        stamp = datetime.strptime(f"{year} {stamp}", "%Y %b %d %H:%M:%S").isoformat()
    stamp = timestamp(stamp, offset)
    metadata = {"pid": m["pid"]}
    if m["process"] == "sshd":
        ssh = SSH.search(m["message"])
        if not ssh:
            return None
        metadata.update(method=ssh["method"], source_port=ssh["port"])
        source_ip = ip(ssh["ip"])
        if not source_ip:
            raise ValueError("Invalid SSH source IP")
        return Event(
            stamp,
            "linux",
            "ssh_success" if ssh["status"] == "Accepted" else "ssh_failure",
            m["host"],
            ssh["user"],
            source_ip,
            line,
            metadata,
        )
    message = m["message"]
    if "pam_unix(sudo:auth): authentication failure" in message:
        values = dict(re.findall(r"(\w+)=([^\s;]*)", message))
        user = clean(values.get("ruser")) or clean(values.get("logname"))
        metadata["target_user"] = clean(values.get("user"))
        metadata["tty"] = clean(values.get("tty"))
        return Event(
            stamp,
            "linux",
            "sudo_failure",
            m["host"],
            user,
            ip(values.get("rhost")),
            line,
            metadata,
        )
    bad = re.search(r"^\s*(\S+)\s*:\s*\d+ incorrect password attempts?", message)
    if bad:
        metadata["aggregate_summary"] = True
        return Event(
            stamp, "linux", "sudo_failure", m["host"], bad[1], None, line, metadata
        )
    return None


def local_tag(tag):
    return tag.rsplit("}", 1)[-1]


def xml_record(node):
    system, data = {}, {}
    for child in node:
        if local_tag(child.tag) == "System":
            for item in child:
                system[local_tag(item.tag)] = (
                    item.attrib
                    if local_tag(item.tag) in ("TimeCreated", "Provider")
                    else item.text
                )
        if local_tag(child.tag) == "EventData":
            data = {item.attrib.get("Name", ""): item.text for item in child}
    return {"System": system, "EventData": data}


def windows_event(record, raw, offset):
    if not isinstance(record, dict):
        raise ValueError("Windows record must be an object")
    record = record.get("Event", record)
    if not isinstance(record, dict):
        raise ValueError("Event must be an object")
    system = record.get("System", record)
    data = record.get("EventData", record)
    if not isinstance(system, dict) or not isinstance(data, dict):
        raise ValueError("System and EventData must be objects")
    if "Data" in data:
        items = data["Data"]
        if not isinstance(items, list):
            items = [items]
        data = {
            item.get("@Name", item.get("Name")): item.get("#text", item.get("Value"))
            for item in items
            if isinstance(item, dict)
        }
    event_id = system.get("EventID", system.get("Id"))
    if isinstance(event_id, dict):
        event_id = event_id.get("#text")
    if str(event_id) not in ("4624", "4625"):
        if event_id is None:
            raise ValueError("Missing EventID")
        return None
    validate_windows_source(system)
    stamp = system.get("TimeCreated", system.get("Timestamp"))
    if isinstance(stamp, dict):
        stamp = stamp.get("@SystemTime", stamp.get("SystemTime"))
    host = clean(system.get("Computer", system.get("MachineName")))
    if not stamp or not host:
        raise ValueError("Windows event needs TimeCreated and Computer")
    metadata = {
        "event_id": int(event_id),
        "record_id": clean(system.get("EventRecordID", system.get("RecordId"))),
        # Keep the existing event identity compatible with earlier imports.
        # Provider is checked against raw input, not added to identity metadata.
        "channel": "Security",
        "domain": clean(data.get("TargetDomainName")),
        "logon_type": clean(data.get("LogonType")),
    }
    return Event(
        timestamp(stamp, offset),
        "windows",
        "windows_success" if str(event_id) == "4624" else "windows_failure",
        host.lower(),
        clean(data.get("TargetUserName")),
        ip(data.get("IpAddress")),
        raw,
        metadata,
    )


def parse(text, format="auto", year=2026, offset="+00:00"):
    timestamp("2000-01-01T00:00:00", offset)  # Validate even for empty files.
    if not 1970 <= year <= 2100:
        raise ValueError("Year must be between 1970 and 2100")
    text = text.lstrip("\ufeff").strip()
    if not text:
        raise ValueError("File is empty")
    if format == "auto":
        format = (
            "xml"
            if text.startswith("<") and not re.match(r"<\d+>", text)
            else "json"
            if text[0] in "[{"
            else "linux"
        )
    result = ParseResult()
    records = []
    if format == "xml":
        try:
            root = ET.fromstring(
                text, forbid_dtd=True, forbid_entities=True, forbid_external=True
            )
        except (ET.ParseError, DefusedXmlException, RecursionError) as exc:
            raise ValueError("Invalid or unsafe XML document") from exc
        nodes = (
            [root]
            if local_tag(root.tag) == "Event"
            else [n for n in root if local_tag(n.tag) == "Event"]
        )
        if not nodes:
            raise ValueError("XML must contain Event or Events/Event")
        records = [(xml_record(n), ET.tostring(n, encoding="unicode")) for n in nodes]
    elif format == "json":
        try:
            doc = json.loads(text)
            if isinstance(doc, dict) and "Events" in doc:
                doc = doc["Events"]
            docs = doc if isinstance(doc, list) else [doc]
            records = [(doc, json.dumps(doc, ensure_ascii=True)) for doc in docs]
        except (json.JSONDecodeError, RecursionError):
            records = [(line, line) for line in text.splitlines() if line.strip()]
    elif format == "linux":
        records = [(line, line) for line in text.splitlines() if line.strip()]
    else:
        raise ValueError("Format must be auto, linux, json or xml")
    if len(records) > MAX_RECORDS:
        raise ValueError(f"Import exceeds {MAX_RECORDS} records")
    for number, (record, raw) in enumerate(records, 1):
        try:
            if len(raw) > MAX_LINE:
                raise ValueError("Record exceeds 64 KiB")
            if format == "linux":
                event = linux_event(record, year, offset)
            else:
                event = windows_event(
                    json.loads(record) if isinstance(record, str) else record,
                    raw,
                    offset,
                )
            if event:
                result.events.append(event)
            else:
                result.ignored += 1
        except SourceMismatch as exc:
            result.reject(number, str(exc))
        except (ValueError, TypeError, AttributeError, OverflowError, RecursionError):
            result.reject(number, "Malformed record, invalid fields or timestamp")
    return result
