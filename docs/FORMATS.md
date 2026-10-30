# Supported log formats

All uploads must be UTF-8 (a UTF-8 BOM is accepted). Maximum file size: 5 MiB. The importer reports accepted, duplicate, rejected, and ignored records. At most ten record-level errors are returned; raw rejected text is not echoed into errors. Valid records in a partially malformed file are accepted. Invalid whole XML documents are rejected atomically.

## Linux syslog

Recognized examples:

```text
Oct 26 08:00:00 edge-01 sshd[1234]: Failed password for invalid user admin from 203.0.113.42 port 50100 ssh2
2026-10-26T08:01:00+00:00 edge-01 sshd[1235]: Accepted publickey for deploy from 10.0.0.12 port 50101 ssh2
2026-10-26T08:02:00Z app-02 sudo[3456]: pam_unix(sudo:auth): authentication failure; logname=analyst uid=1001 euid=0 tty=/dev/pts/1 ruser=analyst rhost= user=root
```

The parser supports an optional syslog priority prefix `<N>`. It expects a host and `sshd` or `sudo` daemon prefix; PIDs are optional. Supported SSH methods are `password`, `publickey`, and `keyboard-interactive` (including `/pam`). Invalid SSH IPs reject the record. Other daemon records and unrecognized messages from the supported daemons are ignored rather than treated as authentication failures.

RFC3164 omits year and timezone. Supply the correct year and fixed offset in the import dialog. Offset defaults to `+00:00`. A year applies to every yearless record in that file. Split December/January logs and daylight-saving transitions into separate imports. ISO timestamps retain their embedded offset; naive ISO timestamps use the import offset. All stored times normalize to UTC.

The parser is intentionally format-specific. Journald JSON, RFC5424 structured data, custom collector prefixes, localized text and all possible Linux distributions are not supported.

## Windows Event XML

For 4624/4625, an explicitly supplied `Channel` must be `Security`. An explicitly supplied provider name must be `Microsoft-Windows-Security-Auditing`. The provider GUID must be `{54849625-5478-4994-A5BA-3E3B0328C30D}` when supplied. XML `Provider` attributes reach the same validation as JSON.

String comparisons accept surrounding whitespace and ignore case. GUIDs accept standard braced or unbraced UUID text. When both name and GUID exist, both must match. Every explicit alias is checked, including contradictory duplicate name aliases. Empty, null, malformed, or unrelated explicit fields are rejected and reported as source rejections.

For documented simplified exports, an **absent** Channel or Provider is accepted. Missing Channel normalizes to `Security` for compatibility. That default is not evidence that the source actually used the Security channel. The raw record is the place to inspect missing declarations.

Validation checks declarations, not provenance. It does not verify signatures or contact Windows. A forged file can contain the expected fields. Existing stored records are not deleted or reparsed by this update; this policy applies to new imports.

The exact values appear in the official [4624 XML example](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) and [4625 XML example](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625).

Use an `Event` element or `Events` wrapper with `Event` children. The standard Windows event namespace is supported. Required named fields:

```xml
<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <Event>
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/>
      <EventID>4625</EventID>
      <TimeCreated SystemTime="2026-10-26T08:00:00.0000000Z"/>
      <EventRecordID>10001</EventRecordID>
      <Computer>ws-finance</Computer>
      <Channel>Security</Channel>
    </System>
    <EventData>
      <Data Name="TargetUserName">j.morgan</Data>
      <Data Name="TargetDomainName">LAB</Data>
      <Data Name="IpAddress">203.0.113.77</Data>
      <Data Name="LogonType">10</Data>
    </EventData>
  </Event>
</Events>
```

To export on Windows using PowerShell (appropriate Security log read permission may be required):

```powershell
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625} -MaxEvents 5000
$xml = '<Events>' + (($events | ForEach-Object { $_.ToXml() }) -join "`n") + '</Events>'
[System.IO.File]::WriteAllText((Join-Path $PWD 'security.xml'), $xml, [System.Text.UTF8Encoding]::new($false))
```

This is an export command for your Windows machine, not host access requested by LogEssential. The command is documented, not executed or validated on Windows during this development session. Do not upload a binary `.evtx` file. XML raw records are preserved as a semantic XML serialization with possible namespace-prefix changes, rather than original byte slices.

Field meanings follow [Microsoft 4624 documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) and [Microsoft 4625 documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625). Missing IP information is normal in some authentication contexts. The app stores these events but does not invent network identity.

## Windows JSON / NDJSON

The equivalent object is:

```json
{
  "System": {
    "EventID": 4625,
    "Provider": {"Name": "Microsoft-Windows-Security-Auditing", "Guid": "{54849625-5478-4994-A5BA-3E3B0328C30D}"},
    "TimeCreated": {"SystemTime": "2026-10-26T08:00:00Z"},
    "Computer": "ws-finance",
    "EventRecordID": "10001",
    "Channel": "Security"
  },
  "EventData": {
    "TargetUserName": "j.morgan",
    "TargetDomainName": "LAB",
    "IpAddress": "203.0.113.77",
    "LogonType": "10"
  }
}
```

Accepted envelopes are one object, a JSON array, `{"Events": [...]}`, `{"Event": {...}}`, or one object per line. Flattened records can place `EventID`, `TimeCreated`, `Computer`, and named EventData fields at the top level. Aliases `Id`, `Timestamp`, `MachineName` and `RecordId` are accepted for their respective System fields. A named `EventData.Data` list with `Name`/`@Name` and `Value`/`#text` is also supported.

Provider may be a name string or an object with `Name`/`@Name` and `Guid`/`@Guid`. `ProviderName` and `ProviderGuid` are accepted aliases in the System object or flattened form. Unknown provider-object fields without a recognized name or GUID are rejected. Other event IDs remain ignored; this source contract concerns supported authentication events.

An arbitrary PowerShell `Get-WinEvent | ConvertTo-Json` export is **not** the supported contract: unnamed `Properties` arrays are ambiguous across event versions. Export XML or transform to the named structure above.

EventID, TimeCreated and Computer are required for a supported authentication event. Other event IDs are ignored. Missing user/IP/domain/logon type does not prevent storage, but prevents correlation. Timestamps may contain sub-microsecond precision; storage truncates to Python microseconds. Without record IDs, identical normalized events inside that precision may deduplicate.
