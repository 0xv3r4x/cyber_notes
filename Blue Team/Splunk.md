# Splunk

Often people think of Splunk as a **SIEM** (**S**ecurity **I**nformation and **E**vent **M**anagement) - a centralised solution to collate, aggregate, normalise, and subsequently analyse log data from multiple locations within an environment.

A **SIEM** is capable of:
- Threat detection
- Investigation
- Time to respond

## Searching and Reporting

This is the default app installed on Splunk.  The configuration files are stored in:

- `C:\Program Files\Splunk\etc\apps\user-prefs\default\user-prefs.conf` (Windows)
- `/opt/splunk/etc/apps/user-pref/default/user-prefs.conf` (Linux)

#### Sources

## Sigma

Each SIEM has its own structure/format for creating queries, and is therefore challenging to share SIEM queries with other security teams who don't use the same SIEM solution.  [Sigma](https://github.com/Neo23x0/sigma) can be used to format queries/rules and shared with teams who don't use Splunk and can be combined with Indicators of Compromise (IOCs) and Yara rules for Threat Intelligence.




Sysmon:

```
soruce="WinEventLog:Microsoft-Windows-Sysmon/Operational"
```

```
index=* sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" *exe
| table CurrentDirectory CommandLine Image Hashes ParentCommandLine ParentImage
```

```
index=* sourcetype="Microsoft-Windows-Sysmon/Operational" EventCode11
| table Image SourceName TargetFilename
```

```
index=* sourcetype="WinEventLog:Security" EventCode=4720
| table AccountName SourceName
```

```
index=* sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" securityninja
| table CommandLine Image ParentCommandLine
```

```
index=* sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=8
| table SourceImage TargetImage
```

```
index=* sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" *aspx
| table Image CommandLine ParentImage SourceName
```

## External Documentation

#### [Sysmon events](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)

- Event ID 1: Process Creation
- Event ID 3: Network Connection
- Event ID 7: Image Loaded
- Event ID 8: CreateRemoteThread
	- indicates process migration
- Event ID 11: File Created
- Event ID 12/13/14: Registry Events
- Event ID 15: FileCreateStreamHash
- Event ID 22: DNS Event