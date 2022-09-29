# Security Information and Event Management (SIEM)

A **SIEM** is a security solution that provides real-time logging of events in an environment in order to detect security threats.

SIEM products have a number of features, such as data filtering and alert creation.  For example, if someone on a Windows OS attempts to enter 20 incorrect passwords in 10 seconds, it is likely that an automated attack is taking place.  The SIEM rules/filters will take this data and determine if it exceeds a threshold value before triggering an alert.

SIEM solutions:
- IBM QRadar
- ArcSight ESM
- FortiSIEM
- Splunk

When an alert is triggered, a SOC analyst must determine if it is a real threat or a false alarm.  If it is a threat, then it must be escalated, but if not, the analyst should still give feedback to the team.