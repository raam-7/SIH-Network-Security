# Security Taxonomy v1

| Concept | Domain | Property | Example Value |
|---|---|---|---|
| SSH_VERSION | REMOTE_MANAGEMENT | protocol_version | 2 |
| TELNET_ACCESS | REMOTE_MANAGEMENT | enabled | false |
| AAA | AUTHENTICATION | authentication_mode | aaa |
| NTP_AUTHENTICATION | TIME_SYNC | enabled | true |
| REMOTE_SYSLOG | LOGGING | enabled | true |

## Purpose

These canonical concepts allow different vendor configurations
to be converted into a common security representation.
| SSH_TIMEOUT | REMOTE_MANAGEMENT | timeout_seconds | 60 |
| SSH_AUTH_RETRIES | REMOTE_MANAGEMENT | retry_limit | 5 |
| SSH_MAXSTARTUPS | REMOTE_MANAGEMENT | max_startups | 3 |
