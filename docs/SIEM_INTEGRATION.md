# SIEM Integration Guide

## Overview

This guide provides instructions for integrating PCAP Analyzer audit logs with popular SIEM (Security Information and Event Management) systems.

The audit logs are designed for machine parsing with:
- **Format**: Newline-delimited JSON (NDJSON)
- **Structure**: Consistent schema across all events
- **Location**: `logs/audit/security_audit.log`
- **Permissions**: 0600 (readable only by log owner)
- **Retention**: 90+ days (configurable)

## Supported SIEM Platforms

- Splunk
- Elastic Stack (ELK)
- Graylog
- IBM QRadar
- ArcSight
- Azure Sentinel

---

## Log Format Specification

### JSON Schema

Each audit record is a single-line JSON object with the following fields:

```json
{
  "timestamp": "2025-12-20T15:30:45.123456+00:00",
  "event_type": "file.validation.success",
  "severity": "INFO",
  "outcome": "SUCCESS",
  "component": "file_validator",
  "user": null,
  "process_id": 12345,
  "source_ip": null,
  "session_id": "abc123def456",
  "file_path": "capture.pcap",
  "hostname": "analyst-workstation",
  "details": {
    "file_size_bytes": 1024000,
    "pcap_type": "pcap"
  },
  "record_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

### Field Descriptions

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `timestamp` | string (ISO 8601) | Event timestamp with timezone | `2025-12-20T15:30:45+00:00` |
| `event_type` | string | Event classification | `security.decompression_bomb.detected` |
| `severity` | enum | Severity level | `CRITICAL`, `WARNING`, `INFO` |
| `outcome` | enum | Event outcome | `SUCCESS`, `FAILURE`, `BLOCKED` |
| `component` | string | Component generating event | `file_validator`, `ssh_auth` |
| `user` | string | User identifier (if applicable) | `admin`, `analyst` |
| `process_id` | integer | OS process ID | `12345` |
| `source_ip` | string | Source IP address (if applicable) | `203.0.113.45` |
| `session_id` | string (UUID) | Session tracking ID | `abc123def456` |
| `file_path` | string | File path (PII-redacted) | `capture.pcap` |
| `hostname` | string | Hostname where event occurred | `analyst-workstation` |
| `details` | object | Event-specific additional data | `{"expansion_ratio": 10500}` |
| `record_id` | string (UUID) | Unique record identifier | `550e8400-e29b-...` |

---

## Splunk Integration

### 1. Create Index

```spl
# Create dedicated index for PCAP analyzer audit logs
/opt/splunk/bin/splunk add index pcap_analyzer_audit \
    -maxTotalDataSizeMB 10000 \
    -frozenTimePeriodInSecs 7776000
```

### 2. Configure Input (inputs.conf)

```ini
[monitor:///opt/pcap_analyzer/logs/audit/security_audit.log]
disabled = false
index = pcap_analyzer_audit
sourcetype = pcap:audit:json
host_segment = 3
```

### 3. Configure Source Type (props.conf)

```ini
[pcap:audit:json]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
NO_BINARY_CHECK = true
KV_MODE = json
TIME_PREFIX = "timestamp"\s*:\s*"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6N%z
MAX_TIMESTAMP_LOOKAHEAD = 30
TRUNCATE = 0
```

### 4. Example Searches

#### Security Violations (Last 24h)
```spl
index=pcap_analyzer_audit event_type=security.* earliest=-24h
| stats count by event_type, severity, outcome
| sort -count
```

#### Authentication Failures
```spl
index=pcap_analyzer_audit event_type=auth.failure
| stats count by user, details.host, details.failure_reason
| where count > 3
| sort -count
```

#### Decompression Bombs
```spl
index=pcap_analyzer_audit event_type="security.decompression_bomb.detected"
| table timestamp, file_path, details.expansion_ratio, details.threshold
| sort -timestamp
```

#### Critical Events Dashboard
```spl
index=pcap_analyzer_audit severity IN (CRITICAL, ALERT, EMERGENCY)
| timechart span=1h count by event_type
```

### 5. Alert Rules

**Decompression Bomb Detected**
```spl
index=pcap_analyzer_audit event_type="security.decompression_bomb.detected"
```
- **Trigger**: Every time
- **Action**: Send email to security team
- **Severity**: Critical

**Multiple Authentication Failures**
```spl
index=pcap_analyzer_audit event_type=auth.failure
| stats count by user, details.host
| where count >= 3
```
- **Trigger**: When count >= 3 in 5 minutes
- **Action**: Send email + create ticket
- **Severity**: High

**Resource Limit Violations**
```spl
index=pcap_analyzer_audit event_type="security.resource_limit.exceeded"
```
- **Trigger**: When count > 5 in 10 minutes
- **Action**: Page on-call engineer
- **Severity**: High

---

## Elastic Stack (ELK) Integration

### 1. Filebeat Configuration (filebeat.yml)

```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /opt/pcap_analyzer/logs/audit/security_audit.log
    json.keys_under_root: true
    json.add_error_key: true
    fields:
      log_type: pcap_audit
      environment: production
    fields_under_root: true

output.elasticsearch:
  hosts: ["localhost:9200"]
  index: "pcap-audit-%{+yyyy.MM.dd}"

setup.template.name: "pcap-audit"
setup.template.pattern: "pcap-audit-*"
```

### 2. Elasticsearch Index Template

```json
PUT _index_template/pcap-audit-template
{
  "index_patterns": ["pcap-audit-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 1,
      "index.codec": "best_compression"
    },
    "mappings": {
      "properties": {
        "timestamp": {"type": "date"},
        "event_type": {"type": "keyword"},
        "severity": {"type": "keyword"},
        "outcome": {"type": "keyword"},
        "component": {"type": "keyword"},
        "user": {"type": "keyword"},
        "process_id": {"type": "long"},
        "source_ip": {"type": "ip"},
        "session_id": {"type": "keyword"},
        "file_path": {"type": "text"},
        "hostname": {"type": "keyword"},
        "record_id": {"type": "keyword"},
        "details": {"type": "object", "enabled": true}
      }
    }
  }
}
```

### 3. Kibana Queries

**Security Events (Last 7 Days)**
```
event_type: security.* AND timestamp:[now-7d TO now]
```

**Failed Authentication Attempts**
```
event_type: "auth.failure" AND timestamp:[now-1h TO now]
```

**High-Severity Events**
```
severity: (CRITICAL OR ALERT OR EMERGENCY)
```

### 4. Kibana Visualizations

**Event Type Distribution (Pie Chart)**
- **Index**: `pcap-audit-*`
- **Aggregation**: Terms on `event_type.keyword`
- **Time Range**: Last 24 hours

**Security Events Over Time (Line Chart)**
- **Index**: `pcap-audit-*`
- **X-Axis**: Date Histogram on `timestamp`
- **Y-Axis**: Count
- **Filter**: `event_type: security.*`

**Top Users by Activity (Bar Chart)**
- **Index**: `pcap-audit-*`
- **Aggregation**: Terms on `user.keyword`
- **Metric**: Count

### 5. Watcher Alerts

**Critical Security Event Alert**
```json
PUT _watcher/watch/pcap-critical-events
{
  "trigger": {
    "schedule": {"interval": "5m"}
  },
  "input": {
    "search": {
      "request": {
        "indices": ["pcap-audit-*"],
        "body": {
          "query": {
            "bool": {
              "must": [
                {"range": {"timestamp": {"gte": "now-5m"}}},
                {"terms": {"severity": ["CRITICAL", "ALERT", "EMERGENCY"]}}
              ]
            }
          }
        }
      }
    }
  },
  "condition": {
    "compare": {"ctx.payload.hits.total": {"gt": 0}}
  },
  "actions": {
    "send_email": {
      "email": {
        "to": "security-team@example.com",
        "subject": "Critical Security Event Detected",
        "body": "{{ctx.payload.hits.total}} critical events detected in PCAP Analyzer"
      }
    }
  }
}
```

---

## Graylog Integration

### 1. Create Input

**Input Type**: GELF UDP

```bash
# Install GELF plugin (if not already installed)
# Navigate to System > Inputs > Select "GELF UDP" > Launch new input
```

**Configuration:**
- Bind address: `0.0.0.0`
- Port: `12201`
- Input name: `PCAP Analyzer Audit Logs`

### 2. Forward Logs with Filebeat (to Graylog)

```yaml
filebeat.inputs:
  - type: log
    paths:
      - /opt/pcap_analyzer/logs/audit/security_audit.log
    json.keys_under_root: true

output.logstash:
  hosts: ["graylog.example.com:5044"]
```

### 3. Logstash Pipeline (Bridge to Graylog)

```ruby
input {
  beats {
    port => 5044
  }
}

filter {
  json {
    source => "message"
  }

  mutate {
    add_field => {
      "[@metadata][graylog_facility]" => "pcap_audit"
    }
  }
}

output {
  gelf {
    host => "graylog.example.com"
    port => 12201
  }
}
```

### 4. Graylog Streams

**Security Events Stream**
- **Rule**: `event_type` matches regex `^security\.`
- **Description**: All security-related events

**Critical Events Stream**
- **Rule**: `severity` matches exactly `CRITICAL` OR `ALERT` OR `EMERGENCY`
- **Description**: Critical severity events only

### 5. Graylog Alerts

**Decompression Bomb Alert**
- **Condition Type**: Message Count
- **Search Query**: `event_type:"security.decompression_bomb.detected"`
- **Threshold**: >= 1 messages in 1 minute
- **Action**: Email notification

---

## Common SIEM Queries

### 1. Authentication Analysis

**Failed Logins by User**
```
event_type: "auth.failure"
| stats count by user, details.host
| where count > 3
```

**Successful Logins After Failures (Potential Compromise)**
```
(event_type: "auth.failure" OR event_type: "auth.success")
| transaction user maxspan=10m
| where event_type="auth.success" AND prev_event_type="auth.failure"
```

### 2. File Validation Failures

**Invalid PCAP Files**
```
event_type: "file.validation.failure"
| stats count by details.failure_reason
```

**Oversized File Rejections**
```
event_type: "security.oversized_file.rejected"
| table timestamp, file_path, details.file_size_gb, details.max_size_gb
```

### 3. Resource Exhaustion

**Memory Limit Violations**
```
event_type: "security.resource_limit.exceeded" AND details.limit_type: "MEMORY"
| timechart count
```

**CPU Limit Violations**
```
event_type: "security.resource_limit.exceeded" AND details.limit_type: "CPU"
| stats count by hostname
```

### 4. Security Incident Detection

**Potential Attack Patterns**
```
event_type: security.*
| stats count by event_type, source_ip
| where count > 5
```

**Path Traversal Attempts**
```
event_type: "security.path_traversal.attempt"
| table timestamp, details.requested_path, details.resolved_path
```

---

## Log Rotation

### Linux (logrotate)

```bash
# /etc/logrotate.d/pcap-analyzer-audit
/opt/pcap_analyzer/logs/audit/security_audit.log {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    create 0600 pcap_user pcap_group
    postrotate
        # Signal SIEM to reload (if needed)
        systemctl reload filebeat 2>/dev/null || true
    endscript
}
```

---

## Security Best Practices

### 1. Log Integrity

**File Permissions:**
```bash
chmod 0600 logs/audit/security_audit.log
chmod 0700 logs/audit/
```

**Immutable Logs (Linux):**
```bash
# Make log file append-only
sudo chattr +a logs/audit/security_audit.log
```

### 2. Network Security

**Encrypt Logs in Transit:**
- Use TLS for Filebeat -> Logstash/Elasticsearch
- Use GELF TLS for Graylog
- Use Splunk forwarder with SSL

**Example Filebeat TLS:**
```yaml
output.logstash:
  hosts: ["logstash.example.com:5044"]
  ssl.certificate_authorities: ["/etc/pki/tls/certs/ca.crt"]
  ssl.certificate: "/etc/pki/tls/certs/client.crt"
  ssl.key: "/etc/pki/tls/private/client.key"
```

### 3. Access Control

**SIEM User Permissions:**
- Read-only access to audit indices
- No delete permissions
- Audit log access logged separately

---

## Compliance Reporting

### NIST SP 800-53 AU-2/AU-3

**Report: All Auditable Events (AU-2)**
```
event_type: *
| stats count by event_type
| lookup nist_au2_compliance event_type OUTPUT requirement
```

**Report: Audit Record Content (AU-3)**
```
event_type: *
| eval has_timestamp=isnotnull(timestamp)
| eval has_event_type=isnotnull(event_type)
| eval has_outcome=isnotnull(outcome)
| eval has_source=isnotnull(user) OR isnotnull(process_id)
| where has_timestamp AND has_event_type AND has_outcome AND has_source
```

### PCI-DSS 10.2

**Report: User Access to Cardholder Data**
```
(event_type: "file.processing.*" OR event_type: "access.*")
| table timestamp, user, event_type, outcome, file_path
```

### ISO 27001 A.12.4.1

**Report: Event Logging Compliance**
```
event_type: *
| stats count by severity, outcome
| eval compliant=if(count > 0, "YES", "NO")
```

---

## Troubleshooting

### Logs Not Appearing in SIEM

1. **Check file permissions:**
   ```bash
   ls -l logs/audit/security_audit.log
   ```

2. **Verify JSON format:**
   ```bash
   cat logs/audit/security_audit.log | jq .
   ```

3. **Check Filebeat connectivity:**
   ```bash
   filebeat test output
   ```

4. **Review SIEM ingestion logs:**
   ```bash
   tail -f /var/log/filebeat/filebeat.log
   ```

### Parsing Errors

**Invalid JSON:**
```bash
# Validate JSON format
python3 -m json.tool logs/audit/security_audit.log
```

**Timestamp Issues:**
```bash
# Check timestamp format
cat logs/audit/security_audit.log | jq -r '.timestamp'
```

---

## Contact & Support

For SIEM integration issues:
- **Documentation**: `docs/AUDIT_COMPLIANCE.md`
- **Analysis Tool**: `scripts/analyze_audit_log.py`
- **Log Format**: JSON schema in this document

For security incidents found in audit logs:
- Review `scripts/analyze_audit_log.py --incidents`
- Escalate critical events per incident response plan
