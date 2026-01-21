# Azure Structured Logging Guide

## Overview

This application uses structured JSON logging that is optimized for Azure Container Apps, Azure Monitor, and Application Insights. All logs include correlation IDs for distributed tracing across services.

## Log Format

All logs are output as JSON with the following structure:

```json
{
  "timestamp": "2026-01-21T22:41:41.862665+00:00",
  "level": "INFO",
  "service": "api",
  "logger": "main",
  "message": "Scan request received",
  "correlation_id": "test-scan-001",
  "url": "https://example.com",
  "scan_type": "url",
  "source": "test"
}
```

### Standard Fields

- **timestamp**: ISO 8601 formatted timestamp with timezone
- **level**: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- **service**: Service name (api, worker, fetcher)
- **logger**: Python logger name (typically module name)
- **message**: Human-readable log message
- **correlation_id**: Request correlation ID for distributed tracing (when available)

### Custom Context Fields

Additional fields vary by operation:

- **job_id**: Unique scan job identifier
- **url**: Target URL being scanned
- **scan_type**: Type of scan (url, file)
- **source**: Source of the scan request
- **verdict**: Scan verdict (benign, malicious, suspicious)
- **status**: Job status (queued, processing, completed, failed)
- **duration_ms**: Operation duration in milliseconds
- **size_bytes**: File/content size in bytes
- **backend**: Storage backend being used (redis, blob, table)
- **error**: Error message (when applicable)
- **error_type**: Exception class name (when applicable)

## Correlation IDs

### How They Work

1. **API Requests**: Correlation IDs are captured from incoming requests via headers:
   - `X-Correlation-ID` (preferred)
   - `X-Request-ID` (fallback)
   - Auto-generated UUID if not provided

2. **Service Bus Messages**: Correlation IDs are propagated through message metadata

3. **Context Propagation**: Using Python's `contextvars`, correlation IDs are automatically included in all log statements within the same request/task context

### Example Flow

```
Client Request → API (correlation_id: abc-123)
                  ↓
              Service Bus (metadata: correlation_id=abc-123)
                  ↓
              Worker (correlation_id: abc-123)
```

All logs throughout this flow will include `"correlation_id": "abc-123"`.

## Azure Integration

### Azure Container Apps

Azure Container Apps automatically captures stdout/stderr from containers and forwards them to:

- Azure Log Analytics workspace
- Application Insights (if configured)

**No additional configuration required** - JSON logs are automatically parsed and indexed.

### Log Analytics Queries

Query logs by correlation ID to trace a request through all services:

```kusto
ContainerAppConsoleLogs_CL
| where TimeGenerated > ago(1h)
| extend logData = parse_json(Log_s)
| where logData.correlation_id == "test-scan-001"
| project 
    TimeGenerated, 
    Service=logData.service,
    Level=logData.level,
    Message=logData.message,
    JobId=logData.job_id,
    Url=logData.url,
    Verdict=logData.verdict
| order by TimeGenerated asc
```

Query by job ID:

```kusto
ContainerAppConsoleLogs_CL
| where TimeGenerated > ago(24h)
| extend logData = parse_json(Log_s)
| where logData.job_id == "eea2a65e-f40d-44a5-9bee-03e618dea6fb"
| project 
    TimeGenerated,
    Service=logData.service,
    Message=logData.message,
    Status=logData.status,
    Verdict=logData.verdict,
    Duration=logData.duration_ms
| order by TimeGenerated asc
```

Find errors:

```kusto
ContainerAppConsoleLogs_CL
| where TimeGenerated > ago(1h)
| extend logData = parse_json(Log_s)
| where logData.level in ("ERROR", "CRITICAL")
| project 
    TimeGenerated,
    Service=logData.service,
    Message=logData.message,
    Error=logData.error,
    ErrorType=logData.error_type,
    CorrelationId=logData.correlation_id
| order by TimeGenerated desc
```

Analyze scan performance:

```kusto
ContainerAppConsoleLogs_CL
| where TimeGenerated > ago(1h)
| extend logData = parse_json(Log_s)
| where logData.message == "Scan completed successfully"
| project 
    TimeGenerated,
    Duration=toint(logData.duration_ms),
    Size=toint(logData.size_bytes),
    Verdict=logData.verdict
| summarize 
    AvgDuration=avg(Duration),
    P50=percentile(Duration, 50),
    P95=percentile(Duration, 95),
    P99=percentile(Duration, 99),
    Count=count()
    by Verdict
```

### Application Insights

If Application Insights is configured, JSON fields are automatically extracted and available as custom dimensions for:

- **Dependency tracking** (external calls, database queries)
- **Request telemetry** (API endpoints)
- **Custom metrics** (duration_ms, size_bytes)
- **Distributed tracing** (via correlation_id)

Example Application Insights query:

```kusto
traces
| where timestamp > ago(1h)
| where customDimensions.service == "worker"
| where customDimensions.message == "Scan completed successfully"
| project 
    timestamp,
    message,
    verdict=customDimensions.verdict,
    duration=toint(customDimensions.duration_ms),
    correlationId=customDimensions.correlation_id
| order by timestamp desc
```

## Local Development

### Viewing Logs

View JSON logs from Docker containers:

```bash
# All services
docker compose logs -f

# Specific service
docker logs azure-devsecops-aca-api-1 -f

# Filter by correlation ID
docker logs azure-devsecops-aca-api-1 2>&1 | grep "correlation_id.*test-scan-001"

# Pretty print JSON logs
docker logs azure-devsecops-aca-worker-1 2>&1 | tail -20 | jq -r '. | "\(.timestamp) [\(.level)] \(.service).\(.logger): \(.message) \(if .correlation_id then "(\(.correlation_id))" else "" end)"'
```

### Testing Correlation IDs

Submit a request with a custom correlation ID:

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: local-dev-key" \
  -H "X-Correlation-ID: my-custom-trace-id" \
  -d '{"url": "https://example.com", "type": "url", "source": "test"}'
```

Then trace it through the logs:

```bash
docker logs azure-devsecops-aca-api-1 2>&1 | grep "my-custom-trace-id"
docker logs azure-devsecops-aca-worker-1 2>&1 | grep "correlation_id"
```

## Implementation Details

### Logging Configuration

The logging infrastructure is implemented in `app/common/logging_config.py`:

- **JSONFormatter**: Custom formatter that outputs structured JSON
- **setup_logging()**: Initializes JSON logging for a service
- **get_logger()**: Returns a logger instance with JSON formatting
- **set_correlation_id()**: Sets correlation ID in context for current request/task
- **clear_correlation_id()**: Clears correlation ID from context
- **log_with_context()**: Logs with automatic correlation ID and custom fields

### API Middleware

The API service uses FastAPI middleware to capture correlation IDs from incoming requests:

```python
@app.middleware("http")
async def correlation_id_middleware(request: Request, call_next):
    correlation_id = (
        request.headers.get("X-Correlation-ID") 
        or request.headers.get("X-Request-ID") 
        or str(uuid4())
    )
    set_correlation_id(correlation_id)
    # ... process request
    response.headers["X-Correlation-ID"] = correlation_id
    return response
```

### Worker Correlation ID Propagation

Workers extract correlation IDs from Service Bus message metadata:

```python
correlation_id = task.get("correlation_id")
if correlation_id:
    set_correlation_id(correlation_id)
```

### Example Usage in Code

```python
from common.logging_config import get_logger, log_with_context
import logging

logger = get_logger(__name__)

# Simple log with automatic correlation ID
log_with_context(logger, logging.INFO, "Processing started", job_id=job_id)

# Log with additional context fields
log_with_context(
    logger, 
    logging.INFO, 
    "Scan completed",
    job_id=job_id,
    verdict=verdict,
    duration_ms=duration,
    size_bytes=size
)

# Error logging with exception details
log_with_context(
    logger, 
    logging.ERROR, 
    "Scan failed",
    job_id=job_id,
    error=str(e),
    error_type=e.__class__.__name__
)
```

## Benefits

### For Development

- **Easy debugging**: Filter logs by correlation ID to trace a single request
- **Rich context**: All relevant data included in log statements
- **Consistent format**: All services use the same JSON structure

### For Production

- **Auto-indexed**: Azure automatically parses JSON and indexes all fields
- **Queryable**: Use KQL to filter, aggregate, and analyze logs
- **Distributed tracing**: Follow requests across services via correlation IDs
- **Performance monitoring**: Track duration_ms and size_bytes metrics
- **Error tracking**: Quickly identify and diagnose issues with structured error logs

### For Operations

- **Alerting**: Create alerts based on specific field values (verdict, error_type, duration)
- **Dashboards**: Build Azure dashboards using structured log data
- **Compliance**: Structured logs make audit trails and compliance reporting easier
- **Cost optimization**: Efficient indexing reduces query costs
