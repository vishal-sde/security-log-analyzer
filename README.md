# Security Log Analyzer & Threat Detection

A mini-SIEM: log ingestion → normalization → rule-based detection → risk scoring → live alert dashboard.

Built as a portfolio project to demonstrate backend design for security-adjacent systems: Spring Boot, PostgreSQL, Redis, and an explainable (non-ML) detection engine.

## Architecture

```
POST /api/logs
      │
      ▼
 [raw_logs]  ──persist first, never lose data──▶ (JSONB payload)
      │
      ▼
 LogNormalizer ──▶ [normalized_events] (queryable by ip / username / type)
      │
      ▼
 DetectionEngine ──▶ runs every DetectionRule against the event
      │                 • BruteForceDetectionRule (Redis sliding window)
      │                 • KnownRiskyIpDetectionRule (denylist)
      │                 • SensitiveFileAccessDetectionRule (path match)
      ▼
   [alerts]  (risk_score, severity, evidence JSONB)
      │
      ▼
GET /api/alerts, GET /api/events  ──▶  live dashboard (polls every 5s)
```

## Stack

Java 21 · Spring Boot 4 · PostgreSQL · Redis · plain HTML/JS dashboard · Docker · Testcontainers

## Running locally

```bash
docker compose up -d        # Postgres (5433) + Redis (6379)
./mvnw spring-boot:run       # app on :8081
```

Health check: `curl http://localhost:8081/actuator/health`

Dashboard: `http://localhost:8081/`

### Generate sample traffic

A synthetic log generator lives in `src/test/java/.../tools/LogGenerator.java` (test-only, so it never ships in the jar). Run it from your IDE, or:

```bash
./mvnw test-compile exec:java -Dexec.mainClass=com.application.security_log_analyzer.tools.LogGenerator -Dexec.classpathScope=test
```

It sends normal login/file-access traffic plus two brute-force bursts, one from a known-risky IP, so you'll see all three detection rules fire.

## API

| Endpoint | Description |
|---|---|
| `POST /api/logs` | Ingest a log event. Optional `eventId` for idempotency; rejects duplicates. |
| `GET /api/events?ip=&username=&type=&limit=` | Query normalized events. |
| `GET /api/events/stats` | Total event count. |
| `GET /api/alerts?severity=&ip=&from=&to=&limit=` | Query alerts. |
| `GET /api/alerts/stats` | Alert counts by severity. |

Sample log event:

```json
{
  "timestamp": "2026-10-04T10:00:00Z",
  "ip": "203.0.113.7",
  "username": "admin",
  "eventType": "LOGIN_FAILURE",
  "eventId": "optional-idempotency-key",
  "meta": { "userAgent": "curl" }
}
```

## Testing

```bash
./mvnw test
```

21 tests: unit tests for each detection rule and the risk-scoring logic, plus a Testcontainers integration test that runs the full `POST /api/logs → normalize → alert` pipeline against real Postgres and Redis containers.

## Design notes / interview talking points

- **Explainable rules over ML.** Every alert has a `rule_triggered` name and an `evidence` JSONB blob showing exactly which values caused it to fire. For an MVP with no labeled training data, rule-based detection is auditable and immediately debuggable — something an ML model's output usually isn't.
- **Pluggable detection.** `DetectionRule` is an interface; `DetectionEngine` collects every Spring-managed bean implementing it and runs them all against each event. Adding a new rule (e.g. impossible-travel, odd-hours access) means writing one class — no changes to the engine or ingestion flow.
- **Redis sliding-window counters.** Both brute-force detection and rate limiting use the same pattern: `INCR` a key per (ip, username) or per caller, set a TTL only on the first increment of the window. `INCR` is atomic, so concurrent requests can't lose count the way a read-then-write counter would — and it's O(1), which matters when a burst is exactly the scenario being detected.
- **Raw-then-normalize, not atomic.** The raw payload is persisted in its own step before normalization runs, so a bad event or a transient failure in detection logic never costs you the original data. Logged and recoverable, not lost.
- **Idempotency.** Callers can supply an `eventId`; duplicates (network retries, replayed log shippers) are detected via a nullable unique index and short-circuited before reprocessing, so retried requests can't double-count a brute-force window or double-fire an alert.
- **How this scales beyond the MVP:** Kafka in front of ingestion for backpressure and multiple consumers; Elasticsearch for full-text log search; more detection rules (impossible travel, time-of-day anomalies); real IP reputation feeds instead of a hardcoded denylist; an `investigations`/`audit_logs` workflow for case management.

## Out of scope for this MVP

Kafka/event streaming, Elasticsearch, ML-based anomaly detection, additional detection rules beyond the three implemented, and a full investigation/audit workflow — all deliberate scope cuts to ship one thing end-to-end first.