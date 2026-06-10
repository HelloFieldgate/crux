# Helios Platform Services

## Auth Service

Handles all authentication and authorization for the Helios platform. Issues short-lived JWTs for operator sessions and longer-lived API keys for robot-to-cloud communication. Integrates with our SSO provider via OIDC.

Owner: Alice Chen. Language: Rust. Deployment: single replica per region, active-passive failover. Dependencies: PostgreSQL (session store), Redis (token cache). On-call rotation: platform team.

Key endpoints: `POST /auth/token`, `POST /auth/refresh`, `GET /auth/validate`, `DELETE /auth/revoke`. SLA: 99.95% availability, p99 latency under 50ms.

## Inventory Service

Manages the robot fleet registry: which robots exist, their firmware versions, assigned missions, and current operational status. The source of truth for fleet composition.

Owner: Bob Singh. Language: Go. Deployment: stateless, horizontally scaled behind a load balancer. Dependencies: PostgreSQL (fleet DB), Auth Service (token validation), Telemetry Pipeline (status updates).

Key endpoints: `GET /inventory/robots`, `POST /inventory/robots`, `PATCH /inventory/robots/{id}`, `GET /inventory/missions`. SLA: 99.9% availability.

## Telemetry Pipeline

Real-time ingestion and fanout of sensor data from active robots. Robots push telemetry over MQTT; the pipeline normalizes, stores in time-series, and fans out to subscribers (operator dashboards, anomaly detectors, fleet console).

Owner: Maria Reyes. Language: Rust. Deployment: distributed message broker + stream processors. Dependencies: MQTT broker, InfluxDB (time-series), Kafka (fanout). Throughput target: 50k events/sec per region.

Data classification: sensor readings are `internal`. If a reading includes location data from a deployment with a confidentiality agreement, elevate to `confidential`.

## Web UI

Operator-facing dashboard for fleet management, live telemetry views, mission planning, and incident reporting. Single-page application served from a CDN, talks exclusively to the Helios API gateway.

Owner: Priya Patel. Language: TypeScript/React. Deployment: static assets on CDN, API calls proxied through gateway. No server-side rendering. Auth: SSO via Auth Service.

Key features: live map view of active robots, mission queue editor, telemetry charts, incident dashboard, user management.
