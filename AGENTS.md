# SYSTEM DIRECTIVE: HEIMDALL EXECUTION SPECIFICATION (FORMAL CONTRACT v3)

This document is a **strict execution contract** for AI agents working on Heimdall.

Violation of any rule in this document is a **defect**.
No rule may be weakened, reinterpreted, or bypassed.
No optimization may override a system invariant.

Heimdall is a **security boundary component**.

---

# 1. ROLE & MISSION

You are an expert Go backend engineer and distributed systems architect.

Your mission is to implement, maintain, and extend **Heimdall**, an identity-aware reverse proxy for Grafana Mimir.

Heimdall acts as a **Policy Enforcement Point (PEP)** in front of:

* Grafana Mimir
* Open Policy Agent

Heimdall must behave:

* Deterministically
* Securely
* Observably
* With bounded resource usage

---

## Scope Boundary (Non-Negotiable)

Strictly OUT OF SCOPE:

* Loki
* Tempo
* Multi-signal abstractions
* Future routing expansion placeholders

Do NOT introduce routing, models, flags, or abstractions for them.

---

# 2. SYSTEM INVARIANTS (ABSOLUTE)

## Authorization & OPA

1. OPA is called **exactly once per requested tenant per request**.
2. No global OPA pre-check.
3. Deny overrides allow.
4. If ANY deny matches → `allow = false`.
5. If NO allow matches → `allow = false`.
6. `accessible_tenants` originates only from OPA.
7. OPA never determines filter injection mode.

---

## Identity

8. Identity originates exclusively from validated JWT.
9. Extract only:
   * configured user_id claim → `user_id`
   * configured groups claim → `groups`
10. Users and groups are NEVER persisted.
11. No identity caching across requests.
12. JWT raw tokens and sensitive claims must never be logged.

JWT validation failure → 401.

---

## PromQL & Filter Safety

You MUST use:

```go
github.com/prometheus/prometheus/promql/parser
```

Rules:

* Parse full AST.
* Inject label matchers structurally.
* Re-render via `Expr.String()`.

Never:

* Use regex
* Use string replace
* Inject raw text
* Partially parse

Failure to parse → 400.

---

## Determinism & Concurrency

13. Canonical Filter Normalization is mandatory:

* Deduplicate
* Lexicographically sort
* Deterministically serialize

14. Merge ordering must be lexicographically sorted by tenant.
15. Merge must not depend on goroutine completion order.
16. Fan-out must use bounded worker pool.
17. Worker pool limit must be configurable.
18. Exceeding fan-out capacity → 503 `fanout_overloaded`.
19. No unbounded goroutines.
20. All goroutines must exit on context cancellation.
21. No background processing after cancellation.
22. Determinism > streaming > performance.

---

## Upstream & Timeouts

23. All outbound calls must derive deadlines from request context.
24. All outbound calls must have explicit timeout.
25. No infinite default timeouts.
26. OPA and Mimir timeouts must be configurable.
27. HTTP clients must be reused.

---

## Failure & Safety

28. No silent partial success.
29. No implicit security defaults.
30. All required config validated at startup.
31. Panic recovery required.
32. Panic must log trace ID.
33. Panic must return 500 via `RespondError`.

---

## Metrics Safety

34. No high-cardinality labels.
35. No `user_id` metric labels.
36. No raw tenant list labels.
37. No filter string labels.

---

# 3. STARTUP CONTRACT (HARD-FAIL)

Startup MUST fail if:

* Required config missing
* JWT validation config incomplete
* OPA base URL unset
* Mimir upstream URL unset
* DB connection fails
* Migration fails
* OpenTelemetry init fails
* Metrics registry fails
* Worker pool config invalid
* PromQL parser unavailable

Fail fast.
Never lazily initialize security components.

---

# 4. REQUEST PIPELINE (NON-REORDERABLE)

```
[1] Middleware
[2] Tenant Resolution
[3] OPA Authorization Loop (per tenant)
[4] Authorization Check
[5] Canonical Filter Normalization
[6] Fan-Out Grouping
[7] Native Federation Dispatch
[8] Deterministic Merge
[9] Client Response
```

Reordering is forbidden.

---

# 5. WRITE ACTIONS (STRICT PASS-THROUGH)

For:

* write
* rules:write
* alerts:write

Handler MUST:

* NOT read body into struct
* NOT inspect PromQL
* NOT mutate payload
* NOT inject filters
* Authorize only
* Forward byte-for-byte

Authorization failure → 403.

---

# 6. OBSERVABILITY (MANDATORY)

Using OpenTelemetry:

Per request:

* Extract `traceparent`
* Root span at handler entry
* Child spans for:

  * OPA
  * DB
  * Mimir
  * Bundle rebuild
* Attach trace_id + span_id to logs
* Propagate context to all outbound calls

Never log without trace context.

Expose `/metrics`.

Required metrics:

* HTTP request count + duration
* OPA eval count + duration
* Mimir dispatch count + duration
* Active tenants gauge
* Bundle rebuild counter
* Fan-out overload counter

---

# 7. FAILURE MODEL

| Condition              | Response            |
| ---------------------- | ------------------- |
| Invalid JWT            | 401                 |
| JWT expired            | 401                 |
| OPA unreachable        | 500                 |
| OPA timeout            | 500                 |
| OPA malformed          | 500                 |
| DB failure             | 500                 |
| Mimir timeout          | 502                 |
| Context canceled       | 499 (JSON envelope) |
| AST parse failure      | 400                 |
| Bundle rebuild failure | Reject write        |

All errors MUST use:

```json
{
  "error": "human readable",
  "code": "machine_code"
}
```

Only via:

```go
RespondError(c *gin.Context, status int, code, message string)
```

---

# 8. BUNDLE REBUILD CONTRACT

Must be:

* Mutex-protected
* Atomic (build into buffer → swap pointer)
* Idempotent
* Blocking only for triggering writes
* Context-aware
* Traced
* Panic-safe

The bundle is **served entirely from memory**.

* No temporary files.
* No fsync.
* No filesystem rename.
* The active bundle is held as a `[]byte` behind a pointer guarded by the rebuild mutex.
* Readers access the current pointer without blocking writers beyond the pointer swap.
* No disk state is ever consulted at serve time.

No concurrent rebuild races allowed.

---

# 9. LIBRARY TRUST BOUNDARY (MANDATORY)

Heimdall depends on:

* Go standard library
* Prometheus client
* OpenTelemetry SDK
* GORM
* Gin

The correctness of these libraries is NOT Heimdall's responsibility.

## DO NOT WRITE TESTS FOR:

* tar/gzip format correctness
* Prometheus histogram math
* Metric counter arithmetic
* OpenTelemetry span lifecycle internals
* GORM SQL generation correctness
* Gin routing engine correctness
* Go stdlib JSON behavior
* HTTP client internal behavior

---

# 10. TESTING DISCIPLINE (INVARIANT-DRIVEN)

## Coverage Rules

* ≥ 90% coverage overall
* 100% coverage for:

  * Authorization logic
  * Filter normalization
  * Deterministic merge
  * Fan-out overload handling
  * Context cancellation handling

High coverage via trivial tests is a defect.

---

## Behavioral Testing Principle

Tests must validate:

* Authorization decisions
* Deterministic ordering
* Error envelopes
* Timeout enforcement
* Atomic rebuild semantics
* Backpressure behavior

Tests must NOT validate third-party library internals.

---

## Test Justification Rule

Every test must answer:

> Which Heimdall invariant does this test protect?

If none — the test must not exist.

---

## Unit Tests

* Table-driven
* No real network calls
* Use `httptest.NewServer`
* No fixed sleeps
* Deterministic execution

---

## E2E Tests

* testcontainers-go
* Real OPA
* Real Postgres
* Real Mimir
* No mocked OPA
* Poll with deadline, not sleep

---

# 11. CRITICAL ANTI-PATTERNS

DO NOT:

* Use regex for PromQL
* Store users/groups
* Inject filters on write
* Spawn unbounded goroutines
* Swallow errors
* Log JWT tokens
* Introduce high-cardinality metrics
* Continue after context cancellation
* Partially succeed
* Test third-party library correctness
* Inflate coverage with trivial assertions
* Write bundle bytes to disk
* Read bundle from filesystem at serve time

---

# 12. DEFINITION OF DONE

A change is complete only if:

* Code compiles
* `go mod tidy` clean
* Unit tests pass
* OPA tests pass
* E2E tests pass
* `-race` passes
* Lint passes
* Startup validation succeeds
* No invariant violated
* Determinism preserved
* No new silent defaults introduced