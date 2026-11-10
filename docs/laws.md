# Law-driven checks

Schemathesis finds bugs by generating inputs and asserting on responses. That
model is excellent for protocol-level bugs, but it cannot see the bugs that
live in *who is allowed to do what*:

* a write that lands in a row owned by somebody else (IDOR on write),
* a request that changes the caller's own authority (mass assignment),
* two identical requests that both succeed (a TOCTOU race).

`schemathesis.laws` adds that layer. It works on two inputs:

**A traffic log** - the requests a normal client makes. From it the engine
learns which resources exist, who owns them, and which access rules hold.

**A write ledger** - one line per database mutation, attributed to the
principal that caused it:

```json
{"ts": 1794311241.68, "request_id": "req-8", "principal": "alice",
 "method": "PUT", "path": "/orders/o1", "table": "orders", "row_id": "o1",
 "columns": {"status": "paid"}, "source_fields": ["status"], "row_owner": "alice"}
```

For Postgres, enable `log_statement = 'all'` and tag connections with
`SET application_name = 'mizan:<principal>'`; `PostgresLogParser` turns the log
into ledger events.

## Usage

```bash
export MIZAN_POLICY=mizan-policy.json
export MIZAN_LEDGER=ledger.jsonl
schemathesis run http://127.0.0.1:8000/openapi.json --checks MizanLawCheck
```

## The laws

| ID | Law | Severity |
|---|---|---|
| L1 | Authentication coherence | high |
| L2 | Read authorization (read-taint) | high |
| L3 | Write authorization (write-taint) | high |
| L4 | No authority creation | critical |
| L5 | Atomicity (TOCTOU) | high |
| L6 | Cardinality and bounds | medium |
| L7 | Path confidentiality | medium |

## Access matrix

Every identity has a row in the access matrix, every `(resource, action)` a
column. The permitted matrix comes from the learned rules; the observed matrix
comes from the run. The difference is the residual, and its norm per identity
shows how far each identity strayed from its own authority.
