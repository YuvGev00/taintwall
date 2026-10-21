# Load test

Locust, 200 concurrent simulated agent sessions, 75 s (ramp 50 users/s), `loadtest/locustfile.py`.

**Hardware:** MacBook Pro, Apple M2 Pro (12 cores), 16 GB, macOS 25.5 (Darwin). Locust (one process) and the
service (uvicorn, 2 workers, SQLite in WAL mode, `noop` detector) ran on the *same* machine, so they compete
for CPU. Run on 2026-10-21; no GPU, no Docker involved.

| Endpoint | Requests | Failures | RPS | p50 | p95 | p99 |
|---|---:|---:|---:|---:|---:|---:|
| `POST /v1/check/tool_call` | 21,258 | 0 | 294 | 250 ms | 640 ms | 850 ms |
| `POST /v1/check/tool_output` | 16,955 | 0 | 235 | 180 ms | 500 ms | 740 ms |
| `POST /v1/sessions` | 200 | 0 | 2.8 | 140 ms | 260 ms | 390 ms |
| **All** | 38,413 | 0 | 531 | 210 ms | 600 ms | 820 ms |

## How to read this

- This is a **saturation** number. 200 users with 50–200 ms think time offer more load than the box serves, so the
  latencies are mostly queueing. An unloaded request takes a few ms (min observed 1.4 ms).
- The `noop` detector costs nothing here, so `tool_output` measures the HTTP + SQLite write + LRU path only.
  With ProtectAI on CPU, a cache miss costs a DeBERTa forward pass (tens to hundreds of ms); the cache exists for that.
- `tool_call` rebuilds the session's provenance from its stored tool outputs on every call (O(session
  history)). Sessions here grow for the whole run, so late-run calls are slower than early ones. A per-session
  provenance cache would be the first optimization.
- SQLite serializes writes (one writer at a time); Postgres is the intended multi-worker store. Not benchmarked.

Reproduce:

```bash
TAINTWALL_DATABASE_URL=sqlite:////tmp/tw-load.db uv run uvicorn taintwall.api.app:app --workers 2 --port 8000 &
uv run locust -f loadtest/locustfile.py --headless -u 200 -r 50 -t 75s --host http://localhost:8000
```
