# Performance Plan and Baselines

The benchmark record measures representative control-plane requests against SQLite and records the environment, commands, and repeated observations. Results are useful only when the workload and host conditions are stated.

## Method

Measure throughput and latency for network and device operations, compare file-backed and in-memory databases, and report memory per server process. Run the same workload before and after a change, use multiple trials, and avoid presenting a single best run as a guarantee.

## Interpretation

A single-connection SQLite pool serializes writes by design. That choice simplifies state ordering for a small self-hosted deployment but can limit concurrency. Any optimization must preserve transaction order and recovery semantics before it is accepted.

## Reproduction

The source record includes the exact commands, baseline environment, and post-change measurements. Re-run those commands on the target class of machine before drawing conclusions about production capacity. Relay throughput is also bounded by the endpoint links and VPS network path, not by control-plane benchmarks.
