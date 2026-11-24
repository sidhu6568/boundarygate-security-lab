# BoundaryGate: delegated agent-tool security repair

One downloadable bundle contains the repair task, isolated Python environment, reference solution, and behavioral verifier. It uses the same Harbor package layout as the accompanying RelayFrame example.

The candidate repairs a tool gateway after a synthetic authorization incident. The gateway must reject forged or overbroad authority while preserving legitimate delegated calls. Tests cover signed parent binding, ancestor policy intersection, path confusion, injected approval text, budget sharing, transactional rollback, retry identity, and revocation.

The work stays inside a local simulator. There is no external exploitation, cloud account, browser session, paid API, or customer evidence to prepare. After the runtime and base images are available, the task and verifier run without network access.

The release includes measured reference and starter results plus a mutation audit. Those results establish that the task is solvable and rejects the audited partial fixes. A claim that it defeats a named model requires a recorded run of that model; this listing makes no such claim.
