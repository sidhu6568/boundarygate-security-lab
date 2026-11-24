# BoundaryGate security lab

BoundaryGate is a repair task about delegated access to agent tools. A worker has a signed capability, passes part of its authority to another worker, and asks a gateway to approve a batch of operations. The supplied gateway works on a clean read. It also trusts approval text from retrieved content, checks too little of a delegation chain, and updates spending before it knows whether a batch can pass.

The candidate repairs one Python file. The written contract covers the wire format, policy rules, trusted inputs, path normalization, shared budgets, request retries, and authenticated revocation. Everything runs locally. Resource paths are names in a simulator; the lab makes no cloud calls and needs no live credentials.

The hard part is deciding when separate facts can establish authority together. A valid signature can belong to an untrusted root. A child can allow an operation that its parent denies. A retry can be identical to a successful call and still be invalid after revocation. A failed batch can look harmless in its output while quietly using up another worker's budget. The tests observe those effects through later calls.

## Running it

From the directory containing this task:

```sh
harbor run -p boundarygate-security-lab -a oracle
harbor run -p boundarygate-security-lab -a nop
```

The reference repair should receive reward `1`. The starter should receive `0`. The agent has a 72,000-second budget to match the submission format; no test earns difficulty by waiting for that time to pass. The separate verifier has a 240-second limit.

Inside the agent environment, run `python /app/examples/run_capture.py` for the public example. It prints a fresh approval followed by a cached retry. The example should work before and after repair, so it cannot prove the security behavior on its own.

## What the bundle contains

`instruction.md` is the full candidate contract. `environment/` holds the starter and public example. `solution/` holds the reference repair. `tests/` builds a separate verifier image with its own copy of the result type and its own signed test messages. Harbor transfers only `/app/boundarygate/authorizer.py` between the two environments.

The verifier requires every check to pass. Diagnostic counts help locate a failure but do not award partial credit. `VALIDATION.md` records the measured results and the audit of partial repairs. Difficulty against a particular model remains unmeasured until that model completes a recorded attempt.
