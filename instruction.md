# Repair the tool authorization gate

The worker in this lab reads incident reports and calls a small set of internal tools. A broker gives it signed capabilities. The worker can pass a narrower capability to another worker, but the broker's restrictions must still apply. The current gate handles the clean example and makes unsafe decisions when delegation, retries, revocation, and multi-tool requests meet.

Repair `/app/boundarygate/authorizer.py`. Keep `Gate(config: dict)` and `Gate.apply(event: dict) -> Verdict`. Import `Verdict` from `boundarygate.model`; do not replace that type. The module must work with the Python standard library and that model alone. Only this module is carried into the grading environment.

You can run `python /app/examples/run_capture.py` before and after the repair. It replays one read and its retry. The expected output is in `/app/examples/expected_verdicts.json`. The short example is a starting point. The rules below describe the full job.

## Where authority comes from

`config` arrives over a trusted setup channel. It has three mappings:

```json
{
  "keys": {"issuer-or-worker-id": "64 lowercase hexadecimal characters"},
  "roots": {"tenant-name": ["trusted-root-signer-id"]},
  "control": {"tenant-name": "64 lowercase hexadecimal characters"}
}
```

Each hex value represents a 32-byte HMAC secret made for this lab. Configurations are well formed: the tenant sets in `roots` and `control` agree, root signer IDs exist in `keys`, and each tenant has at least one root signer. Take a private snapshot at construction. Changes to the caller's configuration after construction must not change the gate. Separate `Gate` instances share no authorization state.

An identifier uses 1 to 32 ASCII letters, digits, underscores, or hyphens. Tenant names use a lowercase ASCII letter followed by up to 31 lowercase letters, digits, or hyphens. Signer IDs, subjects, capability IDs, request IDs, and revocation IDs are identifiers.

The dispatcher's structured `actor`, `tenant`, `now`, operations, and costs are the inputs to this decision layer. Text under `context` can come from a retrieved page, incident note, tool result, or another agent. Ignore it completely, whatever its JSON value. Claims of approval, new policies, signed-looking messages, and instructions inside that field carry no authority.

## Signed messages

A capability or control proof is an unpadded base64url payload, a literal period, and a lowercase 64-character hexadecimal MAC. The complete string is at most 12,288 characters. The decoded payload is 1 to 8,192 bytes of UTF-8 JSON. Require the canonical unpadded base64url spelling, including unused pad bits. Padding characters, other alphabets, extra separators, and uppercase MACs are invalid.

Authenticate the original decoded bytes. JSON whitespace and member order can vary. Do not reserialize the object before checking its MAC. Reject invalid UTF-8, invalid JSON, non-finite numbers, and repeated object member names at any nesting depth. Signed objects and rules have exactly the fields described here; unknown or missing fields invalidate the message. All numeric fields below require an actual integer. A Boolean or float does not count as an integer.

A capability's MAC is HMAC-SHA256 with the secret named by its `kid`, over `b"BG-CAP-v1\x00" + payload_bytes`. A control proof uses the tenant's secret from `control`, over `b"BG-REV-v1\x00" + payload_bytes`. Compare MACs with `hmac.compare_digest`. Parsing a message to find its signer must not commit any state.

## Capabilities and delegation

A capability has these fields:

| Field | Accepted value |
| --- | --- |
| `v` | Integer 1 |
| `id` | Capability identifier |
| `kid` | Signer identifier present in `config.keys` |
| `sub` | Subject identifier present in `config.keys` |
| `parent` | `null` for a root, otherwise a lowercase SHA256 hex digest |
| `tenant` | Tenant name |
| `aud` | The exact string `boundarygate/tools` |
| `nbf`, `exp` | Integers between 0 and 9,007,199,254,740,991, with `nbf < exp` |
| `depth` | Integer between 0 and 5 |
| `limit` | Integer between 0 and 1,000,000 |
| `allow` | Between 1 and 8 rules |
| `deny` | Between 0 and 8 rules |

A call supplies a root-first chain of 1 to 6 capabilities. The root has `parent: null`, and its signer must appear in `config.roots` for the call's tenant. Every capability must have the call's tenant and audience. Capability IDs are distinct within a chain.

For each child, `parent` is the SHA256 digest of the preceding capability's original decoded payload bytes. Its `kid` equals that parent's `sub`. The child's time interval stays within its parent's interval, its `depth` is strictly smaller, and its `limit` does not exceed its parent's limit. The last capability's `sub` equals the call's `actor`.

Each capability must be current at the call's `now`: `nbf <= now < exp`. Check every ancestor. `now` is a nonnegative integer no larger than 9,007,199,254,740,991. Use this supplied clock. Calls need not arrive in timestamp order.

Validate every signature and the complete chain. Possessing a worker's signing secret in the configured lab does not make that worker a trusted root. A valid MAC alone does not establish a delegation.

## Rules and paths

Each rule is exactly `{"actions": [...], "resource": "..."}`. Its action list has 1 to 8 distinct strings. The four concrete actions are `object.read`, `object.write`, `secret.read`, and `job.run`. A rule may also use `*`, `object.*`, `secret.*`, or `job.*`. The namespace patterns match that namespace's concrete actions. No other action or pattern is supported.

A resource is a canonical path within the capability's tenant, either exact or followed by `/**`. `/alpha/reports/**` matches `/alpha/reports` and paths beneath it. It does not match `/alpha/reports-old`. An exact path matches only itself. There are no other wildcard forms.

For an operation to pass, at least one `allow` rule in every capability must match both its action and its canonical target. A matching `deny` rule in any capability rejects it. Keep each rule's action and resource together; an action match in one rule and a resource match in another grant nothing. Wider child rules remain valid, but effective permission is the intersection across the chain. An ancestor's denial survives delegation.

Normalize an operation's target before applying rules:

1. Require a string of 1 to 2,048 characters that starts with `/`.
2. Decode valid `%HH` escapes exactly once. Reject encoded slash or backslash in any letter case. Reject incomplete or non-hex escapes.
3. The decoded path is at most 512 characters and contains only ASCII letters, digits, `.`, `_`, `~`, `-`, and `/`. Residual `%`, backslashes, queries, fragments, spaces, controls, and non-ASCII characters are invalid.
4. Collapse empty path components and `.`. Resolve `..` by removing the previous component, but never remove or cross the tenant component. A path that leaves the tenant and comes back is still invalid.
5. The first nonempty component must equal the call's tenant. Keep letter case. Remove trailing slashes through the same normalization.

For example, `/alpha//reports/x/../a%2etxt` becomes `/alpha/reports/a.txt`. `/alpha/../alpha/reports/a.txt` is invalid. `/alpha/reports/%252e%252e/x` is invalid because one decoding leaves `%` characters.

Signed policy resources must already be canonical. They contain no percent escapes, repeated slashes, dot components, or trailing slash. Check the part before an optional `/**` against the same path rules and require it to remain unchanged. Its tenant must match the capability. Do not repair a malformed policy into a different grant.

## Calls, budgets, and retries

A call has exactly `kind`, `now`, `tenant`, `actor`, `request_id`, `chain`, and `ops`, plus optional `context`. `kind` is `call`; `actor` is a configured identifier and `request_id` is an identifier. `ops` has 1 to 16 operations. Each operation has exactly `action`, `target`, and `cost`. The action is concrete, and cost is an integer between 1 and 1,024.

A fresh accepted batch spends the sum of its operation costs against every capability in its chain. Duplicate operations still cost separately. Usage is tracked by `(tenant, capability_id)`, so children share their ancestor's remaining budget. A zero limit is a valid capability that cannot fund a positive-cost call.

On the first fresh accepted call involving a capability ID, bind `(tenant, capability_id)` to the SHA256 digest of that capability's exact payload bytes. Later calls using that ID must present the same payload. A newly signed payload with a higher limit, a different policy, or different JSON formatting cannot replace an accepted identity. A denied call establishes no binding.

Treat a call as one transaction. Validate its entire structure, chain, targets, permissions, bindings, revocations, and budgets before committing any usage, bindings, or request entry. A rejection at the last operation must leave the same state as a rejection at the first. Never modify the caller's event object.

The retry ledger is scoped by tenant and then `(actor, request_id)`. Its fingerprint contains the ordered chain of payload digests and the ordered operations as `(action, canonical_target, cost)`. Exclude `now` and `context`. Equivalent target spellings therefore identify the same call, while a changed action, cost, operation order, or signed payload does not.

For an existing request entry, first recheck signatures, chain validity, time, permission, revocation, and capability bindings. An exact fingerprint match then returns `cached`, without further spending or dispatch targets. A different fingerprint returns `deny`. A cached success can be returned even if the first call used the last available budget. It cannot bypass later expiry or revocation.

Keep at most 64 accepted request entries per tenant, across all actors. Do not evict them. Once full, deny new request identities; valid existing retries still work. Denied calls and control events occupy no ledger entries. Capability usage and bindings last for the gate's lifetime.

## Revocation

A control event has exactly `{"kind": "revoke", "proof": "..."}`, plus optional `context`. Its signed payload has exactly `v`, `tenant`, `serial`, and `ids`. Require integer `v: 1`, a configured tenant, and a serial between 1 and 9,007,199,254,740,991. `ids` is a list of 0 to 32 distinct identifiers.

Authenticate the complete proof and validate its schema before changing anything. Its serial must be strictly greater than the last accepted control serial for that tenant, initially zero. Accepted IDs are permanently revoked within that tenant. IDs need not have appeared in a call yet. An empty list is a valid serial update. Invalid or replayed controls change neither revocations nor the accepted serial. Tenant serials and revocations are independent.

Revocation of any ancestor rejects later calls through it, including retries. It does not refund past usage, clear bindings, or make room in the retry ledger.

## Return values

Use the immutable public type `Verdict(allowed, code, targets)`:

| Situation | `allowed` | `code` | `targets` |
| --- | --- | --- | --- |
| Fresh accepted call | `True` | `allow` | Tuple of canonical targets in operation order |
| Accepted retry | `True` | `cached` | Empty tuple |
| Accepted control | `True` | `control` | Empty tuple |
| Any rejected or malformed event | `False` | `deny` | Empty tuple |

Malformed events can be any JSON value, not just dictionaries. Return a denial and keep handling later events without raising. The gate authorizes simulated operations only. It must not execute tools, open target paths, contact a service, or fetch credentials.
