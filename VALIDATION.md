# Release validation

Validated on 29 October 2026 with Harbor 0.20.0, Docker's Linux engine, and Python 3.12.14 in both lab images. Local checks also ran under Python 3.14.4 in WSL.

The reference passes all 116 behavioral checks across 573 events and receives reward `1`. The unmodified starter passes 33 checks and receives reward `0`. Both Harbor trials complete without exceptions, and their transferred authorizer files match the corresponding source files byte for byte. The public capture produces the expected fresh approval and cached retry with both implementations.

The verifier builds and signs its own messages. Twelve generated traces vary tenants, signing identities, subjects, capability IDs, secrets, and resource names. They combine inherited restrictions, shared budgets, rejected batches, retries, and revocation. Separate cases check exact limits and keep every supported tool action usable.

The mutation audit rejects all 32 faulty repairs through incorrect verdicts. The faults include skipped lineage or ancestor restrictions, prefix matching, double decoding, unsigned controls, premature state updates, leaf-only spending, incomplete retry identity, cached approvals after revocation, and hard-coded demo signers. Allow-all, deny-all, and disabling an otherwise permitted tool also fail. Syntax errors or process crashes are treated as audit errors rather than successful rejections.

The installed Harbor model accepts schema 1.4, one transferred artifact, and a separate verifier. Both digest-pinned images build successfully with no runtime package installation. Network probes use Docker mode `none`. The agent image contains neither the reference nor the private verifier. A probe as UID/GID 65,534 can read the public contract and cannot read the private verifier source. The two model files are byte-identical.

All Python, JSON, JSONL, and TOML sources parse. The submission checker passes without warnings. The ZIP has the same 25-file layout and eight directory entries as the RelayFrame reference, with names adapted for BoundaryGate. Each entry matches its source bytes and passes its ZIP CRC check. Audit reports, local logs, receipts, and development helpers stay outside the submission.

From the folder containing the extracted task, run:

```sh
harbor run -p boundarygate-security-lab -a oracle
harbor run -p boundarygate-security-lab -a nop
```

Expect rewards `1` and `0`. Harbor collects `metrics.json` and `reward.txt` with the trial logs. Obtaining an uncached base image or installing Harbor can require network access during setup; the lab runs without networking.

No model-agent solve attempt was made. The audit establishes a working reference, a failing starter, and rejection of the tested faulty repairs. It does not establish a named model's failure rate or a measured expert completion time.
