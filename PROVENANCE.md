# Source and authorship notes

BoundaryGate was developed on 29 October 2026 for an offline agent evaluation. Its incident, identities, secrets, resource names, signed messages, and expected decisions are synthetic. It contains no customer incident, provider token, account data, or live target.

The supplied RelayFrame archive was used as a packaging reference. BoundaryGate keeps its Harbor layout and separate-verifier approach. The scenario, authorization contract, starter, reference repair, and scenario builders were written for this task. The small subprocess harness follows the same general isolation pattern as the supplied example. No claim of an independent comparison against an unrelated archive is made.

The code and documentation were drafted with AI assistance. The prose was edited for direct, natural wording. No human-authorship or model-failure certification is attached to this package.

The implementation uses Python's standard library. The HMAC interface and constant-time comparison follow the [Python documentation](https://docs.python.org/3/library/hmac.html). The task layout follows [Harbor's task documentation](https://docs.harborframework.com/tasks/overview). The capability and resource rules are local to this lab; they do not claim to reproduce a cloud provider's policy language.

The two Dockerfiles reference a digest-pinned Python image. Obtaining an uncached base image or installing Harbor can require network access during setup. Agent and verifier execution use the no-network policy declared in `task.toml`.
