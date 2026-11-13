# Proposed v0.7.0 catalog disclosure

This text describes the separate settings/tool-matcher candidate. Catalog PR #155058 remains draft and still pins merged v0.6.0. It must not be read as an installation claim for this version.

Sentinel Governance is experimental, audit-first deterministic action governance. Active-profile Hermes plugin settings select audit/enforce and a custom policy under that profile's home. Settings are read on each call; the environment can tighten audit to enforce but cannot loosen settings enforce. Invalid modes fail closed. Unsafe/unparsable configured policy observes in audit and blocks in enforce, without falling back to bundled rules. Registration and report show mode and source without policy contents/private paths.

Optional exact tool names narrow policy rules. Unknown-operation allows require named tools and reject terminal/execute_code. An allow grants the **whole tool**; arguments, paths and server capabilities are not inspected. A named MCP/plugin tool can perform any operation its implementation permits, and naming it is an operator trust decision. This is not a shell sandbox, network boundary or capability attestation; other host/plugin protections still apply. Hard denies override all other rules, equal-priority approval beats allow, and invalid destinations remain blocked. Journal tool names remain terminal/other.

The runtime hook inspects arguments in memory, reads policy and an audit key, and writes a sanitized local JSONL journal. It starts no network request or subprocess. User-invoked counts-only replay uses the same matcher against a selected current policy and makes private temporary raw history copies; deletion is best effort, not secure erasure. SIGKILL of both processes, power loss and filesystem errors can leave files. Eligible marked, private, unleased leftovers older than 60 seconds are swept; unmarked directories are deliberately preserved. The README contains complete storage and history-coverage limits.

The Hermes-bundled `hermes_yaml` rule-9 catalog warning remains disclosed pending maintainer guidance. No production enforcement is enabled by preparing this candidate.
