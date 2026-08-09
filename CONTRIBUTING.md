# Contributing to IronVeil

## Ground rules

IronVeil sits in the data path of databases holding personal data. Two failure
modes matter more than anything else, and both are worse than an outage:

1. **Leaking** — a value an explicit rule covers reaching the client unmasked.
2. **Corrupting** — the proxy rewriting or truncating a value nothing asked it
   to touch. An agent reasoning over silently wrong data is worse than one
   seeing a masked field.

Changes are judged against those first.

## Development

```bash
cargo build
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings

cd web && npm ci && npm run lint && npm test && npm run build
```

End-to-end masking (manages its own containers):

```bash
./scripts/test_e2e.sh all
```

## Conventions

- **No `unwrap()`/`expect()` in production paths.** Handle `Result` and
  `Option`, and propagate with `?`. Compile-time constants in `LazyLock`
  initializers are the accepted exception.
- **All I/O is non-blocking.** Blocking work belongs in `spawn_blocking`.
- **Protocol code is tested.** Every codec change needs a decode/encode test.
  For any packet type the proxy does not intentionally modify, that means a
  **byte-equality round trip** — decode a captured packet, encode it, assert
  the bytes are identical. Three separate bugs shipped because a packet was
  rebuilt from parsed fields and quietly lost what the parser did not model.
- **Never re-encode what you did not change.** Parse for rule matching and
  logging; forward the original bytes.
- **Fail closed on the control plane, fail visible on the data path.** Refuse
  to serve the management API without credentials; when an unmasked path is
  unavoidable (COPY, binary protocol), log it and emit a metric rather than
  letting it pass silently.
- **Never log a pre-masking value.** Log the column, strategy and length.

## Pull requests

- Keep changes scoped and explain *why* in the commit body — the defect being
  fixed, not just the edit.
- Add or update tests in the same commit as the behaviour change.
- Update `CHANGELOG.md` under `[Unreleased]`, and the README when behaviour or
  configuration changes.
- Security-relevant reports should follow `SECURITY.md` instead of a PR.
