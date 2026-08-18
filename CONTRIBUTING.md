# Contributing to LAN Scan

Thanks for your interest. This is a small, focused tool; contributions that keep
it that way are the most welcome.

## Development

```bash
cargo build            # debug build
cargo test --all       # unit + end-to-end tests
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
```

All four must pass before a change is ready - CI runs exactly these gates.

## Guidelines

- **Keep the dependency tree small.** New runtime dependencies need a clear
  justification in the PR description.
- **No `unsafe`.** The crate is `#![forbid(unsafe_code)]`; keep it that way.
- **Document public items.** `missing_docs` is a warning; new public API needs a
  doc comment.
- **Add tests** for new behavior. Parsing and protocol logic should be unit-
  testable without a live network (see `src/arp.rs` and `src/mcp.rs` for the
  pattern of splitting pure logic from I/O).

## Scope

LAN Scan discovers hosts, ports, and vendors on a local network without root.
Features that require raw sockets/root, target the public internet, or add heavy
dependencies are out of scope. Open an issue to discuss before building.

## Commit and PR

- Branch from `main` (`feat/...` or `fix/...`).
- Keep PRs focused and small.
- Reference any related issue.
