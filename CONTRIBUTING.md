# Contributing

Thanks for looking. SecureSend is small on purpose, and contributions that keep
it small are the most welcome kind.

## Before you start

- **Security issues go to [SECURITY.md](SECURITY.md)**, not to an issue.
- Open an issue before a large change so we can agree on the shape first.
- Read [docs/security-model.md](docs/security-model.md). A change that weakens
  an invariant there will not be merged, however useful it is otherwise.

## Building and testing

```
cd web && npm ci && npm run build && cd ..
cargo build
cargo test
cd web && npm test && npx playwright install chromium && npm run e2e
```

`cargo fmt --all` and `cargo clippy --all-targets -- -D warnings` must both be
clean; CI enforces them.

## What a good change looks like

- One concern per pull request.
- Tests for behavior, not for coverage numbers. A new failure mode in the
  consume path needs a test proving the response is byte-identical to the
  others.
- No new runtime dependency without a sentence in the PR saying why the
  standard library or an existing dependency could not do it.
- No new third-party origin in the interface. The Content Security Policy is
  `'self'` and stays that way.
- Comments explain why, not what.

## Commit messages

Describe what the change does and why a reader outside this repository would
care. No ticket numbers from other systems, no severity tags, no references to
plans.

## Licensing

By contributing you agree that your contribution is licensed under the
Apache License 2.0, the same license as the project.
