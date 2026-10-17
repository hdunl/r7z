# Contributing

Thanks for helping out. Bug reports, format samples that r7z gets wrong, and pull requests
are all welcome.

## Reporting bugs

Use the [bug report form](https://github.com/hdunl/r7z/issues/new?template=bug_report.yml).
An archive that shows the problem is the most useful thing you can include; if it is
private, a description of how it was made (tool, version, options) is the next best.
Security problems go through [private reporting](SECURITY.md) instead.

## Building

You need Rust 1.95 or newer with the MSVC toolchain.

```bash
cargo build --release          # target/release/r7z.exe and r7z-gui.exe
cargo test --release           # unit, round-trip and fixture tests
cargo clippy --workspace       # should print no warnings
```

`scripts/interop.sh target/release/r7z 7z` runs the two-way compatibility matrix against
an installed 7-Zip. The source layout is described in
[docs/development.md](docs/development.md).

## Pull requests

- Keep each pull request to one change, and include a test when you fix a bug or add a
  format. Fixture archives go in `tests/fixtures/`; keep them small and make sure you are
  allowed to share them.
- Archives are untrusted input. New parsing code must not panic, allocate without a bound,
  or write outside the destination, whatever the archive says.
- Match the style of the code around your change, and run `cargo fmt`.
- CI must pass: build, tests, clippy and the dependency audit.

By submitting a pull request you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE), like the rest of the project.
