# Contributing to shoji

Thank you for your interest. Reviews of the circuit's constraints, corrections
to our assumptions about JPKI certificates, and bug reports are all welcome.
Issues and pull requests may be written in English or Japanese.

## Rules that are not negotiable

1. **No real personal data, anywhere.** Never put a real person's certificate,
   name, address, date of birth, PIN, or anything derived from a real card into
   code, test data, logs, issues, pull requests or commits, including your own.
   Use the mock CA (`cmd/mockca`). If you need to describe the structure of a
   real certificate, describe the structure (tags, lengths, OIDs), not the
   contents.
2. **Do not log witnesses or certificate contents.**
3. **Do not guess specifications.** OIDs, APDUs, field positions and the like
   that have not been confirmed go into `docs/open-questions.md` with their
   status, not into the code as facts. When you confirm one, cite the source.
4. **No hand-rolled cryptography.** Use existing, pinned libraries for RSA,
   hashing and big-integer arithmetic.
5. **Pin dependency versions** (tags in `circuits/Nargo.toml`, `go.mod`, tool
   versions in the README and CI).

## Changing the circuit

Under-constrained circuits are the most common class of ZK vulnerability, so:

- For every constraint you add or change, add a negative test showing that a
  proof cannot be produced when the value is falsified. Make each negative test
  a passing case with exactly one thing changed.
- Do not take positions, offsets or selectors as witness inputs unless the
  circuit fully constrains them from signed data. Avoid `unconstrained` code; if
  it is unavoidable, explain in the pull request how every returned value is
  constrained.
- Nothing that feeds the nullifier may be freely chosen by the prover.
- If you change a public input or output, the message format, or a hash, update
  `internal/proto` and the verifier to match, and regenerate the verification key.
- Update `docs/threat-model.md` when the set of attacks or guarantees changes.

## Development

Install the pinned tools as described in the [README](README.md), then:

```sh
make circuit   # fixtures + compile + verification key
make test      # nargo test + go test
gofmt -l . && go vet ./...
```

`make` creates the mock CA and certificates under `testdata/` on first use.
They are ignored by git on purpose; do not commit them.

## Pull requests

- Keep changes focused, and describe what you changed and how you tested it.
- `make test` must pass. Go code must be `gofmt`-clean and pass `go vet`.
- English documents under `docs/` are authoritative. If you change one, please
  update the Japanese version in `docs/ja/` too, or say in the pull request that
  it still needs updating.

## Security issues

Please do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).
