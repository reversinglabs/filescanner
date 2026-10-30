# Contributing

Contributions are welcome — bug reports, feature requests, and pull requests.
This project is licensed under the MIT License; see [LICENSE](LICENSE). By
submitting a contribution you agree it will be distributed under the same
license.

## Ground rules

- **Dual-implementation parity (mandatory).** `filescanner.py` (Python) and
  `go/` (Go) are two implementations of the same scanner that must stay in
  lockstep. Any behavior, config or bugfix change applies to **both** in the
  same change, or the diff must explain why it cannot apply. See AGENTS.md
  for the full parity checklist.
- **No secrets.** `config.ini` is gitignored and must never be committed;
  secrets come from environment variables via `${VAR}` expansion.
- **Commit style:** Conventional Commits (`type(scope): description`), one
  logical change per commit.

## Development setup

```bash
# Python — system python3 is used for tests
python3 -m pytest tests/ -q

# Go
cd go && gofmt -l . && go vet ./... && go build ./...

# Cross-compiled binaries -> dist/
make
```

## Testing

- Unit tests: `python3 -m pytest tests/ -q` and `cd go && go test ./...`
- Live end-to-end tests (require credentials and running services):

  ```bash
  ./tests/e2e_live.sh            # full suite, py + go
  ./tests/e2e_fie_up.sh          # start local FIE container first
  ```

  Credentials are sourced from the dotenv files in `FILESCANNER_ENV_FILES`
  (colon-separated; default `~/.env`); see `tests/test_e2e_live.py` for
  the `FILESCANNER_E2E_*` variables.

## Submitting changes

1. Make the change in both implementations (see parity rule).
2. Update `config.ini.template` (root and `go/`) and README when adding or
   renaming config keys.
3. Run the verification commands above; run `tests/e2e_live.sh` when pipeline
   behavior changes.
4. Add a CHANGELOG.md entry under the next version heading.
5. Open a pull request against the default branch.
