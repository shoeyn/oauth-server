# End-to-End Cucumber Specs

Cucumber feature specs for the OAuth 2.1 / OIDC platform.

> **Scope note:** These specs assert **UI-level outcomes** (page content, flash messages, redirects, and visible authentication state) exercised through the browser-facing flow. They do not independently verify the underlying cryptographic guarantees (DPoP binding, PAR, JARM), which are covered by the functional test suites under `*/functional_tests/`.

## Running

```bash
# List all steps without executing (also validates no undefined/pending steps under --strict)
mise exec -- bundle exec cucumber --dry-run

# Full run (default profile applies --publish-quiet --strict)
mise exec -- bundle exec cucumber
```

The default profile in `cucumber.yml` runs with `--strict`, so any undefined or pending step fails the run.
