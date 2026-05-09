# Tests

```
tests/
  test_mcp_tools.py     Unit tests — mocked, no credentials needed, CI-safe
  integration/
    skd_tests.py        Integration tests — require live SaaS credentials
    README.md           Per-platform env var reference
```

## Unit tests

```bash
python -m unittest tests.test_mcp_tools
```

## Integration tests

```bash
python tests/integration/skd_tests.py          # all platforms
python tests/integration/skd_tests.py jira     # single platform
```

See `tests/integration/README.md` for the full env var reference.
