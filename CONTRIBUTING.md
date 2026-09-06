# Contributing

## Setup

```bash
uv venv
uv pip install -e .
source .venv/bin/activate
python -m unittest discover -s tests -v
```

## Pull requests

1. Branch from `main`.
2. Keep protocol and authority changes explicit.
3. Add focused negative tests before widening behavior.
4. Run:

```bash
python -m unittest discover -s tests -v
python -m compileall -q src tests
uv build
```

5. Sign off commits with `git commit -s`.

## What we want

- stronger deterministic snapshot verification;
- platform-contained resource controls;
- clearer typed failures and receipts;
- reproducible owner installation and rollback;
- tests for tamper, replay, collision, and unavailable-owner behavior.

## What we do not want

- arbitrary shell or caller-selected remote paths;
- `StrictHostKeyChecking=no`;
- ambient credential discovery;
- hidden local fallback;
- permissive request parsing;
- claims that remote execution is universally faster or production-certified.
