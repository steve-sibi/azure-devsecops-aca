# Contributing

Thanks for your interest in improving this project! I welcome contributions of all kinds.

## Code of Conduct

Please be respectful and constructive. We're all here to learn and build something useful.

## Development Setup

**Prerequisites**: Docker + Docker Compose, Python 3.11+

```bash
# Clone and start locally
git clone https://github.com/steve-sibi/azure-devsecops-aca.git
cd azure-devsecops-aca
cp .env.example .env
docker compose up --build
```

- API docs: `http://localhost:8000/docs`
- Dashboard: `http://localhost:8000/`

## Running Checks Locally

```bash
python3 -m pip install --upgrade pip
python3 -m pip install -r app/api/requirements.txt -r app/worker/requirements.txt pytest
pytest -q
ruff check .
terraform fmt -check -recursive infra
actionlint -color .github/workflows/*.yml
```

## Code Style

- **Python**: I use [Ruff](https://docs.astral.sh/ruff/) for linting and formatting
- **Terraform**: Run `terraform fmt -recursive infra` before committing
- **Commits**: Use clear, descriptive commit messages

## Protected Main Workflow

`main` is protected, so direct pushes are blocked. Please use this flow:

1. Sync `main`

```bash
git switch main
git pull --ff-only
```

2. Create a focused branch from `main`

```bash
git switch -c feat/<scope>-<topic>
# or fix/<scope>-<topic>
# or chore/<scope>-<topic>
```

3. Commit and push your branch

```bash
git add <files>
git commit -m "type(scope): concise summary"
git push -u origin <branch-name>
```

4. Open a PR to `main`, wait for required checks, and merge with **Squash and merge**.

Note: CI now triggers for docs-only and markdown-only changes as well, so docs PRs can satisfy required checks and merge normally.

## Pull Request Guidelines

1. **Keep changes focused** — One feature or fix per PR
2. **Add tests** — If you're adding functionality, include tests
3. **Update documentation** — If you change the API or config, update README.md
4. **Security-first** — Prefer secure defaults; don't disable protections without good reason
5. **Run checks locally** — Ensure relevant checks are clean before opening a PR

## What We're Looking For

- Bug fixes with clear reproduction steps
- Security improvements
- Documentation clarifications
- Performance optimizations (with benchmarks)
- New scan analysis features (with tests)

## Reporting Issues

- **Bugs**: Open an issue with reproduction steps
- **Security vulnerabilities**: See [SECURITY.md](SECURITY.md) — do not open a public issue

## Questions?

Open a discussion or issue. I'm happy to help and learn!
