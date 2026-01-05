# Contributing

Thanks for your interest in improving this project.

## Development setup

Prereqs: Docker + Docker Compose.

```bash
cp .env.example .env
docker compose up --build
```

API docs: `http://localhost:8000/docs`

## Tests

```bash
python3 -m pip install --upgrade pip
python3 -m pip install pytest
pytest
```

## Pull requests

- Keep changes focused and small.
- Prefer security-by-default settings.
- If you change Terraform, run `terraform fmt -recursive infra`.
- If you change the API contract, update `README.md`.

