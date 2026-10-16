# AI ScamShield

AI ScamShield is a web application for checking suspicious text messages, pasted emails and URLs. A user submits a message or a link and gets back a risk classification, the specific warning signs that were found, a plain-language explanation and suggested next steps. The aim is to help people pause and recognize common scam patterns, not to give a verdict they should rely on blindly.

It is a portfolio project by Soham Shah.

## Status

Early development. The repository foundation (skeletons, CI and health endpoints) is in place, but no analysis features exist yet. Nothing is deployed. There is no live demo, no trained model and no published evaluation. Everything below describes the plan, and any detail may change as the work progresses.

## What it will do

- Accept a pasted message (SMS, email text, chat) or a single URL.
- Return one of four outcomes: likely legitimate, suspicious, high risk, or inconclusive.
- List the signals behind the result, such as urgency, requests for credentials or payment, or an unusual link.
- Report URL reputation results when a lookup is available, and say plainly when it is not.
- Offer a short, plain-language explanation and practical recommendations.
- Always state its limitations. A low-risk result is not proof that something is safe.

## How it will work

Each request passes through a fixed pipeline:

1. Input validation: size and length limits, character normalization, strict URL parsing, rejection of unsupported schemes, rate limiting.
2. Rule signals: deterministic checks for known scam patterns in the text and in the URLs found in it.
3. Baseline text classifier: TF-IDF features with a linear model, trained on public labeled data and evaluated on a held-out test set.
4. URL reputation lookup: a backend-only call to a reputation provider. A timeout or failure is reported as unknown.
5. Evidence aggregation: a transparent, testable layer that combines the signals into a classification. It does not blend unrelated scores into one number.
6. Explanation: the Gemini API turns the structured evidence into a short explanation. If the API is unavailable, unconfigured or returns something that fails validation, a fixed template is used instead. The explanation cannot change the classification.

## Design principles

- It never says a message or URL is guaranteed safe.
- An unknown or failed check is never shown as safe.
- Submitted URLs are never visited, and their hosts are never resolved by the server.
- Submitted content is treated as untrusted data, never as instructions.
- Only the minimum data needed to run the service is kept.
- Any figure published here will come from a documented evaluation, not from estimates.

## Planned stack

- Frontend: Next.js, TypeScript, Tailwind CSS
- Backend: Python, FastAPI
- Machine learning: scikit-learn
- Database: PostgreSQL
- Explanations: Gemini API
- Packaging and infrastructure: Docker, Terraform, AWS
- CI: GitHub Actions

## Planned repository layout

```
frontend/         Next.js application
backend/          FastAPI service and analysis pipeline
ml/               training and evaluation code
tests/            contract, end-to-end and load tests
infrastructure/   Terraform
scripts/          development helpers
```

## Roadmap

1. Repository foundation: skeletons, linting, CI, health endpoints.
2. Database schema and retention rules.
3. Analysis API and web interface using rule signals only.
4. Baseline classifier with a documented evaluation.
5. URL reputation lookup and Gemini explanations.
6. Test suites, observability and hardening.
7. Staging deployment on AWS, then a clearly labeled public beta.

## Privacy

What is processed: the text or URL you submit, for the length of the request, to produce a result.

What is not stored: the submitted text, extracted excerpts, the URLs or their hosts, raw IP addresses, and user agents. The plan is to keep only derived fields (classification, signal identifiers, timings, versions).

What leaves the service:

- URLs found in a submission are sent to the URL reputation provider so they can be checked.
- The Gemini API receives only structured evidence (signal identifiers and descriptions, the classification, URL check statuses and threat types). It does not receive the message text or the URLs.

Do not paste anything you are not comfortable having checked against a third-party reputation service. This section will be updated once the implementation exists.

## Local development

Prerequisites: Python 3.12 or newer, [uv](https://docs.astral.sh/uv/), Node.js 20 or newer, and Docker.

Copy the example environment file before running anything that reads configuration:

```
cp .env.example .env
```

Backend (http://localhost:8000):

```
cd backend
uv sync
uv run uvicorn app.main:app --reload
```

Frontend:

```
cd frontend
npm ci
npm run dev
```

PostgreSQL and the backend together, using Docker (the credentials in `docker-compose.yml` are for local use only):

```
docker compose up
```

Checks:

```
# backend, from backend/
uv run ruff check .
uv run ruff format --check .
uv run mypy app
uv run pytest -q
uv run pip-audit

# frontend, from frontend/
npm run lint
npm run format:check
npm run typecheck
npm test
npm run build
npm audit --omit=dev --audit-level=high
```

## Reporting security issues

Please report vulnerabilities privately through GitHub's private vulnerability reporting (the "Report a vulnerability" button on the repository's Security tab). Do not post exploit details in a public issue, and allow reasonable time for a response.

## License

MIT. See [LICENSE](LICENSE).
