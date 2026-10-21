# AI ScamShield

AI ScamShield is a web application for checking suspicious text messages, pasted emails and URLs. A user submits a message or a link and gets back a risk classification, the specific warning signs that were found, a plain-language explanation and suggested next steps. The aim is to help people pause and recognize common scam patterns, not to give a verdict they should rely on blindly.

It is a portfolio project by Soham Shah.

## Status

Early development. The analysis API and the web page work end to end. A baseline text classifier can be trained locally from public datasets; the backend uses it only when a model file with a matching checksum is configured, and otherwise runs on rule signals alone. There is no URL reputation lookup yet, so links are reported as not checked. How well the classifier handles real current-style messages has not been measured yet, so its results are not yet reliable (see Limitations below). Nothing is deployed. There is no live demo and no published evaluation. Everything below describes the plan, and any detail may change as the work progresses.

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

## Limitations of the text classifier

- It is trained on English SMS collections from 2011 to 2022. Email, chat and recent scam styles are outside what it has seen.
- Older spam collections include ordinary marketing, so "spam" is not the same as "scam".
- Its training also includes a few hundred invented current-style messages written for this project. Local checks on similar invented messages look much better than with the public data alone, but those checks share the same author, and performance on real current messages has not been measured.
- It still flags some genuine business notifications as suspicious.
- Its score is an uncalibrated heuristic, not a probability.

## Privacy

What is processed: the text or URL you submit, for the length of the request, to produce a result.

What is not stored: the submitted text, extracted excerpts, the URLs or their hosts, raw IP addresses, and user agents. Each analysis keeps only derived fields (classification, signal identifiers, counts, timings, versions) for 90 days. Rate limiting stores a keyed hash of the client address, never the address itself, for 48 hours.

What leaves the service:

- URLs found in a submission are sent to the URL reputation provider so they can be checked.
- The Gemini API receives only structured evidence (signal identifiers and descriptions, the classification, URL check statuses and threat types). It does not receive the message text or the URLs.

Neither third-party call is enabled yet: links are currently reported as not checked, and explanations come from fixed templates. Do not paste anything you are not comfortable having checked against a third-party reputation service once lookups are enabled.

## Local development

Prerequisites: Python 3.12 or newer, [uv](https://docs.astral.sh/uv/), Node.js 20 or newer, and Docker.

The simplest setup runs PostgreSQL, the migrations and the backend in Docker (http://localhost:8000; the credentials in `docker-compose.yml` are for local use only):

```
docker compose up --build
```

Then start the frontend (http://localhost:3000). In development it forwards `/api/*` to the backend on port 8000:

```
cd frontend
npm ci
npm run dev
```

To run the backend outside Docker instead, point it at a PostgreSQL database you control. The backend reads `backend/.env`; when `APP_ENV` is not set it assumes production and refuses to start without a database URL and a strong `CLIENT_ID_HASH_KEY`:

```
cp .env.example backend/.env    # then edit DATABASE_URL
cd backend
uv sync
uv run alembic upgrade head
uv run uvicorn app.main:app --reload
```

To train the baseline classifier (Python 3.12, from `ml/`). The fetch step downloads the two public datasets listed under Data sources and refuses any file whose checksum differs from the pinned value; the datasets are never committed:

```
cd ml
uv sync
uv run python -m scamshield_ml.fetch
uv run python -m scamshield_ml.train
```

The training run prints the model file's SHA-256. To let the backend use the model, set `MODEL_ARTIFACT_SHA256` to that value: in `.env` at the repository root for `docker compose` (which mounts `ml/artifacts` read-only), or in `backend/.env` together with `MODEL_ARTIFACT_PATH=../ml/artifacts/current/model.joblib` when running uvicorn from `backend/`. Without a matching checksum the model is not loaded and `/readyz` reports `"model": "not_loaded"`.

Checks:

```
# ml, from ml/
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest -q
uv run pip-audit

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

## Data sources

The baseline classifier is trained and evaluated on these datasets. They are downloaded by the training scripts and not redistributed by this repository.

- SMS Spam Collection. Almeida, T. & Hidalgo, J. (2011). UCI Machine Learning Repository. https://doi.org/10.24432/C5CC84. Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
- SMS Phishing Dataset for Machine Learning and Pattern Recognition. Mishra, S. & Soni, D. (2022). Mendeley Data, V1. https://doi.org/10.17632/f45bkkt8pr.1. Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

The training data also includes a set of invented current-style messages written for this project (`ml/supplement/`), covered by the repository license.

Changes made to the public datasets: labels mapped to two classes (ham as not scam-like; spam and smishing as scam-like), text Unicode-normalized, and duplicate messages across the two datasets merged.

## Reporting security issues

Please report vulnerabilities privately through GitHub's private vulnerability reporting (the "Report a vulnerability" button on the repository's Security tab). Do not post exploit details in a public issue, and allow reasonable time for a response.

## License

MIT. See [LICENSE](LICENSE).
