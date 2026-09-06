# CYCLOPS — Setup & Quickstart

Integrated on the **`develop`** branch. Everything below runs **offline** (no downloads)
because the trained DGA model and eval results are committed.

## 1. Clone & branch

```bash
git clone https://github.com/Pranav4012/-CYCLOPS.git
cd -CYCLOPS
git checkout develop
```

## 2. Install (engine only — just numpy)

```bash
pip install -r reference-impl/requirements.txt
```

## 3. Run it

```bash
cd reference-impl

python demo.py                 # end-to-end: synth traffic -> detect -> tamper proof
python -m eval.run_eval 30     # the headline evals -> eval/results/metrics.json
pip install pytest && python -m pytest -q      # 37 tests
python -m eval.ci_gate         # regression gate (F1 / false-alarm / DGA AUC)
```

Ingest a real capture:

```bash
python -m eval.make_pcaps                      # write sample pcaps
python -m halfsight.ingest pcaps/mixed.pcap    # run the pipeline on one
python -m halfsight.ingest big.pcap --stream   # bounded-memory streaming
```

## 4. Optional — things that DO need a download

Datasets/pcaps are gitignored on purpose. Only these two commands need them:

```bash
./datasets/fetch_datasets.sh   && python -m eval.train_dga      # retrain the DGA model
./pcaps/real/fetch_real_captures.sh && python -m eval.validate_real   # 8/8 real captures
```

## 5. Optional — the backend API (Person 2)

Has its own dependencies (FastAPI, etc.):

```bash
pip install -r reference-impl/backend/requirements.txt
cd reference-impl/backend && uvicorn app.main:app --reload
```

## Layout

```
reference-impl/
├── halfsight/        # the engine (8 cores) — the real detector
├── eval/             # eval harness + regression gate + trained-model metrics
├── tests/            # 37 pytest tests
├── backend/          # FastAPI service bridging UI <-> engine
└── demo.py
product/              # console / dossier / eval report (HTML)
decisions.md · progress.md · handoff.md
```

## Branching

- Base everything on **`develop`**. Open PRs into `develop`, not `main`.
- `main` only advances from a green `develop`.
- CI (`.github/workflows/ci.yml`) runs tests + eval + the regression gate on every push/PR.
