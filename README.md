# PhishGuard — Phishing URL Detection

## What it does
  Detects phishing URLs using engineered URL & domain features. Includes:
- reproducible training with stratified split + CV hyperparameter search
- PR-AUC / ROC-AUC evaluation
- decision-threshold tuning to reduce false negatives
- FastAPI inference API + Docker
- tests + CI

## Train
   "```bash"
python train_model.py

## Run API
uvicorn src.phishguard.api:app --reload --port 8000

## Docker
docker build -t phishguard .
docker run -p 8000:8000 phishguard
