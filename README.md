# ShopSecure: Cloud Shopping + Real-Time Login Threat Detection

An Amazon-style shopping website where **every login and user action is streamed through a
log pipeline into an ML model** that labels it **Normal**, **Suspicious** or **Malicious**.
Users never see the ML internals, only the results: graphs, risk scores and evaluation metrics.

| What the user does | What happens in the cloud app |
|---|---|
| Registers, signs in, browses, adds to cart, checks out | Each action becomes a log event → queue → stream worker → ML model → stored + logged |
| Picks **services** (SaaS catalogue) | Turns on the features they need: live protection, file analyzer, URL import, alerts |
| Feeds logs in one of **3 ways** | ① live pipeline ② file upload ③ import from a URL / public dataset |
| Opens the **Security Console** | Sees charts, KPIs, flagged events, accuracy / precision / recall / confusion matrix |

**Demo login:** `demo` / `demo123` (all services on, with sample activity already in the live feed).

---

## 1. Run it locally (2 minutes)

```bash
python -m venv venv && source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py                                         # first start trains the model (~10 s)
```
Open http://localhost:5000, sign in as `demo` / `demo123`, then open **Security Console**.

## 2. Deploy it (about 5 minutes, free, no cloud setup)

**Render (recommended, easiest)**
1. Push this repo to GitHub (already done if you're reading this there).
2. Go to https://dashboard.render.com → **New** → **Blueprint** → pick this repo.
   Render reads `render.yaml` and builds it automatically: installs deps, pre-trains the model, starts gunicorn.
3. Wait for "Live" and open the `https://shopsecure-xxxx.onrender.com` URL. Done.
   - Logs (including every detection as JSON) are in the service's **Logs** tab: that's your cloud monitoring.
   - Free instances sleep after 15 minutes idle, so the first request takes ~50 s to wake up. Open it 1 minute before your demo.
   - Free instances have no persistent disk, so data resets on redeploy. That's fine for a demo; the `demo` account is re-seeded automatically.

**Any Docker host** (Google Cloud Run, AWS App Runner, Railway, Azure Container Apps, Hugging Face Spaces):
```bash
docker build -t shopsecure .
docker run -p 8080:8080 shopsecure
# Cloud Run:  gcloud run deploy shopsecure --source . --allow-unauthenticated --region asia-south1
```

## 3. The three ways to feed logs

1. **Live pipeline**: the store itself. Sign out and type a wrong password a few times, or press one of the
   **Attack simulator** buttons (brute force, credential stuffing, vulnerability scan, request flood, account takeover)
   and watch the live charts react within seconds.
2. **Upload a file**: CSV (`timestamp, ip` + optional `user, action, success, user_agent, path, status, label`),
   SSH/Linux auth logs (`/var/log/auth.log`), Apache/Nginx access logs; `.gz` is fine.
   A labelled sample is at `static/samples/sample_login_events.csv`.
3. **Import from a URL**: paste any public link (S3/GCS public object, GitHub raw), or pick a curated dataset:

| Dataset | Direct URL (works in the app) | What's inside |
|---|---|---|
| ShopSecure labelled sample | built in | ~9.4k store events **with true labels**, so you get accuracy etc. |
| Loghub OpenSSH | https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log | Real SSH server under brute-force attack |
| Loghub OpenSSH (CSV) | https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log_structured.csv | Same, pre-parsed |
| Loghub Linux syslog | https://raw.githubusercontent.com/logpai/loghub/master/Linux/Linux_2k.log | PAM auth failures, sessions |
| Elastic Apache access logs | https://raw.githubusercontent.com/elastic/examples/master/Common%20Data%20Formats/apache_logs/apache_logs | 10k real web requests incl. bots/scanners |

Bigger datasets for your report (download them, then upload or host them yourself):
[Loghub full collection](https://github.com/logpai/loghub) ·
[RBA login dataset (33M logins, Kaggle)](https://www.kaggle.com/datasets/dasgroup/rba-dataset) ·
[SecRepo security logs](https://www.secrepo.com/) ·
[LANL authentication data](https://csr.lanl.gov/data/cyber1/) ·
[CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) (network flows; needs your own model).

## 4. Architecture

```
 Browser ──HTTPS──► Flask web app (gunicorn, Render / Cloud Run)
                     │  store, auth, services, console
                     │
   producers ────────┤ after_request hook + attack simulator
                     ▼
              EventBus queue  (in-process; swap for SQS / Pub/Sub / Kinesis)
                     ▼
           Stream worker thread: sliding-window features per IP / user
                     ▼
           ML detector: RandomForest (3 classes) + IsolationForest (anomaly)
                     ▼
    ┌────────────────┼──────────────────────┬────────────────────────┐
 SQLite DB      JSON logs on stdout     logs/detections.jsonl    Discord/Slack
 (events,       (Render Logs / Cloud    (audit trail)            webhook alerts
  reports)       Logging / CloudWatch)
```

| Path | Purpose |
|---|---|
| `app.py` | Web app: store, auth, services, console, APIs, `/health` |
| `pipeline/bus.py` | Queue + stream-processing worker (the log pipeline) |
| `pipeline/sinks.py` | Structured cloud logging, audit file, webhook alerts |
| `ml/features.py` | Event → features (failed logins/IP, distinct users/IP, new device, bot UA, …) |
| `ml/engine.py` | Train / load / predict / evaluate |
| `ml/parsers.py` | CSV, SSH/syslog and Apache/Nginx log parsers |
| `ml/synth.py` | Labelled training data + attack simulator |
| `analytics.py` | Aggregations for the charts |
| `render.yaml`, `Dockerfile`, `gunicorn.conf.py` | Deployment |

### Plugging in your own ML model
If your team already has a trained model, replace `Detector.predict()` in `ml/engine.py`.
It receives a list of feature dicts (`ml/features.FEATURES`) and must return
`[{"label": "Normal|Suspicious|Malicious", "risk": 0-100, "reason": "..."}]`. Everything else
(pipeline, dashboards, metrics) keeps working.

## 5. Model quality
Measured on 21k held-out events: **98.8% accuracy, 98.2% of threats caught, 0.86% false alarms, ROC-AUC 0.997**.
On the separately generated labelled sample: 95.6% accuracy. See **Console → Model quality** in the app.

## 6. Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `SECRET_KEY` | random | Session signing key (Render generates one) |
| `DEMO_PASSWORD` | `demo123` | Password of the auto-created `demo` account |
| `TZ_OFFSET_HOURS` | `5.5` | Local time zone for "night-time login" features (IST) |
| `DATABASE_PATH` | `instance/shopsecure.db` | SQLite file (point at a mounted disk to persist) |
| `MAX_UPLOAD_MB` | `25` | Upload / download size limit |

## 7. Tests
```bash
pip install pytest && pytest -q
```

See **[docs/CLOUD_CONCEPTS.md](docs/CLOUD_CONCEPTS.md)** for how each cloud-computing concept is covered and what to say in your viva.
