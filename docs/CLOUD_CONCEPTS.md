# Cloud computing concepts in ShopSecure

Each row says which concept is covered, where it is in the code, and the quickest way to show it in a demo.
Rows marked ⭐ are optional upgrades that take 10-30 minutes each, if your evaluator wants "real" managed services.

| # | Concept | Where / how | How to demo it |
|---|---|---|---|
| 1 | **SaaS (Software as a Service)** | The whole app: users sign up and use security analytics in the browser, nothing to install | Register a new user live |
| 2 | **PaaS deployment** | `render.yaml`: Render builds, runs and serves it over HTTPS; you never touch a server | Show the Render dashboard + public URL |
| 3 | **On-demand self-service** (NIST) | `/services`: users add/remove services themselves and they activate instantly | Add "Cloud Log Import", the console unlocks option 3 |
| 4 | **Multi-tenancy** | One app instance, many users; every event/report is tagged with its tenant and isolated (`tenant` column, `_own_analysis`) | Log in as two users: each sees only their own data |
| 5 | **Containerization** | `Dockerfile` (model is pre-trained at build time, `HEALTHCHECK` included) | `docker build` / Cloud Run deploy |
| 6 | **Data pipeline / message queue / stream processing** | `pipeline/bus.py`: producer → queue → micro-batch consumer → model → storage (same pattern as Kinesis/SQS + Lambda) | Live monitor → pipeline status strip; press an attack button |
| 7 | **Real-time analytics** | Sliding-window features per IP/user, scored in < 100 ms | Watch charts update every 3 s |
| 8 | **Cloud logging & monitoring** | `pipeline/sinks.py`: JSON logs to stdout, automatically collected by Render Logs / Cloud Logging / CloudWatch; `/health` endpoint used by the platform health check | Render → Logs tab, filter `MALICIOUS` |
| 9 | **Event-driven notifications** | Discord/Slack webhook on Malicious events (Instant Threat Alerts service) | Paste a Discord webhook, run brute-force simulation, phone buzzes |
| 10 | **Storage / data persistence** | SQLite (events, reports), JSONL audit log, CSV/JSON report export | Download a report CSV |
| 11 | **Elasticity & scalability** | Stateless web tier behind gunicorn threads; the pipeline is isolated behind a publish/consume interface so the queue can move to a managed service and workers can scale independently | Explain the ⭐ upgrades below |
| 12 | **Security in the cloud** | Hashed passwords, CSRF tokens, HTTP-only cookies, HTTPS by the platform, tenant isolation, SSRF protection on URL import (blocks private IPs), upload size limits | Try importing `http://127.0.0.1`: blocked |
| 13 | **Broad network access / resource pooling** | Responsive UI on phone and laptop; many tenants share one pool of compute and one model | Open on your phone |

## ⭐ Quick upgrades (only if you need them)

| Upgrade | Time | Steps |
|---|---|---|
| **Persistent managed database** | 10 min | Render → New → PostgreSQL (free), or Render Disk ($) mounted at `/data` and set `DATABASE_PATH=/data/shopsecure.db`. A Disk needs zero code changes. |
| **Object storage for reports (S3)** | 20 min | `pip install boto3`; in `run_analysis()` call `boto3.client("s3").put_object(Bucket=..., Key=f"reports/{aid}.json", Body=json.dumps(summary))`; set `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` env vars on Render. |
| **Managed queue (Redis)** | 30 min | Render Key Value (free Redis) → in `EventBus.publish` use `redis.rpush("events", json.dumps(e))` and in `_run` use `redis.blpop`. Then run the worker as a separate Render *Background Worker* and scale web instances > 1. |
| **Auto-scaling** | 5 min | Paid Render plan → Scaling → min 1 / max 3 instances on CPU 70%. Or Cloud Run: `--min-instances 0 --max-instances 5` (scales to zero). |
| **CI/CD** | already on | `autoDeploy: true` in `render.yaml`: every `git push` redeploys. Add a GitHub Action running `pytest` for a full pipeline. |

## One-paragraph architecture summary (for the report)
ShopSecure is a SaaS e-commerce application deployed on a PaaS (Render) as a containerised Python/Flask
service. Every user interaction is emitted as a structured log event by a producer hook and published to an
event queue. A stream-processing worker consumes events in micro-batches, maintains sliding-window behavioural
features per IP address and per user, and classifies each event with a hybrid machine-learning model
(Random Forest classifier plus Isolation Forest anomaly detector) as Normal, Suspicious or Malicious with a
0-100 risk score. Results are persisted to a database, written as structured JSON logs to the platform's
cloud logging service, and pushed as webhook alerts for malicious activity. Tenants subscribe to services on
demand and see only their own results through dashboards showing verdict distributions, timelines, threat
types, risky IPs and model-evaluation metrics (accuracy, precision, recall, F1, ROC-AUC, confusion matrix).
