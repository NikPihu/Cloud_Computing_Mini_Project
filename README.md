# NetGuard Cloud: Network Intrusion & Anomaly Detection as a Service

Cloud Computing mini project. It turns the **AIML mini project**
([NikPihu/AIML_Mini_Project_AIT](https://github.com/NikPihu/AIML_Mini_Project_AIT), NSL-KDD intrusion detection)
into a multi-user cloud service, deployed with **Docker Compose on AWS EC2**, with logs and metrics in **Amazon CloudWatch**.

| # | Requirement | How it's done |
|---|---|---|
| 1 | Website with login and the usual account features | Sign up, sign in/out, profile, change password, login history, delete account |
| 2 | Services shown as boxes | **Network Intrusion Detection**, **Anomaly Detection**, **Attack Type Classification**: add/remove per account |
| 3 | Input your company's network logs, or connect a service that delivers them one by one | **Upload** a log file, or a **live feed**: the bundled network sensor, your own NDJSON feed URL, or the push API / agent |
| 4 | Use the AIML project models | `aiml/nids` is the AIML project's engine; its Random Forest + Isolation Forest make every prediction |
| 5-6 | Dashboard with analytics and evaluation | Verdicts, traffic over time, attack types, targeted services, protocols, anomaly scores, source IPs, flagged table; accuracy / precision / recall / F1 / false alarms / confusion matrices / unseen-attack detection |
| 7 | CloudWatch logs and metrics | JSON logs → CloudWatch Logs (awslogs driver); custom metrics → CloudWatch (PutMetricData); dashboard + alarms script |
| 8 | Docker Compose for EC2 | `docker-compose.yml` + `docker-compose.aws.yml`, EC2 user-data script |

**Demo login:** `demo` / `demo123`. All services are on and the network sensor is already streaming.

## Architecture

```
                         ┌──────────────────────── EC2 instance (Docker Compose) ───────────────────────┐
  Browser ──HTTP:80────► │  web  (Flask + gunicorn)                                                     │
  Log agent ─POST /api/v1/ingest─►  accounts · services · upload · feeds · dashboards                    │
                         │     │ batch: uploaded file            ▲ pulls NDJSON one record at a time    │
                         │     ▼                                 │                                      │
                         │  queue ─► analysis worker ─► AIML models (aiml/nids)   log-streamer          │
                         │     (micro-batches)          RandomForest + IsolationForest   (NSL-KDD       │
                         │             │                + attack-type RandomForest        network sensor)│
                         │             ▼                                                                │
                         │   SQLite on volume  ·  JSON logs (stdout)  ·  metrics buffer                 │
                         └──────────────────────────────┬────────────────────────┬─────────────────────┘
                                         awslogs driver  ▼                        ▼  PutMetricData (instance role)
                                       CloudWatch Logs /netguard/*        CloudWatch Metrics "NetGuard"
                                                         └──── Dashboard "NetGuard" + Alarms (SNS email) ┘
```

## Run it locally (Docker)
```bash
cp .env.example .env            # optional
docker compose up --build       # first build trains the models (~1 min)
# open http://localhost  ->  sign in as demo / demo123
```
Without Docker: `pip install -r requirements.txt`, then run `python streamer/streamer.py` (set `DATA_FILE` to a KDDTest+.txt)
and `cd web && STREAM_FEED_URL=http://localhost:9000/stream python app.py`.

## Deploy on EC2 with CloudWatch
Step by step: **[docs/EC2_DEPLOY.md](docs/EC2_DEPLOY.md)**. Short version:
1. Create an IAM role from `deploy/iam-policy.json` (CloudWatch Logs + PutMetricData).
2. Launch Amazon Linux 2023 (t3.small) with that role, **metadata hop limit 2**, port 80 open, and
   `deploy/ec2-user-data.sh` as user data. It installs Docker and runs
   `docker compose -f docker-compose.yml -f docker-compose.aws.yml up -d --build`.
3. In CloudShell run `deploy/setup_cloudwatch.sh` to create the **NetGuard** dashboard and alarms.

## The three ways to send logs
1. **Upload a file**: NSL-KDD / KDD-99 connection records, CSV with header or raw `.txt`. With a `label` column you also get
   the evaluation. Samples are built in (500-row demo file, full 22,544-row KDDTest+).
2. **Network sensor feed**: the `log-streamer` container replays real KDDTest+ traffic **one record at a time**
   (profiles: quiet / mixed / under attack; 1-25 records/s). Includes 17 attack types the models never saw in training.
3. **Your own feed or agent**: connect any URL that streams newline-delimited JSON, or create an API key and push:
   ```bash
   python agent/send_logs.py my_traffic.csv --url http://<server>/api/v1/ingest --key ng_xxx --rate 5
   ```

## Results (official NSL-KDD test set, same as the AIML project)
| Approach | Accuracy | Precision | Recall | F1 | Unseen attacks caught | False alarms |
|---|---|---|---|---|---|---|
| Random Forest (intrusion) | 77.8% | 96.9% | 63.1% | 76.4% | 30.3% | 2.7% |
| Isolation Forest (anomaly) | 79.1% | 96.9% | 65.4% | 78.1% | 66.2% | 2.8% |
| **Combined verdict** | **84.3%** | 96.6% | **75.0%** | **84.4%** | **67.5%** | 3.5% |

## Project layout
| Path | What |
|---|---|
| `web/app.py` | Website: accounts, services, upload, feeds, dashboards, ingest API, `/health` |
| `web/engine.py` | Loads/trains the AIML detectors, runs the subscribed services, evaluation |
| `web/pipeline.py` | Streaming pipeline: feed readers → queue → analysis worker → storage + CloudWatch |
| `web/cloudwatch.py` | JSON logging and the CloudWatch metrics publisher |
| `web/analytics.py`, `web/storage.py` | Dashboard aggregations, SQLite |
| `aiml/` | ML engine copied from the AIML project (`scripts/sync_aiml.sh` re-syncs it) |
| `streamer/` | Network-sensor container that streams records one by one |
| `agent/send_logs.py` | Push a log file to the ingest API record by record |
| `Dockerfile`, `docker-compose*.yml`, `deploy/` | Containers, EC2 user data, IAM policy, CloudWatch dashboard/alarms |
| `docs/CLOUD_CONCEPTS.md` | Cloud concepts covered, for the report/viva |

## Tests
```bash
pip install -r requirements.txt pytest && python -m pytest
```
