# Cloud computing concepts in NetGuard Cloud

| Concept | Where it is | How to show it in the demo |
|---|---|---|
| **IaaS** | The app runs on an **AWS EC2** virtual machine you launch and configure | EC2 console: the running instance |
| **SaaS** | Customers use intrusion detection in the browser, with nothing to install | Register a new account live |
| **On-demand self-service** | Users add/remove detection services themselves; they're active instantly | Services page → *Add to my account* |
| **Multi-tenancy** | One deployment serves many companies; every record, feed and report belongs to one user and is isolated | Two accounts each see only their own data |
| **Containerisation** | `Dockerfile` (web + models) and `streamer/Dockerfile` | `docker compose ps` on the instance |
| **Orchestration (Docker Compose)** | Two services, private network, named volume, health checks, restart policies, depends-on | `docker-compose.yml` |
| **Infrastructure as code / automation** | `deploy/ec2-user-data.sh` builds the whole server on first boot; `setup_cloudwatch.sh` creates the dashboard and alarms | Launch a fresh instance |
| **Identity & access management** | EC2 **instance role** with a least-privilege policy (`deploy/iam-policy.json`), no access keys in code | IAM role page |
| **Monitoring: CloudWatch Logs** | `awslogs` Docker log driver ships structured JSON logs to `/netguard/web` and `/netguard/log-streamer` | Log groups + Logs Insights query |
| **Monitoring: CloudWatch Metrics** | Custom namespace `NetGuard`: traffic, attacks by type, latency, queue depth, sign-ins | Dashboard `NetGuard` |
| **Alerting** | CloudWatch alarms → SNS email on attack spikes / pipeline backlog | Switch the sensor to "Under attack" and wait for the email |
| **Data streaming / event-driven processing** | Feed readers deliver records one by one into a queue; a worker analyses micro-batches in real time | Live dashboard pipeline strip |
| **APIs / integration** | REST ingest endpoint with per-source API keys (push model), NDJSON feed client (pull model) | `curl` example on the Live feeds page |
| **Persistent storage** | SQLite on a Docker named volume (survives container restarts and rebuilds) | Restart the containers: reports remain |
| **Health checks / reliability** | `/health` endpoint, container `HEALTHCHECK`s, `restart: unless-stopped`, automatic feed reconnect with back-off | `docker kill` the streamer: it restarts and feeds reconnect |
| **Security** | Hashed passwords, CSRF tokens, HTTP-only cookies, tenant isolation, feed URLs can't reach the EC2 metadata endpoint, upload limits | Monitoring page / code |
| **Scalability (next step)** | Stateless web tier behind one interface: move the queue to SQS/Kinesis and the database to RDS, then run several web containers behind an Application Load Balancer, or move to ECS | Explain as future work |

## One-paragraph summary for the report
NetGuard Cloud delivers the AIML mini project's network intrusion detection models as a multi-tenant SaaS
application on AWS. A Flask web application and a network-sensor service run as Docker containers orchestrated by
Docker Compose on an EC2 instance that is provisioned automatically by a user-data script. Customers register,
subscribe on demand to intrusion detection (Random Forest), anomaly detection (Isolation Forest) and attack-type
classification services, and send network connection logs either as file uploads or as live feeds that deliver
records one by one (pull from an NDJSON stream or push through an API-key-protected REST endpoint). A streaming
pipeline queues the records, analyses them in micro-batches and stores the verdicts, which are presented in
dashboards with analytics and evaluation metrics (accuracy, precision, recall, F1, false-alarm rate, confusion
matrices and detection of previously unseen attack types). All container logs are shipped to Amazon CloudWatch
Logs through the awslogs driver, and the application publishes custom CloudWatch metrics using the instance's IAM
role. These feed a CloudWatch dashboard and alarms that notify administrators through SNS.
