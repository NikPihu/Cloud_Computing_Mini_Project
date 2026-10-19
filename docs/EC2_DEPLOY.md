# Deploying NetGuard on AWS EC2 with CloudWatch

About 15 minutes, most of it waiting. You need an AWS account and the AWS console.

## 1. Create the IAM role (once, 3 min)
1. IAM → **Policies** → Create policy → JSON → paste [`deploy/iam-policy.json`](../deploy/iam-policy.json) → name it `NetGuardCloudWatch`.
2. IAM → **Roles** → Create role → *AWS service* → **EC2** → attach `NetGuardCloudWatch` → name it `NetGuardEC2Role`.

This lets the containers send logs and metrics to CloudWatch without storing any access keys.

## 2. Launch the instance (3 min)
EC2 → **Launch instance**:

| Setting | Value |
|---|---|
| AMI | **Amazon Linux 2023** |
| Instance type | **t3.small** (2 GB). t2.micro/t3.micro work too thanks to the swap file, but the first build is slower |
| Key pair | any (only needed for SSH) |
| Security group | allow **HTTP (80)** from anywhere, **SSH (22)** from My IP |
| Storage | 16 GB gp3 |
| Advanced → IAM instance profile | **NetGuardEC2Role** |
| Advanced → **Metadata response hop limit** | **2** ⚠️ required, otherwise containers can't use the instance role and metrics fail |
| Advanced → User data | paste [`deploy/ec2-user-data.sh`](../deploy/ec2-user-data.sh) (check `REPO_URL` and `BRANCH` at the top) |

Launch it. The user-data script installs Docker + Compose, adds swap, clones the repo, writes `.env` and runs
`docker compose -f docker-compose.yml -f docker-compose.aws.yml up -d --build`.
The build trains the AIML models (~1-3 min). After ~5 minutes open `http://<instance public IP>/`
and sign in as `demo` / `demo123`.

> Repo is private? Replace `REPO_URL` with `https://<github-user>:<personal-access-token>@github.com/...`,
> or make the repo public for the demo.

### Doing it by hand instead (SSH)
```bash
sudo dnf install -y docker git && sudo systemctl enable --now docker
# then run the "Docker Compose" and later sections of deploy/ec2-user-data.sh, or simply:
sudo bash deploy/ec2-user-data.sh
```
Useful commands on the instance (`cd /opt/netguard`):
```bash
sudo docker compose -f docker-compose.yml -f docker-compose.aws.yml ps        # status
sudo docker compose -f docker-compose.yml -f docker-compose.aws.yml up -d --build   # redeploy after git pull
sudo tail -f /var/log/cloud-init-output.log                                    # first-boot progress
curl localhost/health
```
(`docker compose logs` shows nothing with the awslogs driver; logs are in CloudWatch.)

## 3. Create the CloudWatch dashboard and alarms (2 min)
Easiest is **AWS CloudShell** (the `>_` icon in the console header), which already has admin credentials:
```bash
git clone -b claude/funny-allen-64e1fs https://github.com/NikPihu/Cloud_Computing_Mini_Project.git && cd Cloud_Computing_Mini_Project
AWS_REGION=ap-south-1 INSTANCE_ID=i-0123456789abcdef0 bash deploy/setup_cloudwatch.sh you@example.com
```
This creates:
* **Dashboard `NetGuard`**: traffic by verdict, attacks by type (DoS/Probe/R2L/U2R), latency, queue depth,
  website sign-ins, records by source, EC2 CPU, and a live table of the latest attacks from Logs Insights.
* **Alarm `netguard-attack-spike`** (>300 attacks in 5 min, so the normal demo feed stays below it and "Under attack" trips it) and **`netguard-pipeline-backlog`**, emailing you via SNS
  if you passed an address (confirm the subscription email).
* 7-day retention on the log groups.

## 4. What you'll see in CloudWatch

| Where | What |
|---|---|
| **Logs → Log groups → `/netguard/web`** | JSON log line for every detected attack (verdict, attack type, source IP, confidence, anomaly score, true label), every batch analysis, sign-ins/failed sign-ins, HTTP access log |
| **Logs → `/netguard/log-streamer`** | the network sensor: dataset loaded, clients connected, records streamed |
| **Logs Insights** | queries listed on the app's *Monitoring* page, e.g. `filter event = "detection" \| stats count(*) by attack_type, bin(5m)` |
| **Metrics → All metrics → `NetGuard`** | RecordsAnalyzed, Attacks, Suspicious, NormalTraffic, AttacksByType, ProcessingLatency, QueueDepth, ActiveStreams, HttpRequests, ResponseTime, Logins, FailedLogins, Signups, BatchJobs, … |
| **Dashboards → `NetGuard`** | all of the above in one screen |
| **Alarms** | attack spike / backlog alarms |

The app's **☁️ Monitoring** page shows whether metrics are being published and links to all of these.

## Troubleshooting
* **Monitoring page says "Unable to locate credentials" / metrics missing**: metadata hop limit is 1. Fix:
  EC2 → instance → Actions → Instance settings → *Modify instance metadata options* → hop limit **2**,
  then `sudo docker compose ... restart web`.
* **No log groups appear**: the instance role is missing or lacks `logs:CreateLogGroup`. Attach `NetGuardEC2Role`
  and run the `up -d` command again.
* **Site not reachable**: the security group doesn't allow port 80, or the build is still running (check
  `/var/log/cloud-init-output.log`).
* **Cost**: t3.small ≈ US$0.02/hour, plus about 25 custom metrics (~US$7.50/month if left running all month, prorated hourly).
  Stop the instance after the demo.
