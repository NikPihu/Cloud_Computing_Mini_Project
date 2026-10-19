#!/bin/bash
# Creates the CloudWatch dashboard, an attack alarm (optionally emailing you) and log retention.
# Run once from the EC2 instance (or anywhere with AWS CLI admin credentials):
#   bash deploy/setup_cloudwatch.sh [your@email.com]
set -euo pipefail
cd "$(dirname "$0")"
TOKEN=$(curl -s -m 2 -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 60" || true)
md() { curl -s -m 2 -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/meta-data/$1"; }
REGION=${AWS_REGION:-$(md placement/region)}
INSTANCE=${INSTANCE_ID:-$(md instance-id)}
NS=${CW_NAMESPACE:-NetGuard}

sed -e "s/__REGION__/$REGION/g" -e "s/__NS__/$NS/g" -e "s/__INSTANCE__/$INSTANCE/g" cloudwatch-dashboard.json > /tmp/netguard-dashboard.json
aws cloudwatch put-dashboard --region "$REGION" --dashboard-name NetGuard --dashboard-body file:///tmp/netguard-dashboard.json
echo "Dashboard: https://$REGION.console.aws.amazon.com/cloudwatch/home?region=$REGION#dashboards/dashboard/NetGuard"

ALARM_ACTIONS=()
if [ -n "${1:-}" ]; then
  TOPIC=$(aws sns create-topic --region "$REGION" --name netguard-alerts --query TopicArn --output text)
  aws sns subscribe --region "$REGION" --topic-arn "$TOPIC" --protocol email --notification-endpoint "$1" > /dev/null
  ALARM_ACTIONS=(--alarm-actions "$TOPIC")
  echo "Confirm the subscription email sent to $1"
fi
aws cloudwatch put-metric-alarm --region "$REGION" --alarm-name netguard-attack-spike \
  --alarm-description "More than 300 network attacks detected in 5 minutes" \
  --namespace "$NS" --metric-name Attacks --statistic Sum --period 300 --evaluation-periods 1 \
  --threshold 300 --comparison-operator GreaterThanThreshold --treat-missing-data notBreaching "${ALARM_ACTIONS[@]}"
aws cloudwatch put-metric-alarm --region "$REGION" --alarm-name netguard-pipeline-backlog \
  --alarm-description "Log pipeline is falling behind" \
  --namespace "$NS" --metric-name QueueDepth --statistic Maximum --period 60 --evaluation-periods 3 \
  --threshold 1000 --comparison-operator GreaterThanThreshold --treat-missing-data notBreaching "${ALARM_ACTIONS[@]}"
for g in /netguard/web /netguard/log-streamer; do
  aws logs put-retention-policy --region "$REGION" --log-group-name "$g" --retention-in-days 7 || true
done
echo "Alarms and 7-day log retention configured."
