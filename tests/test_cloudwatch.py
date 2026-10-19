"""PutMetricData payloads must pass botocore's request validation (no AWS account needed)."""
import sys
from pathlib import Path

import boto3
from botocore.stub import ANY, Stubber

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "web"))
from cloudwatch import Metrics  # noqa: E402


def test_flush_sends_valid_metric_data():
    m = Metrics()
    m._client = boto3.client("cloudwatch", region_name="ap-south-1",
                             aws_access_key_id="x", aws_secret_access_key="x")
    m.count("RecordsAnalyzed", 120, Source="stream")
    m.count("Attacks", 7)
    m.count("AttacksByType", AttackType="DoS")
    m.sample("ProcessingLatency", 42.0)
    m.sample("ProcessingLatency", 58.0)
    m.gauges["QueueDepth"] = lambda: 3
    with Stubber(m._client) as stub:
        stub.add_response("put_metric_data", {}, {"Namespace": "NetGuard", "MetricData": ANY})
        m.flush()
        stub.assert_no_pending_responses()
    assert m.status["sent"] == 5 and m.totals["Attacks"] == 7
