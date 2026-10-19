"""End-to-end checks of the cloud app: accounts, services, upload, push feed, dashboards."""
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path

os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ["DEMO_STREAM"] = "off"
os.environ["CW_METRICS"] = "off"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "web"))

import app as web  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def token(c):
    return re.search(r'name="csrf" value="([^"]+)"', c.get("/login").get_data(as_text=True)).group(1)


def signup(c, name):
    t = token(c)
    r = c.post("/register", data={"csrf": t, "username": name, "password": "secret12", "confirm": "secret12",
                                  "full_name": name.title(), "company": "ACME"})
    assert r.status_code == 302
    return t


def test_public_pages():
    c = web.app.test_client()
    assert c.get("/health").json["status"] == "ok"
    for path in ("/", "/services", "/login", "/register"):
        assert c.get(path).status_code == 200
    assert c.get("/console").status_code == 302          # needs login
    assert c.post("/login", data={"username": "x"}).status_code == 400   # no CSRF token


def test_upload_flow_with_evaluation():
    c = web.app.test_client()
    t = signup(c, "alice")
    assert c.get("/console/upload").status_code == 302   # no services yet
    for svc in web.SERVICES:
        c.post("/services", data={"csrf": t, "service": svc, "op": "add"})
    r = c.post("/console/upload", data={"csrf": t, "sample": "demo"})
    assert r.status_code == 302
    page = c.get(r.location).get_data(as_text=True)
    assert "Demo traffic sample" in page and "renderEvaluation" in page
    aid = int(r.location.rsplit("/", 1)[1])
    a = web.storage.query_one("SELECT * FROM analyses WHERE id=?", (aid,))
    ev = json.loads(a["evaluation"])
    assert a["n_records"] == 500 and ev["hybrid"]["accuracy"] > 0.7 and "family" in ev
    csv_text = c.get(f"/console/reports/{aid}/export.csv").get_data(as_text=True)
    assert csv_text.splitlines()[0].startswith("src_ip,protocol")

    # raw KDD .txt without header, uploaded as a file
    from io import BytesIO
    raw = b"".join((ROOT / "aiml/data/raw/KDDTest+.txt").read_bytes().splitlines(keepends=True)[:300])
    r = c.post("/console/upload", data={"csrf": t, "file": (BytesIO(raw), "kdd.txt")}, content_type="multipart/form-data")
    assert r.status_code == 302 and "/reports/" in r.location

    # other users can't open alice's report
    c2 = web.app.test_client()
    signup(c2, "bob")
    assert c2.get(f"/console/reports/{aid}").status_code == 404


def test_push_feed_and_live_dashboard():
    c = web.app.test_client()
    t = signup(c, "carol")
    c.post("/services", data={"csrf": t, "service": "intrusion", "op": "add"})
    c.post("/services", data={"csrf": t, "service": "anomaly", "op": "add"})
    c.post("/console/sources", data={"csrf": t, "op": "push", "name": "agent"})
    key = web.storage.query_one("SELECT api_key FROM sources WHERE name='agent'")["api_key"]
    lines = (ROOT / "aiml/data/sample/demo_traffic.csv").read_text().splitlines()
    cols = lines[0].split(",")
    records = [dict(zip(cols, l.split(","))) for l in lines[1:61]]
    assert c.post("/api/v1/ingest", data=json.dumps(records), headers={"X-API-Key": "bad"}).status_code == 401
    r = c.post("/api/v1/ingest", data=json.dumps(records), headers={"X-API-Key": key})
    assert r.status_code == 202 and r.json["accepted"] == 60
    for _ in range(50):
        if web.pipeline.q.qsize() == 0 and web.pipeline.stats["processed"] >= 60:
            break
        time.sleep(0.1)
    time.sleep(0.5)
    s = c.get("/api/live?window=3600").json
    assert s["kpis"]["total"] == 60
    assert s["evaluation"]["hybrid"]["samples"] == 60
    assert c.get("/console/live").status_code == 200


def test_account_pages():
    c = web.app.test_client()
    t = signup(c, "dave")
    assert c.get("/console/models").status_code == 200
    assert c.get("/console/monitoring").status_code == 200
    c.post("/account", data={"csrf": t, "action": "password", "current": "secret12", "new": "newpass99"})
    c.post("/logout", data={"csrf": t})
    t = token(c)
    assert c.post("/login", data={"csrf": t, "username": "dave", "password": "newpass99"}).status_code == 302
    c.post("/account", data={"csrf": t, "action": "delete"})
    assert web.storage.get_user("dave") is None
