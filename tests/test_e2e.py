"""End-to-end smoke test: store flow, services, the three input options, exports."""
import os
import re
import sys
import tempfile
import time

os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ.setdefault("LOG_DIR", tempfile.mkdtemp())
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import app as shop  # noqa: E402

SAMPLE_SSH = b"""Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186
""" + b"".join(f"Dec 10 07:{i:02d}:00 LabSZ sshd[24201]: Failed password for root from 5.36.59.76 port 4{i} ssh2\n".encode() for i in range(30)) + \
    b"Dec 10 09:12:01 LabSZ sshd[24300]: Accepted password for fztu from 119.137.62.142 port 49116 ssh2\n"


def csrf(client):
    html = client.get("/login").get_data(as_text=True)
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def wait_pipeline():
    for _ in range(50):
        if shop.bus.q.qsize() == 0:
            time.sleep(0.3)
            return
        time.sleep(0.1)


def test_full_flow():
    c = shop.app.test_client()
    assert c.get("/health").json["status"] == "ok"
    assert c.get("/").status_code == 200
    assert "Smartphone" in c.get("/search?q=phone").get_data(as_text=True)
    tok = csrf(c)

    # register -> services page
    r = c.post("/register", data={"csrf": tok, "username": "alice", "password": "secret12"})
    assert r.status_code == 302 and "/services" in r.location
    for svc in ("live_protection", "log_analyzer", "cloud_import"):
        c.post("/services", data={"csrf": tok, "service": svc, "op": "add"})
    c.post("/cart/add/1", data={"csrf": tok})
    assert c.post("/checkout", data={"csrf": tok}).status_code == 302
    assert "Nova X5" in c.get("/orders").get_data(as_text=True)

    # wrong passwords against alice are tracked in her tenant
    c.post("/logout", data={"csrf": tok})
    tok = csrf(c)
    for _ in range(12):
        assert c.post("/login", data={"csrf": tok, "username": "alice", "password": "nope"}).status_code == 401
    r = c.post("/login", data={"csrf": tok, "username": "alice", "password": "secret12"})
    assert r.status_code == 302
    tok = csrf(c)

    # option 1: live pipeline + simulator
    c.post("/console/live/simulate", data={"csrf": tok, "kind": "brute_force"})
    wait_pipeline()
    s = c.get("/api/live/summary?window=3600").json
    assert s["kpis"]["total"] > 40
    assert s["kpis"]["malicious"] > 10
    assert s["pipeline"]["worker_alive"]

    # option 2: upload
    from io import BytesIO
    r = c.post("/console/analyze", data={"csrf": tok, "mode": "upload", "file": (BytesIO(SAMPLE_SSH), "auth.log")},
               content_type="multipart/form-data")
    assert r.status_code == 302, r.get_data(as_text=True)
    page = c.get(r.location).get_data(as_text=True)
    assert "Linux / SSH auth log" in page

    # option 3: built-in labelled dataset -> evaluation shown
    r = c.post("/console/analyze", data={"csrf": tok, "mode": "url", "preset": "builtin:sample"})
    page = c.get(r.location).get_data(as_text=True)
    assert "Confusion matrix" in page
    aid = r.location.rsplit("/", 1)[-1]
    csv_body = c.get(f"/console/analysis/{aid}/export.csv").get_data(as_text=True)
    assert csv_body.startswith("time,ip,user")

    # private addresses are rejected for URL import
    r = c.post("/console/analyze", data={"csrf": tok, "mode": "url", "url": "http://127.0.0.1:5000/health"},
               follow_redirects=True)
    assert "not allowed" in r.get_data(as_text=True)

    # other users can't see alice's report
    c2 = shop.app.test_client()
    t2 = csrf(c2)
    c2.post("/register", data={"csrf": t2, "username": "bob", "password": "secret12"})
    assert c2.get(f"/console/analysis/{aid}").status_code == 404


def test_post_without_csrf_rejected():
    c = shop.app.test_client()
    assert c.post("/login", data={"username": "x", "password": "y"}).status_code == 400
