"""NetGuard Cloud - network intrusion & anomaly detection as a cloud service.

Users sign up, pick the detection services they need, send their company's network
logs (file upload or a live feed delivering records one by one) and get dashboards.
Detection uses the AIML mini-project models (aiml/nids). Logs and metrics go to
Amazon CloudWatch.

Local:       cd web && python app.py
Production:  gunicorn -c gunicorn.conf.py app:app    (see Dockerfile / docker-compose.yml)
"""
import csv
import io
import ipaddress
import json
import logging
import os
import secrets
import socket
import time
from functools import wraps
from urllib.parse import urlparse

import numpy as np
import pandas as pd
from flask import (Flask, Response, abort, flash, g, jsonify, redirect, render_template, request, session,
                   url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import storage
from analytics import summarize
from cloudwatch import log_event, metrics, setup_logging
from engine import ROOT, evaluate, get_engine
from pipeline import emit_metrics, pipeline, record_row

setup_logging()
log = logging.getLogger("netguard.web")

MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "50"))
DEMO_PASSWORD = os.environ.get("DEMO_PASSWORD", "demo123")
FEED_URL = os.environ.get("STREAM_FEED_URL", "http://log-streamer:9000/stream")
SAMPLES = {
    "demo": ("Demo traffic sample (500 connections, labelled)", ROOT / "aiml/data/sample/demo_traffic.csv"),
    "kddtest": ("NSL-KDD test set (22,544 connections, labelled)", ROOT / "aiml/data/raw/KDDTest+.txt"),
}
PROFILES = {
    "normal": "Quiet office network - mostly normal traffic",
    "mixed": "Typical day - normal traffic with occasional attack bursts",
    "attack": "Under attack - heavy DoS, probing and intrusion attempts",
}

SERVICES = {
    "intrusion": {
        "name": "Network Intrusion Detection", "icon": "🛡️", "model": "Random Forest classifier",
        "desc": "Classifies every network connection as normal or attack, with a confidence score. "
                "Trained on 125,973 labelled NSL-KDD connections.",
        "metric": ("Precision", "Random Forest (intrusion)", "precision"),
    },
    "anomaly": {
        "name": "Anomaly Detection", "icon": "📈", "model": "Isolation Forest (trained on normal traffic only)",
        "desc": "Learns what normal traffic looks like and flags anything unusual, so it catches new "
                "(zero-day) attacks that no classifier has seen before.",
        "metric": ("Unseen attacks caught", "Isolation Forest (anomaly)", "unseen_caught"),
    },
    "attack_type": {
        "name": "Attack Type Classification", "icon": "🧬", "model": "Random Forest (multi-class)",
        "desc": "Tells you what kind of attack it is: DoS, Probe (scanning), R2L (remote break-in) "
                "or U2R (privilege escalation).",
        "metric": ("Accuracy", None, None),
    },
}

app = Flask(__name__)
app.config.update(SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
                  MAX_CONTENT_LENGTH=MAX_UPLOAD_MB * 1024 * 1024,
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")


# =================================================================== helpers
def client_ip():
    fwd = request.headers.get("X-Forwarded-For", "")
    return fwd.split(",")[0].strip() if fwd else (request.remote_addr or "-")


def current_user():
    if "user" not in g:
        uid = session.get("uid")
        g.user = storage.get_user(user_id=uid) if uid else None
    return g.user


def login_required(view):
    @wraps(view)
    def wrapper(*a, **kw):
        if not current_user():
            flash("Please sign in to continue.", "info")
            return redirect(url_for("login", next=request.path))
        return view(*a, **kw)
    return wrapper


def needs_service(view):
    @wraps(view)
    def wrapper(*a, **kw):
        if not storage.subscriptions(current_user()["id"]):
            flash("Add at least one detection service first.", "info")
            return redirect(url_for("services"))
        return view(*a, **kw)
    return login_required(wrapper)


def reset_session(**values):
    keep = {k: session[k] for k in ("csrf",) if k in session}
    session.clear()
    session.update(keep, **values)


@app.before_request
def before():
    g.t0 = time.time()
    session.setdefault("csrf", secrets.token_urlsafe(24))
    if request.method == "POST" and not request.path.startswith("/api/"):
        if request.form.get("csrf") != session["csrf"]:
            abort(400, "Invalid form token - reload the page and try again.")


@app.after_request
def after(resp):
    if request.endpoint not in ("static", "health", "api_live"):
        metrics.count("HttpRequests")
        if resp.status_code >= 500:
            metrics.count("Http5xx")
        metrics.sample("ResponseTime", (time.time() - g.get("t0", time.time())) * 1000)
    return resp


@app.context_processor
def inject():
    u = current_user()
    return {"me": u, "csrf_token": session.get("csrf", ""), "SERVICES": SERVICES,
            "my_services": storage.subscriptions(u["id"]) if u else set()}


@app.template_filter("dt")
def fmt_ts(ts):
    return time.strftime("%d %b %Y, %H:%M UTC", time.gmtime(ts)) if ts else "-"


@app.template_filter("num")
def fmt_num(v):
    return f"{v:,}" if isinstance(v, int) else (f"{v:,.0f}" if isinstance(v, float) else v)


@app.template_filter("pct")
def fmt_pct(v):
    return "-" if v is None else f"{100 * v:.1f}%"


def model_metric(key):
    card = get_engine().card
    label, approach, field = SERVICES[key]["metric"]
    if key == "attack_type":
        return label, card["family_metrics"]["Accuracy"]
    return label, card["evaluation"]["approaches"][approach][field]


app.jinja_env.globals["model_metric"] = model_metric


# ================================================================ public site
@app.route("/")
def index():
    return render_template("index.html", card=get_engine().card)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        f = request.form
        username = f.get("username", "").strip().lower()
        if not (3 <= len(username) <= 30 and username.replace("_", "").isalnum()):
            flash("Username must be 3-30 letters, digits or underscores.", "error")
        elif len(f.get("password", "")) < 6:
            flash("Password must be at least 6 characters.", "error")
        elif f.get("password") != f.get("confirm"):
            flash("Passwords don't match.", "error")
        elif storage.get_user(username):
            flash("That username is taken.", "error")
        else:
            uid = storage.create_user(username, generate_password_hash(f["password"]), f.get("email", "").strip(),
                                      f.get("full_name", "").strip(), f.get("company", "").strip())
            reset_session(uid=uid)
            storage.log_activity(uid, "Account created", client_ip())
            metrics.count("Signups")
            log_event(log, logging.INFO, "user registered", event="signup", user=username, ip=client_ip())
            flash("Welcome to NetGuard Cloud! Choose the services you need.", "success")
            return redirect(url_for("services"))
    return render_template("auth.html", mode="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        user = storage.get_user(username)
        if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
            reset_session(uid=user["id"])
            storage.execute("UPDATE users SET last_login=? WHERE id=?", (time.time(), user["id"]))
            storage.log_activity(user["id"], "Signed in", client_ip(), request.headers.get("User-Agent", "")[:120])
            metrics.count("Logins")
            log_event(log, logging.INFO, "login ok", event="login", user=username, ip=client_ip())
            nxt = request.args.get("next", "")
            return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("console"))
        if user:
            storage.log_activity(user["id"], "Failed sign-in attempt", client_ip())
        metrics.count("FailedLogins")
        log_event(log, logging.WARNING, "login failed", event="login_failed", user=username, ip=client_ip())
        flash("Incorrect username or password.", "error")
        return render_template("auth.html", mode="login", demo_password=DEMO_PASSWORD), 401
    return render_template("auth.html", mode="login", demo_password=DEMO_PASSWORD)


@app.route("/logout", methods=["POST"])
def logout():
    reset_session()
    flash("You have been signed out.", "info")
    return redirect(url_for("index"))


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    u = current_user()
    if request.method == "POST":
        action = request.form.get("action")
        if action == "profile":
            storage.execute("UPDATE users SET full_name=?, email=?, company=? WHERE id=?",
                            (request.form.get("full_name", "").strip(), request.form.get("email", "").strip(),
                             request.form.get("company", "").strip(), u["id"]))
            flash("Profile updated.", "success")
        elif action == "password":
            if not check_password_hash(u["password_hash"], request.form.get("current", "")):
                flash("Current password is wrong.", "error")
            elif len(request.form.get("new", "")) < 6:
                flash("New password must be at least 6 characters.", "error")
            else:
                storage.execute("UPDATE users SET password_hash=? WHERE id=?",
                                (generate_password_hash(request.form["new"]), u["id"]))
                storage.log_activity(u["id"], "Password changed", client_ip())
                flash("Password changed.", "success")
        elif action == "delete":
            if u["username"] == "demo":
                flash("The shared demo account can't be deleted.", "error")
            else:
                for s in storage.query("SELECT id FROM sources WHERE user_id=?", (u["id"],)):
                    pipeline.disconnect(s["id"])
                storage.delete_user(u["id"])
                reset_session()
                flash("Your account and all its data were deleted.", "info")
                return redirect(url_for("index"))
        return redirect(url_for("account"))
    activity = storage.query("SELECT * FROM activity WHERE user_id=? ORDER BY ts DESC LIMIT 15", (u["id"],))
    usage = storage.query_one("SELECT COUNT(*) n, SUM(verdict!='Normal') flagged FROM records WHERE user_id=?",
                              (u["id"],))
    return render_template("account.html", activity=activity, usage=usage)


# ================================================================== services
@app.route("/services", methods=["GET", "POST"])
def services():
    if request.method == "POST":
        u = current_user()
        if not u:
            return redirect(url_for("login", next=url_for("services")))
        key = request.form.get("service")
        if key not in SERVICES:
            abort(400)
        if request.form.get("op") == "add":
            storage.subscribe(u["id"], key)
            storage.log_activity(u["id"], f"Subscribed to {SERVICES[key]['name']}", client_ip())
            metrics.count("ServiceSubscriptions", Service=key)
            flash(f"{SERVICES[key]['name']} is now active on your account.", "success")
        else:
            storage.unsubscribe(u["id"], key)
            storage.log_activity(u["id"], f"Removed {SERVICES[key]['name']}", client_ip())
            flash(f"{SERVICES[key]['name']} removed.", "info")
        return redirect(url_for("services"))
    return render_template("services.html")


# =================================================================== console
@app.route("/console")
@login_required
def console():
    u = current_user()
    reports = storage.query("SELECT * FROM analyses WHERE user_id=? ORDER BY created_at DESC LIMIT 5", (u["id"],))
    for r in reports:
        r["kpis"] = json.loads(r["summary"])["kpis"]
    sources = storage.query("SELECT * FROM sources WHERE user_id=? ORDER BY created_at DESC", (u["id"],))
    totals = storage.query_one("SELECT COUNT(*) n, SUM(verdict='Attack') attacks, SUM(verdict='Suspicious') susp "
                               "FROM records WHERE user_id=?", (u["id"],))
    return render_template("console.html", reports=reports, sources=sources, totals=totals)


# ------------------------------------------------------------- option 1: file
@app.route("/console/upload", methods=["GET", "POST"])
@needs_service
def upload():
    if request.method == "POST":
        engine = get_engine()
        sample = request.form.get("sample")
        try:
            if sample in SAMPLES:
                name, path = SAMPLES[sample]
                raw = path.read_bytes()
            else:
                f = request.files.get("file")
                if not f or not f.filename:
                    raise ValueError("Choose a log file to upload.")
                name, raw = f.filename, f.read()
            df = engine.parse_upload(raw)
        except (ValueError, OSError, pd.errors.ParserError) as exc:
            flash(f"Couldn't read that file: {exc}", "error")
            return redirect(url_for("upload"))
        aid = run_batch(df, name)
        return redirect(url_for("report", aid=aid))
    return render_template("upload.html", samples=SAMPLES, max_mb=MAX_UPLOAD_MB)


def run_batch(df, name):
    u, engine = current_user(), get_engine()
    services = storage.subscriptions(u["id"])
    t0 = time.time()
    results = engine.analyze(df, services)
    label_col = engine.cfg.dataset.label_column
    evaluation = evaluate(df[label_col], results, engine) if label_col in df else None
    now = time.time()
    records = df.to_dict("records")
    rows = [record_row(rec, res, u["id"], ts=now) for rec, res in zip(records, results.to_dict("records"))]
    summary = summarize(rows, engine.threshold, by_time=False)
    seconds = round(time.time() - t0, 2)
    aid = storage.save_analysis(u["id"], name, services, rows, summary, evaluation, seconds)
    emit_metrics(rows, "batch")
    metrics.count("BatchJobs")
    metrics.sample("BatchJobDuration", seconds * 1000)
    log_event(log, logging.INFO, "batch analysis finished", event="batch_analysis", analysis_id=aid,
              user=u["username"], file=name, records=len(rows), seconds=seconds, **summary["kpis"],
              accuracy=evaluation and evaluation["hybrid"]["accuracy"])
    storage.log_activity(u["id"], f"Analysed {name} ({len(rows):,} records)", client_ip())
    return aid


def own_report(aid):
    a = storage.query_one("SELECT * FROM analyses WHERE id=? AND user_id=?", (aid, current_user()["id"]))
    if not a:
        abort(404)
    a["summary"], a["services"] = json.loads(a["summary"]), json.loads(a["services"])
    a["evaluation"] = json.loads(a["evaluation"]) if a["evaluation"] else None
    return a


@app.route("/console/reports")
@login_required
def reports():
    rows = storage.query("SELECT * FROM analyses WHERE user_id=? ORDER BY created_at DESC", (current_user()["id"],))
    for r in rows:
        r["kpis"] = json.loads(r["summary"])["kpis"]
    return render_template("reports.html", rows=rows)


@app.route("/console/reports/<int:aid>")
@login_required
def report(aid):
    return render_template("report.html", a=own_report(aid))


@app.route("/console/reports/<int:aid>/export.csv")
@login_required
def export_report(aid):
    own_report(aid)
    rows = storage.query("SELECT src_ip, protocol, service, flag, src_bytes, dst_bytes, verdict, prediction, "
                         "confidence, anomaly_score, family, label FROM records WHERE analysis_id=? ORDER BY id",
                         (aid,))
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=["src_ip", "protocol", "service", "flag", "src_bytes", "dst_bytes", "verdict",
                                        "prediction", "confidence", "anomaly_score", "family", "label"])
    w.writeheader()
    w.writerows(rows)
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=netguard-report-{aid}.csv"})


# ----------------------------------------------------------- option 2: feeds
def check_feed_url(url):
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("Enter a full http(s):// URL.")
    for info in socket.getaddrinfo(p.hostname, p.port or 80):
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_loopback or ip.is_link_local or ip.is_multicast:   # blocks 169.254.169.254 (EC2 metadata)
            raise ValueError("That address is not allowed.")


@app.route("/console/sources", methods=["GET", "POST"])
@needs_service
def sources():
    u = current_user()
    if request.method == "POST":
        op = request.form.get("op")
        if op == "demo":
            profile = request.form.get("profile", "mixed")
            rate = min(max(float(request.form.get("rate", 5)), 0.5), 50)
            url = f"{FEED_URL}?profile={profile if profile in PROFILES else 'mixed'}&rate={rate:g}"
            sid = storage.create_source(u["id"], f"Network sensor ({profile}, {rate:g}/s)", "pull", url)
            pipeline.connect(storage.query_one("SELECT * FROM sources WHERE id=?", (sid,)))
            flash("Network sensor connected - records will start arriving in a few seconds.", "success")
            return redirect(url_for("live"))
        if op == "feed":
            url = request.form.get("url", "").strip()
            try:
                check_feed_url(url)
            except (ValueError, OSError) as exc:
                flash(str(exc), "error")
                return redirect(url_for("sources"))
            sid = storage.create_source(u["id"], request.form.get("name") or urlparse(url).hostname, "pull", url)
            pipeline.connect(storage.query_one("SELECT * FROM sources WHERE id=?", (sid,)))
            flash("Feed connected.", "success")
        elif op == "push":
            storage.create_source(u["id"], request.form.get("name") or "Log agent", "push")
            flash("API key created - point your log agent at the ingest endpoint below.", "success")
        else:
            src = storage.query_one("SELECT * FROM sources WHERE id=? AND user_id=?",
                                    (request.form.get("id", type=int), u["id"]))
            if not src:
                abort(404)
            if op == "pause":
                pipeline.disconnect(src["id"])
                storage.execute("UPDATE sources SET status='paused' WHERE id=?", (src["id"],))
            elif op == "resume":
                storage.execute("UPDATE sources SET status='active' WHERE id=?", (src["id"],))
                if src["kind"] == "pull":
                    pipeline.connect(src)
            elif op == "delete":
                pipeline.disconnect(src["id"])
                storage.execute("DELETE FROM sources WHERE id=?", (src["id"],))
        return redirect(url_for("sources"))
    rows = storage.query("SELECT * FROM sources WHERE user_id=? ORDER BY created_at DESC", (u["id"],))
    return render_template("sources.html", rows=rows, profiles=PROFILES,
                           ingest_url=request.url_root.rstrip("/") + url_for("ingest"))


@app.route("/api/v1/ingest", methods=["POST"])
def ingest():
    """Push endpoint for log agents: JSON object, JSON array or NDJSON body."""
    key = request.headers.get("X-API-Key", "")
    src = storage.query_one("SELECT * FROM sources WHERE api_key=? AND kind='push'", (key,)) if key else None
    if not src:
        return jsonify(error="invalid API key"), 401
    if src["status"] == "paused":
        return jsonify(error="source is paused"), 409
    body = request.get_data(as_text=True).strip()
    try:
        data = json.loads(body) if body[:1] in "[{" and "\n" not in body else [json.loads(l) for l in body.splitlines() if l.strip()]
    except json.JSONDecodeError:
        return jsonify(error="body must be JSON or newline-delimited JSON"), 400
    records = data if isinstance(data, list) else [data]
    if len(records) > 5000:
        return jsonify(error="max 5000 records per request"), 413
    accepted = pipeline.submit(src["user_id"], src["id"], [r for r in records if isinstance(r, dict)])
    metrics.count("IngestRequests")
    return jsonify(accepted=accepted, queued=pipeline.q.qsize()), 202


# ---------------------------------------------------------------- live view
@app.route("/console/live")
@needs_service
def live():
    srcs = storage.query("SELECT id, name, status FROM sources WHERE user_id=?", (current_user()["id"],))
    return render_template("live.html", sources=srcs)


@app.route("/api/live")
@login_required
def api_live():
    u, engine = current_user(), get_engine()
    window = min(max(request.args.get("window", 900, type=int), 60), 86400)
    args, extra = [u["id"], time.time() - window], ""
    if request.args.get("source", type=int):
        extra, args = " AND source_id=?", args + [request.args.get("source", type=int)]
    rows = storage.query("SELECT * FROM records WHERE user_id=? AND analysis_id IS NULL AND ts>=?" + extra +
                         " ORDER BY ts", args)
    data = summarize(rows, engine.threshold)
    data["evaluation"] = None
    labelled = [r for r in rows if r.get("label")]
    if len(labelled) >= 20:
        res = pd.DataFrame({"verdict": [r["verdict"] for r in labelled]})
        if any(r["prediction"] for r in labelled):
            res["prediction"] = [r["prediction"] or "normal" for r in labelled]
        if any(r["anomaly_score"] is not None for r in labelled):
            res["is_anomaly"] = [r["anomaly_score"] is not None and r["anomaly_score"] > engine.threshold
                                 for r in labelled]
        if any(r["family"] for r in labelled):
            res["family"] = [r["family"] or "" for r in labelled]
        data["evaluation"] = evaluate([r["label"] for r in labelled], res, engine)
    data["pipeline"] = pipeline.health()
    return jsonify(json.loads(json.dumps(data, default=lambda o: o.item() if isinstance(o, np.generic) else str(o))))


# -------------------------------------------------------------- model + ops
@app.route("/console/models")
@login_required
def models_page():
    return render_template("models.html", card=get_engine().card)


@app.route("/console/monitoring")
@login_required
def monitoring():
    return render_template("monitoring.html", health=pipeline.health(), cw=metrics.status,
                           totals=dict(metrics.totals), links=metrics.console_links(),
                           namespace=os.environ.get("CW_NAMESPACE", "NetGuard"),
                           region=os.environ.get("AWS_REGION", ""))


@app.route("/health")
def health():
    return jsonify(status="ok", pipeline=pipeline.health(), cloudwatch=metrics.status)


@app.errorhandler(404)
def not_found(_):
    return render_template("message.html", title="Page not found", text="We couldn't find that page."), 404


@app.errorhandler(413)
def too_large(_):
    flash(f"File too large (max {MAX_UPLOAD_MB} MB).", "error")
    return redirect(url_for("upload"))


# ================================================================= bootstrap
def seed_demo():
    """Ready-made demo account: all services on, connected to the bundled network sensor."""
    if storage.get_user("demo"):
        return
    uid = storage.create_user("demo", generate_password_hash(DEMO_PASSWORD), "demo@netguard.local",
                              "Demo User", "AIT Pune Labs")
    for key in SERVICES:
        storage.subscribe(uid, key)
    if os.environ.get("DEMO_STREAM", "on") != "off":
        storage.create_source(uid, "Network sensor (mixed, 3/s)", "pull", f"{FEED_URL}?profile=mixed&rate=3")
    log.info("demo account created")


def bootstrap():
    storage.init_db()
    get_engine()
    seed_demo()
    pipeline.start()
    metrics.start()


bootstrap()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
