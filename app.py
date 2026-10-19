"""ShopSecure - an e-commerce store with a cloud security-analytics console.

Run locally:   python app.py           (http://localhost:5000)
Production:    gunicorn -c gunicorn.conf.py app:app
"""
import csv
import io
import ipaddress
import json
import logging
import os
import random
import secrets
import socket
import time
from functools import wraps
from urllib.parse import urlparse

import requests
from flask import (Flask, Response, abort, flash, g, jsonify, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import storage
from analytics import summarize
from catalog import CATEGORIES, PRODUCTS, PRODUCTS_BY_ID, PUBLIC_DATASETS, SERVICES
from ml import synth
from ml.engine import analyze_events, get_detector
from ml.parsers import ParseError, parse_bytes
from pipeline.bus import EventBus
from pipeline.sinks import setup_logging, valid_webhook

MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "25"))
TZ_OFFSET = float(os.environ.get("TZ_OFFSET_HOURS", "5.5"))     # IST by default
DEMO_PASSWORD = os.environ.get("DEMO_PASSWORD", "demo123")
SAMPLE_CSV = os.path.join(os.path.dirname(__file__), "static", "samples", "sample_login_events.csv")

setup_logging()
log = logging.getLogger("shopsecure.web")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    MAX_CONTENT_LENGTH=MAX_UPLOAD_MB * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)


def _alert_webhook(tenant):
    user = storage.get_user(tenant) if tenant else None
    if not user:
        return None
    return storage.subscriptions(user["id"]).get("alerts", {}).get("webhook")


bus = EventBus(tz_offset_hours=TZ_OFFSET, alert_lookup=_alert_webhook)


# ============================================================ helpers
def client_ip():
    fwd = request.headers.get("X-Forwarded-For", "")
    return fwd.split(",")[0].strip() if fwd else (request.remote_addr or "0.0.0.0")


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


def service_required(*keys):
    def deco(view):
        @wraps(view)
        def wrapper(*a, **kw):
            subs = storage.subscriptions(current_user()["id"])
            if not any(k in subs for k in keys):
                flash(f"Add the {' or '.join(SERVICES[k]['name'] for k in keys)} service to use this.", "info")
                return redirect(url_for("services"))
            return view(*a, **kw)
        return login_required(wrapper)
    return deco


def reset_session(**values):
    """Start a fresh session on login/logout, keeping the cart and form token."""
    keep = {k: session[k] for k in ("cart", "csrf") if k in session}
    session.clear()
    session.update(keep, **values)


def track(action, success=True, user=None, tenant=None):
    """Mark the current request as an activity event; emitted after the response."""
    g.event = {"action": action, "success": success, "user": user, "tenant": tenant}


@app.before_request
def csrf_protect():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    if request.method == "POST" and not request.path.startswith("/api/"):
        if request.form.get("csrf") != session["csrf"]:
            abort(400, "Invalid form token - please reload the page and try again.")


@app.after_request
def emit_activity(resp):
    """Producer side of the pipeline: every store interaction becomes a log event."""
    ev = g.pop("event", None)
    if ev is None and request.endpoint in ACTIVITY_ENDPOINTS and request.method == "GET":
        u = current_user()
        ev = {"action": ACTIVITY_ENDPOINTS[request.endpoint], "success": resp.status_code < 400,
              "user": u["username"] if u else None, "tenant": u["username"] if u else None}
    if ev:
        bus.publish({**ev, "ts": time.time(), "ip": client_ip(), "path": request.full_path.rstrip("?"),
                     "status": resp.status_code, "user_agent": request.headers.get("User-Agent", ""),
                     "source": "web"})
    return resp


ACTIVITY_ENDPOINTS = {"index": "view", "product": "view", "cart": "view", "orders": "view",
                      "search": "search", "services": "view"}


@app.context_processor
def inject_globals():
    u = current_user()
    return {"me": u, "cart_count": sum(session.get("cart", {}).values()), "csrf_token": session.get("csrf", ""),
            "my_services": storage.subscriptions(u["id"]) if u else {}, "SERVICES": SERVICES,
            "categories": CATEGORIES}


@app.template_filter("inr")
def inr(v):
    return f"₹{v:,.0f}"


@app.template_filter("dt")
def fmt_ts(ts):
    return time.strftime("%d %b %Y, %H:%M", time.gmtime(ts + TZ_OFFSET * 3600)) if ts else "-"


# ============================================================ store
@app.route("/")
def index():
    cat = request.args.get("category")
    items = [p for p in PRODUCTS if not cat or p["category"] == cat]
    return render_template("index.html", products=items, active_cat=cat)


@app.route("/search")
def search():
    q = request.args.get("q", "").strip().lower()
    items = [p for p in PRODUCTS if q in p["name"].lower() or q in p["category"].lower()]
    return render_template("index.html", products=items, query=q)


@app.route("/product/<int:pid>")
def product(pid):
    p = PRODUCTS_BY_ID.get(pid) or abort(404)
    related = [x for x in PRODUCTS if x["category"] == p["category"] and x["id"] != pid][:4]
    return render_template("product.html", p=p, related=related)


@app.route("/cart")
def cart():
    items = [(PRODUCTS_BY_ID[int(pid)], qty) for pid, qty in session.get("cart", {}).items()]
    total = sum(p["price"] * q for p, q in items)
    return render_template("cart.html", items=items, total=total)


@app.route("/cart/add/<int:pid>", methods=["POST"])
def cart_add(pid):
    PRODUCTS_BY_ID.get(pid) or abort(404)
    c = session.setdefault("cart", {})
    c[str(pid)] = c.get(str(pid), 0) + 1
    session.modified = True
    u = current_user()
    track("add_to_cart", user=u and u["username"], tenant=u and u["username"])
    flash("Added to cart.", "success")
    return redirect(request.form.get("next") or url_for("cart"))


@app.route("/cart/remove/<int:pid>", methods=["POST"])
def cart_remove(pid):
    session.get("cart", {}).pop(str(pid), None)
    session.modified = True
    return redirect(url_for("cart"))


@app.route("/checkout", methods=["POST"])
@login_required
def checkout():
    c = session.get("cart", {})
    if not c:
        return redirect(url_for("cart"))
    items = [{"id": int(pid), "name": PRODUCTS_BY_ID[int(pid)]["name"], "qty": q,
              "price": PRODUCTS_BY_ID[int(pid)]["price"]} for pid, q in c.items()]
    total = sum(i["price"] * i["qty"] for i in items)
    storage.execute("INSERT INTO orders (user_id, items, total, created_at) VALUES (?,?,?,?)",
                    (current_user()["id"], json.dumps(items), total, time.time()))
    session["cart"] = {}
    track("checkout", user=current_user()["username"], tenant=current_user()["username"])
    flash(f"Order placed! {inr(total)} will be delivered in 2 days.", "success")
    return redirect(url_for("orders"))


@app.route("/orders")
@login_required
def orders():
    rows = storage.query("SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC", (current_user()["id"],))
    for r in rows:
        r["items"] = json.loads(r["items"])
    return render_template("orders.html", orders=rows)


# ============================================================ auth
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        email = request.form.get("email", "").strip()
        pw = request.form.get("password", "")
        if not (3 <= len(username) <= 30 and username.replace("_", "").isalnum()):
            flash("Username must be 3-30 letters, digits or underscores.", "error")
        elif len(pw) < 6:
            flash("Password must be at least 6 characters.", "error")
        elif storage.get_user(username):
            flash("That username is taken.", "error")
        else:
            uid = storage.create_user(username, email, generate_password_hash(pw))
            reset_session(uid=uid)
            track("register", user=username, tenant=username)
            flash("Welcome to ShopSecure! Pick the security services you want below.", "success")
            return redirect(url_for("services"))
    return render_template("auth.html", mode="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        user = storage.get_user(username)
        if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
            reset_session(uid=user["id"])
            track("login", True, username, username)
            nxt = request.args.get("next", "")
            return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("index"))
        track("login", False, username, username if user else None)
        g.event["invalid_user"] = user is None
        flash("Incorrect username or password.", "error")
        return render_template("auth.html", mode="login", demo_password=DEMO_PASSWORD), 401
    return render_template("auth.html", mode="login", demo_password=DEMO_PASSWORD)


@app.route("/logout", methods=["POST"])
def logout():
    u = current_user()
    if u:
        track("logout", user=u["username"], tenant=u["username"])
    reset_session()
    return redirect(url_for("index"))


# ============================================================ services
@app.route("/services", methods=["GET", "POST"])
def services():
    u = current_user()
    if request.method == "POST":
        if not u:
            return redirect(url_for("login", next=url_for("services")))
        key, op = request.form.get("service"), request.form.get("op")
        if key not in SERVICES:
            abort(400)
        if op == "add":
            settings = {}
            if key == "alerts":
                hook = request.form.get("webhook", "").strip()
                if hook and not valid_webhook(hook):
                    flash("Use a Discord (discord.com/api/webhooks/...) or Slack (hooks.slack.com/...) URL.", "error")
                    return redirect(url_for("services"))
                settings["webhook"] = hook
            storage.subscribe(u["id"], key, settings)
            track("subscribe", user=u["username"], tenant=u["username"])
            flash(f"{SERVICES[key]['name']} is now active.", "success")
        elif op == "remove":
            storage.unsubscribe(u["id"], key)
            flash(f"{SERVICES[key]['name']} removed.", "info")
        return redirect(url_for("services"))
    return render_template("services.html")


# ============================================================ security console
@app.route("/console")
@login_required
def console():
    u = current_user()
    recent = storage.query("SELECT id, name, source_type, n_events, created_at, summary FROM analyses "
                           "WHERE user_id=? ORDER BY created_at DESC LIMIT 5", (u["id"],))
    for r in recent:
        r["kpis"] = json.loads(r.pop("summary"))["kpis"]
    live = storage.query_one("SELECT COUNT(*) n, SUM(label!='Normal') flagged FROM events WHERE tenant=?",
                             (u["username"],))
    return render_template("console.html", recent=recent, live=live)


@app.route("/console/live")
@service_required("live_protection")
def live_monitor():
    return render_template("live.html", attacks=SIMULATIONS)


SIMULATIONS = {
    "brute_force": ("Brute-force attack", "40 rapid wrong-password attempts on your account"),
    "credential_stuffing": ("Credential stuffing", "One IP tries many usernames from a leaked list"),
    "bot_scan": ("Vulnerability scan", "A bot probes /wp-admin, /.env and other weak spots"),
    "flood": ("Request flood", "200 requests in a few seconds (DoS-style)"),
    "new_device": ("Account takeover", "Failed tries, then a login from a new device + password change"),
}


def _live_rows(username, window):
    since = time.time() - window
    return storage.query("SELECT ts, ip, user, action, label, risk, reason FROM events "
                         "WHERE tenant=? AND ts>=? ORDER BY ts", (username, since))


@app.route("/api/live/summary")
@login_required
def api_live_summary():
    window = min(max(int(request.args.get("window", 3600)), 60), 7 * 86400)
    data = summarize(_live_rows(current_user()["username"], window))
    data["pipeline"] = bus.health()
    return jsonify(data)


@app.route("/console/live/simulate", methods=["POST"])
@service_required("live_protection")
def simulate():
    kind = request.form.get("kind")
    if kind not in SIMULATIONS:
        abort(400)
    me = current_user()["username"]
    users = [r["username"] for r in storage.query("SELECT username FROM users LIMIT 50")]
    for ev in synth.simulate(kind, me, users):
        ev.pop("label", None)
        bus.publish({**ev, "tenant": me, "source": "simulator"})
    flash(f"Simulated {SIMULATIONS[kind][0].lower()} sent into the pipeline - watch the charts.", "info")
    return redirect(url_for("live_monitor"))


# ---------------------------------------------------------------- batch analysis
@app.route("/console/analyze", methods=["GET", "POST"])
@service_required("log_analyzer", "cloud_import")
def analyze():
    subs = storage.subscriptions(current_user()["id"])
    if request.method == "POST":
        mode = request.form.get("mode")
        try:
            if mode == "upload":
                if "log_analyzer" not in subs:
                    abort(403)
                f = request.files.get("file")
                if not f or not f.filename:
                    raise ParseError("Choose a file to upload.")
                raw, name, source = f.read(), f.filename, f.filename
            elif mode == "url":
                if "cloud_import" not in subs:
                    abort(403)
                url = request.form.get("url", "").strip() or request.form.get("preset", "")
                raw, name, source = fetch_dataset(url)
            else:
                abort(400)
            events, fmt = parse_bytes(raw, name)
        except ParseError as exc:
            flash(str(exc), "error")
            return redirect(url_for("analyze"))
        except (OSError, ValueError, UnicodeError) as exc:
            log.warning("could not parse upload: %r", exc)
            flash("We couldn't read that file. Check that it is a supported log or CSV format.", "error")
            return redirect(url_for("analyze"))
        aid = run_analysis(events, fmt, name, mode, source)
        return redirect(url_for("analysis", aid=aid))
    return render_template("analyze.html", datasets=PUBLIC_DATASETS, subs=subs, max_mb=MAX_UPLOAD_MB)


def fetch_dataset(url):
    """Download a log file from a public URL (blocks private/internal addresses)."""
    if url == "builtin:sample":
        with open(SAMPLE_CSV, "rb") as fh:
            return fh.read(), "sample_login_events.csv", "ShopSecure labelled sample"
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ParseError("Enter a full http(s):// URL.")
    try:
        for info in socket.getaddrinfo(parsed.hostname, None):
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                raise ParseError("That address is not allowed.")
        resp = requests.get(url, timeout=25, stream=True, allow_redirects=False)
        resp.raise_for_status()
        raw = b""
        for chunk in resp.iter_content(1 << 16):
            raw += chunk
            if len(raw) > MAX_UPLOAD_MB * 1024 * 1024:
                break
    except (requests.RequestException, socket.gaierror) as exc:
        raise ParseError(f"Could not download the file: {exc.__class__.__name__}") from exc
    name = os.path.basename(parsed.path) or "download.log"
    return raw, name, url


def run_analysis(events, fmt, name, mode, source):
    t0 = time.time()
    results, evaluation = analyze_events(events)
    summary = summarize(results)
    summary["processing_seconds"] = round(time.time() - t0, 2)
    aid = storage.save_analysis(current_user()["id"], name, mode, source, fmt, results, summary, evaluation)
    log.info("analysis finished", extra={"data": {"event": "analysis", "analysis_id": aid, "user": current_user()["username"],
                                                    "format": fmt, "events": len(results), **summary["kpis"],
                                                    "accuracy": evaluation and evaluation["accuracy"]}})
    track("analysis", user=current_user()["username"], tenant=current_user()["username"])
    return aid


def _own_analysis(aid):
    a = storage.query_one("SELECT * FROM analyses WHERE id=? AND user_id=?", (aid, current_user()["id"]))
    if not a:
        abort(404)
    a["summary"] = json.loads(a["summary"])
    a["evaluation"] = json.loads(a["evaluation"]) if a["evaluation"] else None
    return a


@app.route("/console/analysis/<int:aid>")
@login_required
def analysis(aid):
    return render_template("analysis.html", a=_own_analysis(aid), model=get_detector().metrics)


@app.route("/console/analysis/<int:aid>/export.<fmt>")
@login_required
def export_analysis(aid, fmt):
    a = _own_analysis(aid)
    if fmt == "json":
        body = json.dumps({k: a[k] for k in ("id", "name", "fmt", "n_events", "summary", "evaluation")}, indent=2)
        return Response(body, mimetype="application/json",
                        headers={"Content-Disposition": f"attachment; filename=analysis-{aid}.json"})
    if fmt != "csv":
        abort(404)
    rows = storage.query("SELECT ts, ip, user, action, success, path, status, label, risk, reason, true_label "
                         "FROM analysis_rows WHERE analysis_id=? ORDER BY ts", (aid,))
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=["time", "ip", "user", "action", "success", "path", "status",
                                        "label", "risk", "reason", "true_label"])
    w.writeheader()
    for r in rows:
        r["time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(r.pop("ts")))
        w.writerow(r)
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=analysis-{aid}.csv"})


@app.route("/console/analyses")
@login_required
def analyses():
    rows = storage.query("SELECT id, name, source_type, fmt, n_events, created_at, summary FROM analyses "
                         "WHERE user_id=? ORDER BY created_at DESC", (current_user()["id"],))
    for r in rows:
        r["kpis"] = json.loads(r.pop("summary"))["kpis"]
    return render_template("analyses.html", rows=rows)


@app.route("/console/model")
@login_required
def model_card():
    return render_template("model.html", m=get_detector().metrics)


# ============================================================ ops
@app.route("/health")
def health():
    """Liveness/readiness probe for the load balancer / platform."""
    return jsonify(status="ok", pipeline=bus.health(), model_loaded=True)


@app.errorhandler(404)
def not_found(_):
    return render_template("message.html", title="Page not found",
                           text="We couldn't find that page."), 404


@app.errorhandler(413)
def too_large(_):
    flash(f"File too large (max {MAX_UPLOAD_MB} MB).", "error")
    return redirect(url_for("analyze"))


# ============================================================ bootstrap
def seed_demo():
    """Create a ready-to-use demo account with some history so dashboards are never empty."""
    if storage.get_user("demo"):
        return
    uid = storage.create_user("demo", "demo@shopsecure.local", generate_password_hash(DEMO_PASSWORD))
    for key in SERVICES:
        storage.subscribe(uid, key, {})
    rng = random.Random(7)
    now = time.time()
    home_ip, ua = "49.36.112.20", synth.BROWSER_UAS[0]
    events = [{"ts": now - 7200, "ip": home_ip, "action": "register", "success": True, "user": "demo", "user_agent": ua}]
    t = now - 6900
    while t < now - 120:
        events.append({"ts": t, "ip": home_ip, "action": "login", "success": True, "user": "demo", "user_agent": ua})
        for _ in range(rng.randint(2, 6)):
            t += rng.uniform(10, 60)
            events.append({"ts": t, "ip": home_ip, "action": rng.choice(["view", "search", "add_to_cart", "view"]),
                           "success": True, "user": "demo", "user_agent": ua, "path": "/", "status": 200})
        t += rng.uniform(300, 900)
    events += synth.brute_force(rng, now - 3000, "demo", n=25, gap=(0.5, 2))
    events += synth.bot_scan(rng, now - 1500, n=30)
    events += [{**e, "user": "demo"} for e in synth.suspicious_scenario(synth.World(rng, 5), now - 600, "few_fails")]
    for e in sorted(events, key=lambda e: e["ts"]):
        e.pop("label", None)
        bus.publish({**e, "tenant": "demo", "source": "seed"})
    log.info("seeded demo account")


def bootstrap():
    storage.init_db()
    get_detector()          # trains on first boot, then loads from disk
    bus.start()
    seed_demo()


bootstrap()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
