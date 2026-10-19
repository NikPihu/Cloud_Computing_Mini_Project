"""Synthetic, labelled activity generator.

Used for two things:
  1. Training data for the detector (Normal / Suspicious / Malicious events).
  2. The live "attack simulator" buttons in the security console.
"""
import random
import time

BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
    "Mozilla/5.0 (Linux; Android 13; SM-A536E) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Mobile Safari/537.36",
]
BOT_UAS = [
    "python-requests/2.32.3", "curl/8.5.0", "Go-http-client/1.1", "sqlmap/1.8#stable",
    "Mozilla/5.00 (Nikto/2.5.0)", "Hydra v9.5", "Wget/1.21.4", "", "-",
]
CRAWLER_UAS = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
]
NORMAL_PATHS = ["/", "/product/3", "/product/7", "/search?q=phone", "/cart", "/orders",
                "/static/css/style.css", "/static/js/app.js", "/images/logo.png", "/favicon.ico",
                "/blog/cloud-tips", "/category/electronics", "/services"]
SCAN_PATHS = ["/wp-login.php", "/wp-admin/", "/.env", "/.git/config", "/phpmyadmin/", "/xmlrpc.php",
              "/cgi-bin/luci", "/admin.php", "/../../etc/passwd", "/search?q=1'+union+select+1,2--",
              "/shell?cd+/tmp", "/boaform/admin/formLogin", "/HNAP1/", "/vendor/phpunit/eval-stdin.php?x=1"]
COMMON_USERNAMES = ["admin", "root", "test", "user", "oracle", "guest", "ubuntu", "support",
                    "info", "postgres", "ftpuser", "pi", "administrator", "webmaster", "demo"]


def rand_ip(rng, private=False):
    if private:
        return f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    first = rng.choice([14, 27, 45, 49, 59, 103, 106, 117, 122, 152, 157, 182, 203, 223])
    return f"{first}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _ev(ts, ip, action, success=True, user=None, ua=None, path=None, status=None,
        invalid_user=False, label="Normal"):
    return {"ts": ts, "ip": ip, "action": action, "success": success, "user": user,
            "user_agent": ua, "path": path, "status": status,
            "invalid_user": invalid_user, "label": label}


class World:
    """A population of users with their usual IPs and devices."""

    def __init__(self, rng, n_users=250):
        self.rng = rng
        self.users = {}
        for i in range(n_users):
            ssh_style = rng.random() < 0.25          # SSH users have no user agent
            self.users[f"user{i:03d}"] = {
                "ips": [rand_ip(rng, private=rng.random() < 0.3) for _ in range(rng.randint(1, 2))],
                "uas": [None] if ssh_style else rng.sample(BROWSER_UAS, rng.randint(1, 2)),
            }

    def daytime_ts(self, start, days):
        r = self.rng
        day = r.randrange(days)
        hour = r.choices(range(24), weights=[1, 1, 1, 1, 1, 2, 4, 7, 9, 10, 10, 10,
                                             10, 10, 10, 9, 9, 9, 9, 8, 7, 5, 3, 2])[0]
        return start + day * 86400 + hour * 3600 + r.random() * 3600

    def night_ts(self, start, days):
        r = self.rng
        return start + r.randrange(days) * 86400 + r.uniform(0, 5) * 3600


# --------------------------------------------------------------------------
# Scenario builders. Each returns a list of events starting at `t`.
# --------------------------------------------------------------------------

def normal_session(w, name, t):
    r, u = w.rng, w.users[name]
    ip = u["ips"][0] if r.random() < 0.92 else rand_ip(r)
    ua = r.choice(u["uas"]) if r.random() < 0.94 or u["uas"] == [None] else r.choice(BROWSER_UAS)
    out = []
    if r.random() < 0.08:  # a typo
        out.append(_ev(t, ip, "login", False, name, ua))
        t += r.uniform(3, 15)
    out.append(_ev(t, ip, "login", True, name, ua))
    if ua is None:
        return out
    for _ in range(r.randint(2, 12)):
        t += r.uniform(4, 90)
        action = r.choices(["view", "search", "add_to_cart", "checkout", "subscribe"],
                           weights=[55, 20, 15, 7, 3])[0]
        out.append(_ev(t, ip, action, True, name, ua, path=r.choice(NORMAL_PATHS), status=200))
    out.append(_ev(t + r.uniform(5, 60), ip, "logout", True, name, ua))
    return out


def guest_browse(w, t):
    r = w.rng
    ip, ua = rand_ip(r), (r.choice(CRAWLER_UAS) if r.random() < 0.15 else r.choice(BROWSER_UAS))
    out = []
    for _ in range(r.randint(1, 6)):
        for _ in range(r.randint(2, 25)):      # page + assets
            t += r.uniform(0.05, 1.5)
            status = 404 if r.random() < 0.04 else (304 if r.random() < 0.1 else 200)
            out.append(_ev(t, ip, "request", status < 400, None, ua, r.choice(NORMAL_PATHS), status))
        t += r.uniform(10, 120)
    return out


def suspicious_scenario(w, t, kind=None):
    r = w.rng
    kind = kind or r.choice(["takeover", "few_fails", "night_new", "probe", "invalid"])
    name = r.choice(list(w.users))
    ip, ua = rand_ip(r), r.choice(BROWSER_UAS + [None])
    lab = "Suspicious"
    out = []
    if kind == "takeover":
        for _ in range(r.randint(2, 4)):
            out.append(_ev(t, ip, "login", False, name, ua, label=lab)); t += r.uniform(5, 40)
        out.append(_ev(t, ip, "login", True, name, ua, label=lab))
        for a in r.sample(["change_password", "checkout", "payment", "view"], 2):
            t += r.uniform(5, 30)
            out.append(_ev(t, ip, a, True, name, ua, "/account", 200, label=lab))
    elif kind == "few_fails":
        for _ in range(r.randint(3, 6)):
            out.append(_ev(t, ip, "login", False, name, ua, label=lab)); t += r.uniform(10, 60)
    elif kind == "night_new":
        out.append(_ev(t, ip, "login", True, name, r.choice(BROWSER_UAS), label=lab))
        t += r.uniform(5, 30)
        out.append(_ev(t, ip, "checkout", True, name, ua, "/checkout", 200, label=lab))
    elif kind == "probe":
        ua = r.choice(BROWSER_UAS)
        for _ in range(r.randint(1, 4)):
            out.append(_ev(t, ip, "request", False, None, ua, r.choice(SCAN_PATHS), 404, label=lab))
            t += r.uniform(1, 20)
    else:  # invalid usernames, a couple of tries
        for _ in range(r.randint(1, 3)):
            out.append(_ev(t, ip, "login", False, r.choice(COMMON_USERNAMES), ua,
                           invalid_user=True, label=lab)); t += r.uniform(2, 30)
    return out


def brute_force(rng, t, target, ip=None, ua="__random__", n=None, label="Malicious", gap=(0.5, 5)):
    ip = ip or rand_ip(rng)
    if ua == "__random__":
        ua = rng.choice(BOT_UAS + BROWSER_UAS[:2] + [None, None])
    out = []
    for _ in range(n or rng.randint(15, 80)):
        out.append(_ev(t, ip, "login", False, target, ua, label=label)); t += rng.uniform(*gap)
    if rng.random() < 0.2:
        out.append(_ev(t, ip, "login", True, target, ua, label=label))
    return out


def credential_stuffing(rng, t, known_users, ip=None, n=None, label="Malicious", gap=(0.3, 3)):
    ip, ua = ip or rand_ip(rng), rng.choice(BOT_UAS + BROWSER_UAS[:1] + [None])
    out = []
    for _ in range(n or rng.randint(20, 80)):
        invalid = rng.random() < 0.5 or not known_users
        name = (rng.choice(COMMON_USERNAMES) + str(rng.randint(0, 99))) if invalid else rng.choice(known_users)
        out.append(_ev(t, ip, "login", False, name, ua, invalid_user=invalid, label=label))
        t += rng.uniform(*gap)
    return out


def bot_scan(rng, t, ip=None, n=None, label="Malicious", gap=(0.1, 1.0)):
    ip, ua = ip or rand_ip(rng), rng.choice(BOT_UAS)
    out = []
    for _ in range(n or rng.randint(30, 150)):
        path = rng.choice(SCAN_PATHS) if rng.random() < 0.7 else f"/{rng.randint(1000, 9999)}.bak"
        out.append(_ev(t, ip, "request", False, None, ua, path, rng.choice([403, 404, 404, 500]), label=label))
        t += rng.uniform(*gap)
    return out


def request_flood(rng, t, ip=None, n=None, label="Malicious", gap=(0.05, 0.3)):
    ip, ua = ip or rand_ip(rng), rng.choice(BOT_UAS + BROWSER_UAS)
    out = []
    for _ in range(n or rng.randint(150, 500)):
        status = 200 if rng.random() < 0.7 else 503
        out.append(_ev(t, ip, "request", status < 400, None, ua, rng.choice(NORMAL_PATHS), status, label=label))
        t += rng.uniform(*gap)
    return out


def generate_training_events(seed=42, days=4, scale=1.0):
    """Return a list of labelled events covering every scenario."""
    rng = random.Random(seed)
    w = World(rng, max(20, int(250 * scale)))
    start = 1_700_000_000
    events = []
    names = list(w.users)
    for name in names:   # registration gives each user a known IP/device
        u = w.users[name]
        events.append(_ev(start - 86400, u["ips"][0], "register", True, name, u["uas"][0]))
        events.append(_ev(start - 86000, u["ips"][0], "login", True, name, u["uas"][0]))
    for _ in range(int(3200 * scale)):
        events += normal_session(w, rng.choice(names), w.daytime_ts(start, days))
    for _ in range(int(900 * scale)):
        events += guest_browse(w, w.daytime_ts(start, days))
    for _ in range(int(700 * scale)):
        kind = rng.choice(["takeover", "few_fails", "night_new", "probe", "invalid"])
        ts = w.night_ts(start, days) if kind == "night_new" or rng.random() < 0.3 else w.daytime_ts(start, days)
        events += suspicious_scenario(w, ts, kind)
    for _ in range(int(170 * scale)):
        t = w.daytime_ts(start, days) if rng.random() < 0.6 else w.night_ts(start, days)
        kind = rng.choice(["bf", "bf", "stuff", "scan", "flood"])
        if kind == "bf":
            events += brute_force(rng, t, rng.choice(names + COMMON_USERNAMES))
        elif kind == "stuff":
            events += credential_stuffing(rng, t, names)
        elif kind == "scan":
            events += bot_scan(rng, t)
        else:
            events += request_flood(rng, t)
    return events


# --------------------------------------------------------------------------
# Live attack simulator (used by the console buttons)
# --------------------------------------------------------------------------

def simulate(kind, target_user, known_users=()):
    rng = random.Random()
    now = time.time() - 30
    if kind == "brute_force":
        return brute_force(rng, now, target_user, n=40, gap=(0.2, 0.8))
    if kind == "credential_stuffing":
        return credential_stuffing(rng, now, list(known_users) or [target_user], n=40, gap=(0.2, 0.6))
    if kind == "bot_scan":
        return bot_scan(rng, now, n=50, gap=(0.1, 0.4))
    if kind == "flood":
        return request_flood(rng, now, n=200, gap=(0.02, 0.1))
    if kind == "new_device":
        ip = rand_ip(rng)
        ua = "Mozilla/5.0 (Linux; Android 10; Unknown) AppleWebKit/537.36 Chrome/90.0 Mobile Safari/537.36"
        evs = [_ev(now + i * 8, ip, "login", False, target_user, ua) for i in range(3)]
        evs.append(_ev(now + 26, ip, "login", True, target_user, ua))
        evs.append(_ev(now + 30, ip, "change_password", True, target_user, ua, "/account", 200))
        return evs
    raise ValueError(f"unknown simulation {kind}")
