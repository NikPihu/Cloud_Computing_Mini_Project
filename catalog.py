"""Static store catalogue and the security services users can subscribe to."""

PRODUCTS = [
    {"id": 1, "name": "Nova X5 Smartphone, 8GB RAM, 256GB", "category": "Electronics", "price": 18999, "mrp": 24999, "rating": 4.4, "reviews": 12873, "icon": "📱", "tone": "#dbeafe"},
    {"id": 2, "name": "AirBeat Pro Wireless Earbuds with ANC", "category": "Electronics", "price": 2499, "mrp": 5999, "rating": 4.1, "reviews": 30412, "icon": "🎧", "tone": "#ede9fe"},
    {"id": 3, "name": "UltraBook 14 Laptop, Ryzen 7, 16GB, 512GB SSD", "category": "Computers", "price": 58990, "mrp": 72000, "rating": 4.5, "reviews": 2391, "icon": "💻", "tone": "#e0f2fe"},
    {"id": 4, "name": "Pulse Smartwatch with AMOLED Display", "category": "Electronics", "price": 3299, "mrp": 7999, "rating": 4.0, "reviews": 8820, "icon": "⌚", "tone": "#fce7f3"},
    {"id": 5, "name": "Mechanical Keyboard, Hot-swappable, RGB", "category": "Computers", "price": 3799, "mrp": 5499, "rating": 4.6, "reviews": 4112, "icon": "⌨️", "tone": "#f1f5f9"},
    {"id": 6, "name": "4K Action Camera, Waterproof 40m", "category": "Electronics", "price": 7499, "mrp": 12999, "rating": 4.2, "reviews": 1905, "icon": "📷", "tone": "#fef3c7"},
    {"id": 7, "name": "Cloud Computing: Concepts & Architecture (Book)", "category": "Books", "price": 549, "mrp": 799, "rating": 4.7, "reviews": 932, "icon": "📘", "tone": "#dbeafe"},
    {"id": 8, "name": "Hands-on Machine Learning (Book)", "category": "Books", "price": 899, "mrp": 1299, "rating": 4.8, "reviews": 5610, "icon": "📗", "tone": "#dcfce7"},
    {"id": 9, "name": "Ergonomic Office Chair with Lumbar Support", "category": "Home", "price": 6999, "mrp": 13999, "rating": 4.3, "reviews": 3477, "icon": "🪑", "tone": "#fee2e2"},
    {"id": 10, "name": "Stainless Steel Water Bottle, 1L", "category": "Home", "price": 449, "mrp": 899, "rating": 4.5, "reviews": 21008, "icon": "🧴", "tone": "#cffafe"},
    {"id": 11, "name": "Running Shoes, Lightweight Mesh", "category": "Fashion", "price": 1899, "mrp": 3999, "rating": 4.1, "reviews": 9921, "icon": "👟", "tone": "#ffedd5"},
    {"id": 12, "name": "Classic Analog Wrist Watch", "category": "Fashion", "price": 1299, "mrp": 2999, "rating": 4.0, "reviews": 4410, "icon": "🕰️", "tone": "#f5f5f4"},
    {"id": 13, "name": "Wi-Fi 6 Dual-band Router", "category": "Computers", "price": 2899, "mrp": 4999, "rating": 4.3, "reviews": 6720, "icon": "📶", "tone": "#e0e7ff"},
    {"id": 14, "name": "Portable SSD 1TB, USB-C", "category": "Computers", "price": 6499, "mrp": 9999, "rating": 4.6, "reviews": 3302, "icon": "💾", "tone": "#f3e8ff"},
    {"id": 15, "name": "Smart LED Bulb (Pack of 4)", "category": "Home", "price": 999, "mrp": 1999, "rating": 4.2, "reviews": 15540, "icon": "💡", "tone": "#fef9c3"},
    {"id": 16, "name": "Backpack for Laptops up to 15.6\"", "category": "Fashion", "price": 1149, "mrp": 2499, "rating": 4.4, "reviews": 11870, "icon": "🎒", "tone": "#e2e8f0"},
]
PRODUCTS_BY_ID = {p["id"]: p for p in PRODUCTS}
CATEGORIES = sorted({p["category"] for p in PRODUCTS})

SERVICES = {
    "live_protection": {
        "name": "Live Account Protection", "icon": "🛡️", "price": "Free",
        "tagline": "Every login and action on your account streams through our real-time "
                   "pipeline and is scored as Normal, Suspicious or Malicious within seconds.",
        "endpoint": "live_monitor", "input": "Live pipeline",
    },
    "log_analyzer": {
        "name": "Log File Analyzer", "icon": "📄", "price": "Free",
        "tagline": "Upload a CSV, SSH/Linux auth log or Apache/Nginx access log and get a full "
                   "threat report with graphs.",
        "endpoint": "analyze", "input": "File upload",
    },
    "cloud_import": {
        "name": "Cloud Log Import", "icon": "☁️", "price": "Free",
        "tagline": "Pull logs straight from a URL (S3/GCS public link, GitHub raw, dataset mirrors) "
                   "or pick one of our curated public security datasets.",
        "endpoint": "analyze", "input": "From URL",
    },
    "alerts": {
        "name": "Instant Threat Alerts", "icon": "🚨", "price": "Free",
        "tagline": "Get a Discord or Slack message the moment a Malicious event hits your account.",
        "endpoint": "services", "input": "Notifications",
    },
}

# Curated public log datasets that our parsers understand (option 3: "From URL").
PUBLIC_DATASETS = [
    {"key": "sample", "name": "ShopSecure labelled login sample (ground truth included)",
     "url": "builtin:sample", "format": "CSV", "size": "~3k events",
     "about": "Store logins & activity with true labels, so you also get accuracy / precision / recall."},
    {"key": "openssh", "name": "Loghub - OpenSSH server log (real brute-force traffic)",
     "url": "https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log",
     "format": "SSH auth log", "size": "2k lines",
     "about": "Real sshd log from a lab server exposed to the internet (Loghub, CUHK)."},
    {"key": "openssh_csv", "name": "Loghub - OpenSSH structured CSV",
     "url": "https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log_structured.csv",
     "format": "CSV", "size": "2k rows", "about": "Same SSH log, pre-parsed into columns."},
    {"key": "linux", "name": "Loghub - Linux syslog (auth failures)",
     "url": "https://raw.githubusercontent.com/logpai/loghub/master/Linux/Linux_2k.log",
     "format": "Linux syslog", "size": "2k lines",
     "about": "Linux system log with PAM authentication failures and sessions."},
    {"key": "apache", "name": "Elastic - Apache web access logs",
     "url": "https://raw.githubusercontent.com/elastic/examples/master/Common%20Data%20Formats/apache_logs/apache_logs",
     "format": "Apache access log", "size": "10k lines",
     "about": "Real website traffic incl. crawlers, bots and scanners."},
]
