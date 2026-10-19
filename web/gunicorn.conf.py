"""One worker process (the stream pipeline and feed readers live in-process), many threads."""
import os

bind = f"0.0.0.0:{os.environ.get('PORT', '8000')}"
workers = 1
threads = int(os.environ.get("THREADS", "16"))
timeout = 300            # large uploads (100k connections) take a while
accesslog = "-"
access_log_format = '{"time":"%(t)s","logger":"access","method":"%(m)s","path":"%(U)s","status":%(s)s,"ms":%(M)s,"ip":"%({x-forwarded-for}i)s"}'
errorlog = "-"
