"""Gunicorn settings used by Render / Docker.

One worker process with threads: the log pipeline (queue + stream worker) lives
in-process, so every request must reach the same process. Scale out by moving
the queue to a managed service (see docs/CLOUD_CONCEPTS.md).
"""
import os

bind = f"0.0.0.0:{os.environ.get('PORT', '10000')}"
workers = 1
threads = int(os.environ.get("THREADS", "8"))
timeout = 120
accesslog = "-"
errorlog = "-"
