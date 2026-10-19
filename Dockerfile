# NetGuard web app + AIML models
FROM public.ecr.aws/docker/library/python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8000 DATABASE_PATH=/data/netguard.db
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY aiml/ aiml/
COPY web/ web/
# Download NSL-KDD and train the AIML detectors at build time (~30 s), so containers start instantly
RUN cd web && python -m engine > /dev/null

WORKDIR /app/web
VOLUME /data
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"
CMD ["gunicorn", "-c", "gunicorn.conf.py", "app:app"]
