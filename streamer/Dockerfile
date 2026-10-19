# Built from the repo root (see docker-compose.yml) so it can copy the bundled dataset.
FROM public.ecr.aws/docker/library/python:3.12-slim
WORKDIR /app
# Real NSL-KDD test traffic (incl. 17 attack types never seen in training), shipped in the repo
COPY aiml/data/raw/KDDTest+.txt /data/KDDTest+.txt
COPY streamer/streamer.py .
ENV PYTHONUNBUFFERED=1 PORT=9000
EXPOSE 9000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:9000/health')"
CMD ["python", "streamer.py"]
