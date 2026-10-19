FROM public.ecr.aws/docker/library/python:3.12-slim
WORKDIR /app
# Real NSL-KDD test traffic (incl. 17 attack types never seen in training)
RUN python -c "import urllib.request,os; os.makedirs('/data',exist_ok=True); urllib.request.urlretrieve('https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt','/data/KDDTest+.txt')"
COPY streamer.py .
ENV PYTHONUNBUFFERED=1 PORT=9000
EXPOSE 9000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:9000/health')"
CMD ["python", "streamer.py"]
