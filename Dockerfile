FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY gateway ./gateway
COPY detector ./detector
COPY manifests ./manifests
COPY registry ./registry
COPY baselines ./baselines
COPY dashboard ./dashboard
COPY eval ./eval

RUN useradd -r -u 10001 aidds && mkdir -p /data && chown aidds /data
ENV AIDDS_DATABASE_URL=sqlite+aiosqlite:////data/aidds.db
VOLUME /data
USER aidds

EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz')"
CMD ["uvicorn", "gateway.main:app", "--host", "0.0.0.0", "--port", "8000"]
