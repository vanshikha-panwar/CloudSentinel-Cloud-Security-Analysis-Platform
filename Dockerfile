# CloudSentinel REST API
# Build: docker build -t cloudsentinel-api .
# Run:   docker run -d --rm --name cloudsentinel -p 8000:8000 cloudsentinel-api

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Dependencies first so this layer is cached across code changes
COPY requirements.txt .
RUN pip install -r requirements.txt

# Only what the API needs at runtime:
#   scanner/        security engine (rule engine, policy parser, risk scorer, MITRE mapper)
#   cloudsentinel/  service layer + FastAPI app
#   rules/          rules_config.json (read by GET /rules and the MITRE mapper)
COPY scanner/ scanner/
COPY cloudsentinel/ cloudsentinel/
COPY rules/ rules/

# Run as an unprivileged user
RUN useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).status == 200 else 1)"

CMD ["uvicorn", "cloudsentinel.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
