FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AGENTSEC_DATABASE=/var/lib/agentsec/workbench.db

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --disable-pip-version-check -r requirements.txt \
    && mkdir -p /var/lib/agentsec \
    && chown 10001:10001 /var/lib/agentsec

COPY agentsec/ agentsec/
COPY samples/ samples/
COPY evals/ evals/
COPY recordings/ recordings/
USER 10001:10001
EXPOSE 8000

CMD ["python", "-m", "uvicorn", "agentsec.main:app", "--host", "0.0.0.0", "--port", "8000"]
