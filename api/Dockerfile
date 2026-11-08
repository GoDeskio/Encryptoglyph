FROM python:3.12-slim

WORKDIR /app

COPY api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY api/main.py /app/main.py
COPY api/eg_crypto /app/eg_crypto
COPY api/eg_api /app/eg_api
COPY console /app/console
COPY VERSION /app/VERSION

ENV BUILD_SHA=unknown \
    PYTHONDONTWRITEBYTECODE=1
EXPOSE 8000

USER nobody

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
