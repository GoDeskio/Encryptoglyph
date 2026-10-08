FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

ENV BUILD_SHA=unknown \
    PYTHONDONTWRITEBYTECODE=1
EXPOSE 8000

USER nobody

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
