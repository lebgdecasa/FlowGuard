FROM python:3.10.6-buster

WORKDIR /app

COPY requirements.txt requirements.txt

RUN pip install --upgrade pip
RUN pip install -r requirements.txt

COPY backend/ backend/
COPY frontend/ frontend

ENV PORT 8080

CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT} backend.api:app"]
