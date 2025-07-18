FROM python:3.10.6-buster

WORKDIR /app

COPY requirements.txt .

RUN pip install --upgrade pip
RUN pip install -r requirements.txt

COPY backend/ backend/
COPY frontend/ frontend/
COPY .streamlit/ .streamlit/

ENV PORT=8080

CMD ["uvicorn", "backend.api:app", "--host", "0.0.0.0", "--port", "8080"]
