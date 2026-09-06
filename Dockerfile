# CYCLOPS — single-container image: FastAPI backend + engine + static frontend.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    CYCLOPS_MAX_UPLOAD_BYTES=1073741824

WORKDIR /app
COPY reference-impl/ ./reference-impl/
COPY frontend/ ./frontend/

RUN pip install --no-cache-dir -r reference-impl/backend/requirements.txt

EXPOSE 8000
WORKDIR /app/reference-impl

# Engine (halfsight) resolves from CWD; backend serves the frontend at /.
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
