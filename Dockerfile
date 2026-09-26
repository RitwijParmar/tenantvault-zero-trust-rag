FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY web ./web
COPY policies ./policies
COPY migrations ./migrations
RUN pip install --no-cache-dir .

ENV APP_ROOT=/app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
RUN useradd --create-home --shell /usr/sbin/nologin appuser && chown -R appuser:appuser /app
USER appuser
EXPOSE 8080
CMD ["sh", "-c", "uvicorn tenantvault.api:app --host 0.0.0.0 --port ${PORT:-8080}"]
