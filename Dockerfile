FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

ENV APP_PORT=8082
EXPOSE 8082

# Run as an unprivileged user (SOC 2 CC6.8: containers must not run as root).
RUN useradd --system --uid 1001 --user-group --no-create-home appuser \
    && chown -R appuser:appuser /app
USER appuser

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${APP_PORT}"]
