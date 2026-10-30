FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi==0.115.0 uvicorn[standard]==0.30.6 httpx==0.27.2 prometheus-client==0.20.0
COPY proxy.py limiter.py ./
EXPOSE 8080
CMD ["uvicorn", "proxy:app", "--host", "0.0.0.0", "--port", "8080"]
