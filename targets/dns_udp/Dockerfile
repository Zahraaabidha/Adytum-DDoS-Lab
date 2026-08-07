FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir prometheus-client==0.20.0
COPY server.py .
EXPOSE 5300/udp 9200
CMD ["python", "server.py"]
