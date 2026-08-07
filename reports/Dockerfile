FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir jinja2==3.1.4
COPY generate_report.py .
COPY templates/ templates/
CMD ["python", "generate_report.py"]
