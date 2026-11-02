FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY classifier/ classifier/
COPY engine.py mitigation.py suricata_alerts.py incidents.py state_store.py policy_state.py ./
EXPOSE 9300
CMD ["uvicorn", "engine:app", "--host", "0.0.0.0", "--port", "9300"]
