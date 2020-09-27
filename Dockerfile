
FROM python:3.8-slim
WORKDIR /cisco-dnac-network-devices-cfg-backup-aws/
COPY ./ ./
RUN pip install -r requirements.txt
ENTRYPOINT ["python", "run.py"]
