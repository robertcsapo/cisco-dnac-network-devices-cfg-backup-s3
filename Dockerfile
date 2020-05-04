
FROM python:3.8-alpine
WORKDIR /cisco-dnac-network-devices-cfg-backup-aws/
COPY ./ ./
RUN pip install -r requirements.txt
ENTRYPOINT ["python", "run.py"]
