FROM python:3.11-alpine

RUN apk add --no-cache iptables

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY *.py .
COPY config.yaml .

RUN mkdir -p /var/log/detector

CMD ["python", "main.py"]
