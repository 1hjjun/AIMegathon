FROM python:3.13-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY runtime_app.py /app/runtime_app.py
COPY container_server.py /app/container_server.py
COPY patch_runtime /app/patch_runtime

EXPOSE 8080

CMD ["python", "container_server.py"]
