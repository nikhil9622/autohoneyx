FROM python:3.11-slim
WORKDIR /app
# COPY from project root because compose build context is project root
COPY honeypots/ssh/server.py /app/server.py
RUN pip install --no-cache-dir paramiko redis
EXPOSE 2222
CMD ["python", "server.py"]
