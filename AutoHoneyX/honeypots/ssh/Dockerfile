FROM python:3.11-slim
WORKDIR /app
# COPY from project root because compose build context is project root
COPY honeypots/ssh/server.py /app/server.py
EXPOSE 2222
CMD ["python", "server.py"]
