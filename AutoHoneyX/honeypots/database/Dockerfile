FROM python:3.11-slim
WORKDIR /app
# COPY using project-root relative path (compose context)
COPY honeypots/database/app.py /app/app.py
RUN pip install --no-cache-dir flask
EXPOSE 3307
CMD ["python", "app.py"]
