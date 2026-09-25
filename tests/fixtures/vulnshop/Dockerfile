FROM python:3.12-slim
WORKDIR /srv
COPY . /srv
RUN pip install --no-cache-dir flask
EXPOSE 8080
CMD ["python", "app.py"]
