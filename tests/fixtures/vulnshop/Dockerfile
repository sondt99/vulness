# Fixture deployment context. Present so the judge stage can establish that the routes
# are actually exposed, rather than reporting needs_deployment_fact for everything.
FROM python:3.12-slim
WORKDIR /srv
COPY . /srv
RUN pip install --no-cache-dir flask
EXPOSE 8080
CMD ["python", "app.py"]
