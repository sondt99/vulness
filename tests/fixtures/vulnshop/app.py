"""vulnshop application entry point.

Registers every blueprint unconditionally, with no feature flags, so every route below is
reachable in any deployment of this app.
"""
import os

from flask import Flask

from api import auth, reports
from storage import files


def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ["VULNSHOP_SESSION_KEY"]
    app.register_blueprint(reports.bp)
    app.register_blueprint(auth.bp)
    app.register_blueprint(files.bp)
    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=8080)
