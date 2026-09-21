"""vulnshop application entry point.

Registers every blueprint unconditionally, with no feature flags, so the routes below are
reachable in any deployment of this app. The fixture needs this: without a wiring point,
reachability cannot be established from source and the judge stage correctly refuses to
call anything exploitable.
"""
from flask import Flask

from api import auth, reports
from storage import files


def create_app():
    app = Flask(__name__)
    app.secret_key = "fixture-only-not-a-real-secret"
    app.register_blueprint(reports.bp)
    app.register_blueprint(auth.bp)
    app.register_blueprint(files.bp)
    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=8080)
