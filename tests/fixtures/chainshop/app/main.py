"""Internal ops console. Entry point; every blueprint is registered unconditionally."""
from flask import Flask

from app import admin, profile

def create_app():
    app = Flask(__name__)
    app.secret_key = __import__("secrets").token_hex(32)
    app.register_blueprint(profile.bp)
    app.register_blueprint(admin.bp)
    return app

if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=9000)
