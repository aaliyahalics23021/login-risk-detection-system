import os


class Config:
    BASEDIR = os.path.abspath(os.path.dirname(__file__))

    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-change-me")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or (
        "sqlite:///" + os.path.join(BASEDIR, "login_risk.db")
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

