"""App configuration."""
from os import environ, path
import logging.config
import json

DEFAULT_ENV = environ.get('DEFAULT_ENV')
cred_file = environ.get('CRED_FILE')
root_path = path.dirname(path.realpath(__file__))

with open(root_path + f'/certs/gcp/{cred_file}', 'r') as f:
    config = json.load(f)


class BaseConfig:
    """Set Flask configuration vars from .env file."""
    # General Config
    FLASK_ENV = 'development'
    ENV = 'development'
    # environ.get('SECRET_KEY')
    SECRET_KEY = 'r4nd0Mk3y*'

    FLASK_DEBUG = True
    DEBUG = True

    # Database configuration
    SQLALCHEMY_DATABASE_URI = environ.get('DB_URI')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MONITOR_TASKS_TRACER = environ.get("MONITOR_TASKS_TRACER")

    # GCP keys
    GKMS_KEY = f"{root_path}/certs/gcp/" + environ.get("KMS_FILE")
    KMS_PJ_ID = config["kms_project_id"]
    KMS_LOCATION = config["kms_location"]
    KMS_KEY_RING_ID = config["key_ring_id"]
    KMS_KEY = config["key_id"]


class LocalConfig(BaseConfig):
    # docker, ip container (sudo docker network inspect bridge)
    pass


class DevConfig(BaseConfig):
    pass


class ProdConfig(BaseConfig):
    FLASK_ENV = 'production'
    DEBUG = False
    SECRET_KEY = 't4ps3cr2Tk3Y.'


app_config = {"local": LocalConfig,
              "development": DevConfig,
              "production": ProdConfig}
