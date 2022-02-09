#!/bin/sh


# 1. Set up Python virtualenv and install requirements

python -m venv env
source env/bin/activate
pip install ignition-gemini 
deactivate


# 2. Generate certificates

openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 3650 -nodes -subj "/CN=localhost"
