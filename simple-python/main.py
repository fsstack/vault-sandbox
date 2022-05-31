#!/usr/bin/env python3

import json
import logging
import os

import requests
from flask import Flask, jsonify


class VaultClient:
    def __init__(self, token, addr):
        self.token = token
        self.addr = addr
        self.addrSecretPathPrefix = f"{addr}/v1/secret/data"
        self.headers = {"X-Vault-Token": token, "Content-Type": "application/json"}

    def isAuthenticated(self):
        url = f"{self.addr}/v1/auth/token/lookup-self"
        try:
            r = requests.get(url=url, headers=self.headers)
            r.raise_for_status()
            return True
        except requests.exceptions.HTTPError as e:
            logging.critical("Not authenticated")
            logging.critical(e)
            return False

    def getSecret(self, path):
        url = f"{self.addrSecretPathPrefix}/{path}"
        try:
            r = requests.get(url=url, headers=self.headers)
            r.raise_for_status()
            return r.json()["data"]
        except requests.exceptions.HTTPError as e:
            logging.critical("Unable to get secret from vault!")
            logging.critical(e)
            return e

    def putSecret(self, path, secretData):
        url = f"{self.addrSecretPathPrefix}/{path}"
        payload = {"data": secretData}
        try:
            r = requests.post(url=url, headers=self.headers, data=json.dumps(payload))
            r.raise_for_status()
            return r.json()["data"]["version"]
        except requests.exceptions.HTTPError as e:
            logging.critical("Unable to put secret in vault!")
            logging.critical(e)
            return e

    def __str__(self) -> str:
        return f"token: {self.token}, addr: {self.addr}"


app = Flask(__name__)


@app.route("/")
def root():
    vaultToken = "root"
    vaultAddr = "http://127.0.0.1:8200"
    secretPath = "foo"
    secretData = {"password": "tyson123"}
    client = VaultClient(vaultToken, vaultAddr)
    writeVersion = client.putSecret(secretPath, secretData)
    readVersion = client.getSecret(secretPath)["metadata"]["version"]

    return jsonify(
        {
            "successful": writeVersion == readVersion,
            "writeVersion": writeVersion,
            "readVersion": readVersion,
        }
    )


if __name__ == "__main__":
    logLevel = os.getenv("LOG_LEVEL", "info").upper()
    logging.basicConfig(level=logLevel)
    app.run()
