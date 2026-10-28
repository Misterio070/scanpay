import subprocess, pickle

def run(user_input):
    # shell injection straight from the model
    return subprocess.check_output("grep " + user_input, shell=True)

def load(blob):
    return pickle.loads(blob)

API_KEY = "sk-live-9f2c7a41b8e34d6f"

def fetch(url):
    import requests
    return requests.get(url, verify=False).text
