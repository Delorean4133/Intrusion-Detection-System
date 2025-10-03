# playbook.py
# Simple Flask app to receive alerts and run actions
from flask import Flask, request, jsonify
import subprocess
import logging
from datetime import datetime
import json
import requests

app = Flask(__name__)
logging.basicConfig(filename="playbook.log", level=logging.INFO)

# config
SLACK_WEBHOOK = None  # set to your Slack webhook URL string if you like
AUTO_BLOCK = True     # set False to disable firewall actions
BLOCK_CMD_TEMPLATE = "iptables -I INPUT -s {ip} -j DROP"   # example (Linux). Use cloud API in prod.

def block_ip(ip):
    try:
        cmd = BLOCK_CMD_TEMPLATE.format(ip=ip)
        # For security, don't run destructive commands in untrusted environments without review
        subprocess.run(cmd.split(), check=True)
        return True, cmd
    except Exception as e:
        return False, str(e)

@app.route("/alert", methods=["POST"])
def alert():
    data = request.json or {}
    src_ip = data.get("src_ip")
    score = data.get("score")
    ts = datetime.utcnow().isoformat()
    logging.info(json.dumps({"ts": ts, "alert": data}))
    actions = []
    # Notify Slack/Ticketing
    if SLACK_WEBHOOK:
        try:
            requests.post(SLACK_WEBHOOK, json={"text": f"ALERT: {src_ip} score={score}"}, timeout=3)
            actions.append("slack_notified")
        except:
            actions.append("slack_failed")
    # Block IP
    if AUTO_BLOCK and src_ip:
        ok, info = block_ip(src_ip)
        actions.append(("block_ip", ok, info))
    return jsonify({"status":"ok", "actions": actions})

if __name__ == "__main__":
    app.run(port=9001)
