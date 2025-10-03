# log_ingest.py
# Simple UDP syslog listener that writes raw messages to logs.csv
# Run: python log_ingest.py
import socket
import csv
from datetime import datetime

UDP_IP = "0.0.0.0"
UDP_PORT = 5514   # non-privileged example port
OUT_CSV = "logs.csv"

header_written = False
try:
    with open(OUT_CSV, "r"):
        header_written = True
except FileNotFoundError:
    header_written = False

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))
print(f"Listening for UDP syslog on {UDP_IP}:{UDP_PORT} -> saving to {OUT_CSV}")

with open(OUT_CSV, "a", newline='') as csvfile:
    writer = csv.writer(csvfile)
    if not header_written:
        writer.writerow(["timestamp", "src_ip", "raw"])
    while True:
        data, addr = sock.recvfrom(65536)
        msg = data.decode(errors='replace').strip()
        src_ip = addr[0]
        ts = datetime.utcnow().isoformat()
        writer.writerow([ts, src_ip, msg])
        csvfile.flush()
        print(f"{ts} {src_ip} {msg[:120]}")
