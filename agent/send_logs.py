"""Ship a network log file to NetGuard Cloud one record at a time (push mode).

    python send_logs.py my_traffic.csv --url http://<server>/api/v1/ingest --key ng_xxx --rate 5

Accepts the same formats as the upload page (NSL-KDD CSV with header, or the raw
KDD .txt format). Only the Python standard library is needed.
"""
import argparse
import csv
import json
import time
import urllib.request

KDD = ("duration,protocol_type,service,flag,src_bytes,dst_bytes,land,wrong_fragment,urgent,hot,num_failed_logins,"
       "logged_in,num_compromised,root_shell,su_attempted,num_root,num_file_creations,num_shells,num_access_files,"
       "num_outbound_cmds,is_host_login,is_guest_login,count,srv_count,serror_rate,srv_serror_rate,rerror_rate,"
       "srv_rerror_rate,same_srv_rate,diff_srv_rate,srv_diff_host_rate,dst_host_count,dst_host_srv_count,"
       "dst_host_same_srv_rate,dst_host_diff_srv_rate,dst_host_same_src_port_rate,dst_host_srv_diff_host_rate,"
       "dst_host_serror_rate,dst_host_srv_serror_rate,dst_host_rerror_rate,dst_host_srv_rerror_rate,label,"
       "difficulty").split(",")

ap = argparse.ArgumentParser()
ap.add_argument("file")
ap.add_argument("--url", required=True)
ap.add_argument("--key", required=True)
ap.add_argument("--rate", type=float, default=5, help="records per second")
args = ap.parse_args()

with open(args.file, newline="") as f:
    first = f.readline()
    f.seek(0)
    reader = csv.DictReader(f) if "protocol_type" in first else csv.DictReader(f, fieldnames=KDD)
    for i, row in enumerate(reader, 1):
        row.pop("difficulty", None)
        row["ts"] = time.time()
        req = urllib.request.Request(args.url, json.dumps(row).encode(),
                                     {"Content-Type": "application/json", "X-API-Key": args.key})
        print(i, urllib.request.urlopen(req, timeout=10).read().decode())
        time.sleep(1 / args.rate)
