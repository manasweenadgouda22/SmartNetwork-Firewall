import random
import pandas as pd
from datetime import datetime, timedelta
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
DATA = BASE / 'data' / 'sample_logs'
DATA.mkdir(parents=True, exist_ok=True)

start = datetime.now().replace(second=0, microsecond=0) - timedelta(minutes=60)

def rand_ip(private=True):
    if not private and random.random() < 0.2:
        return f"{random.randint(20,220)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    # internal ranges: 172.21.x.x / 172.23.x.x / 192.168.1.x
    choice = random.choice(['172.21', '172.23', '192.168.1'])
    return f"{choice}.{random.randint(0,255)}.{random.randint(1,254)}"

def gen_conn_log(n=1800):
    rows = []
    cur = start
    for i in range(n):
        cur += timedelta(seconds=random.randint(1, 3))
        src = rand_ip()
        dst = rand_ip()
        port = random.choice([22, 80, 443, 445, 3389, 53, 8080, 21, 25, 135, 139])
        status = random.choice(['ok','ok','ok','fail'])  # ~25% fail
        rows.append({
            'timestamp': cur.isoformat(),
            'src_ip': src,
            'dst_ip': dst,
            'dst_port': port,
            'status': status
        })
    # Inject a port scan
    scan_src = rand_ip()
    scan_dst = rand_ip()
    t0 = start + timedelta(minutes=40)
    for p in range(20, 20+18):  # 18 ports
        t0 += timedelta(seconds=5)
        rows.append({
            'timestamp': t0.isoformat(),
            'src_ip': scan_src,
            'dst_ip': scan_dst,
            'dst_port': p,
            'status': 'ok'
        })
    # Inject lateral movement (same src hitting different subnets quickly)
    lm_src = rand_ip()
    lm_time = start + timedelta(minutes=50)
    for k in range(6):
        lm_time += timedelta(seconds=30)
        dst = random.choice(["172.21.%d.%d" % (random.randint(0,255), random.randint(1,254)),
                             "172.23.%d.%d" % (random.randint(0,255), random.randint(1,254)),
                             "192.168.1.%d" % random.randint(1,254)])
        rows.append({
            'timestamp': lm_time.isoformat(),
            'src_ip': lm_src,
            'dst_ip': dst,
            'dst_port': random.choice([22,445,3389,80,443]),
            'status': random.choice(['ok','fail'])
        })
    # Inject brute-force (many fails from one IP)
    bf_src = rand_ip()
    bf_time = start + timedelta(minutes=55)
    for _ in range(12):
        bf_time += timedelta(seconds=8)
        rows.append({
            'timestamp': bf_time.isoformat(),
            'src_ip': bf_src,
            'dst_ip': rand_ip(),
            'dst_port': 22,
            'status': 'fail'
        })
    df = pd.DataFrame(rows)
    df = df.sort_values('timestamp')
    df.to_csv(DATA / 'conn_log.csv', index=False)

def gen_fw_log(n=400):
    rows = []
    cur = start
    for i in range(n):
        cur += timedelta(seconds=random.randint(5, 12))
        src = rand_ip()
        dst = rand_ip()
        action = random.choice(['allow','allow','block'])
        rows.append({
            'timestamp': cur.isoformat(),
            'action': action,
            'src_ip': src,
            'dst_ip': dst,
            'proto': random.choice(['tcp','udp']),
            'dst_port': random.choice([22,80,443,445,3389,53,8080])
        })
    df = pd.DataFrame(rows)
    df = df.sort_values('timestamp')
    df.to_csv(DATA / 'firewall_log.csv', index=False)

if __name__ == '__main__':
    gen_conn_log()
    gen_fw_log()
    print("Sample logs regenerated in:", DATA)