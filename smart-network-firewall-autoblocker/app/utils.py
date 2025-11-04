from __future__ import annotations
import ipaddress
import pandas as pd
from pathlib import Path
import time

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
SAMPLE_DIR = DATA_DIR / "sample_logs"
BLOCKLIST = DATA_DIR / "blocklist.txt"

def ensure_files():
    DATA_DIR.mkdir(exist_ok=True, parents=True)
    SAMPLE_DIR.mkdir(exist_ok=True, parents=True)
    if not BLOCKLIST.exists():
        BLOCKLIST.write_text("", encoding="utf-8")


def load_firewall_log() -> pd.DataFrame:
    path = SAMPLE_DIR / "firewall_log.csv"
    df = pd.read_csv(path)
    # enforce dtypes
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df.sort_values('timestamp')


def load_conn_log() -> pd.DataFrame:
    path = SAMPLE_DIR / "conn_log.csv"
    df = pd.read_csv(path)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df.sort_values('timestamp')


def write_block(ip: str):
    # append to blocklist
    ensure_files()
    with open(BLOCKLIST, "a", encoding="utf-8") as f:
        f.write(f"{ip}\n")
    # give filesystem a breath
    time.sleep(0.05)


def read_blocklist() -> list[str]:
    ensure_files()
    text = BLOCKLIST.read_text(encoding="utf-8")
    ips = [line.strip() for line in text.splitlines() if line.strip()]
    return ips


def is_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # RFC1918 ranges typical for labs
    private_ranges = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
    ]
    return any(addr in rng for rng in private_ranges)


def subnet_of(ip: str, prefix: int = 24) -> str:
    try:
        net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        return str(net.network_address) + f"/{prefix}"
    except ValueError:
        return "unknown/24"