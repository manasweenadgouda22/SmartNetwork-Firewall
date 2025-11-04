import streamlit as st
import pandas as pd
from pathlib import Path
from datetime import datetime, timedelta

from smart_network_firewall_autoblocker.app.detector import detect_events, DetectionConfig
from smart_network_firewall_autoblocker.app.utils import load_firewall_log, load_conn_log, write_block, read_blocklist, ensure_files

st.set_page_config(page_title="Smart Network Firewall Auto-Blocker", layout="wide")

st.title("🔐 Smart Network Firewall Auto-Blocker (Mock Dashboard)")
st.caption("Realtime suspicious network detection + automatic blocklist simulation (no real pfSense needed).")

ensure_files()

# ---- sidebar settings ----
st.sidebar.header("Detection Settings")
lat_win = st.sidebar.slider("Lateral window (minutes)", 5, 60, 10, 5)
lat_min = st.sidebar.slider("Min distinct subnets", 2, 6, 2, 1)
scan_min = st.sidebar.slider("Min ports for scan", 5, 50, 8, 1)
bf_min = st.sidebar.slider("Min failed attempts", 3, 30, 6, 1)
auto_block_threshold = st.sidebar.slider("Auto-block score threshold", 50, 100, 75, 1)

cfg = DetectionConfig(
    lateral_window_min=lat_win,
    lateral_min_subnets=lat_min,
    scan_min_ports=scan_min,
    brute_fail_threshold=bf_min
)

# ---- load logs ----
fw = load_firewall_log()
conn = load_conn_log()

# ---- top metrics ----
col1, col2, col3, col4 = st.columns(4)
col1.metric("Firewall events", f"{len(fw):,}")
col2.metric("Connections", f"{len(conn):,}")
unique_ips = conn['src_ip'].nunique() + conn['dst_ip'].nunique()
col3.metric("Unique IPs observed", f"{unique_ips:,}")
col4.metric("Blocklisted IPs", f"{len(read_blocklist()):,}")

# ---- detection ----
events = detect_events(fw, conn, cfg)

st.subheader("Suspicious Events")
if events.empty:
    st.info("No suspicious events detected with current thresholds.")
else:
    block_now = st.checkbox("Auto-block events above threshold", value=True)
    blocked = read_blocklist()
    to_block = []

    for _, r in events.iterrows():
        if r['score'] >= auto_block_threshold and r['src_ip'] not in blocked:
            to_block.append(r['src_ip'])

    if block_now and to_block:
        for ip in sorted(set(to_block)):
            write_block(ip)

    st.dataframe(events, use_container_width=True)

    st.markdown("### Current Blocklist (simulated)")
    st.code("\n".join(read_blocklist()) or "<empty>")

# ---- simple traffic trend ----
st.subheader("Traffic Volume Trend")
times = conn.set_index('timestamp').resample('1min').size()
st.line_chart(times)

st.markdown("---")
st.caption("Tip: Run `python scripts/generate_mock_traffic.py` locally to refresh logs.")
