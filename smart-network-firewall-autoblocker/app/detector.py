from __future__ import annotations
import pandas as pd
from dataclasses import dataclass
from typing import List, Dict, Any
from .utils import is_internal, subnet_of


@dataclass
class DetectionConfig:
    lateral_window_min: int = 10    # time window in minutes to look for cross-subnet moves
    lateral_min_subnets: int = 2    # if a source hits >= this many distinct /24 subnets -> suspicious
    scan_min_ports: int = 8         # distinct ports from same src to same dst or many dsts
    brute_fail_threshold: int = 6   # failed attempts per src


def detect_events(fw: pd.DataFrame, conn: pd.DataFrame, cfg: DetectionConfig) -> pd.DataFrame:
    """Return a DataFrame of suspicious events with a score and reason."""

    # -------- FIX TYPE ISSUE --------
    fw['timestamp'] = pd.to_datetime(fw['timestamp'], errors='coerce')
    conn['timestamp'] = pd.to_datetime(conn['timestamp'], errors='coerce')
    # --------------------------------

    # Basic normalization
    df = conn.copy()
    df['is_internal_src'] = df['src_ip'].apply(is_internal)
    df['is_internal_dst'] = df['dst_ip'].apply(is_internal)
    df['src_subnet'] = df['src_ip'].apply(lambda x: subnet_of(x, 24))
    df['dst_subnet'] = df['dst_ip'].apply(lambda x: subnet_of(x, 24))

    events: List[Dict[str, Any]] = []

    # 1) Lateral movement heuristic: internal src touching multiple internal dst subnets in a window
    window = f"{cfg.lateral_window_min}min"
    tmp = df[df['is_internal_src'] & df['is_internal_dst']].copy()
    if not tmp.empty:
        tmp = tmp.set_index('timestamp').sort_index()
        grouped = tmp.groupby('src_ip').rolling(window=window)['dst_subnet'].apply(lambda s: s.nunique()).reset_index()
        grouped.rename(columns={'dst_subnet': 'distinct_dst_subnets'}, inplace=True)
        merged = tmp.reset_index().merge(grouped, on=['timestamp','src_ip'], how='left')
        lateral_hits = merged[merged['distinct_dst_subnets'] >= cfg.lateral_min_subnets]
        for _, r in lateral_hits.iterrows():
            score = 60 + (r['distinct_dst_subnets'] - cfg.lateral_min_subnets) * 10
            events.append({
                'timestamp': r['timestamp'],
                'src_ip': r['src_ip'],
                'dst_ip': r['dst_ip'],
                'event': 'lateral_move_suspect',
                'score': min(100, score),
                'detail': f"crossed {int(r['distinct_dst_subnets'])} internal subnets in {cfg.lateral_window_min}m"
            })

    # 2) Port scan heuristic: many ports from same src to same dst (or many dsts)
    by_src_dst = df.groupby(['src_ip','dst_ip']).agg(distinct_ports=('dst_port','nunique'),
                                                     first_time=('timestamp','min')).reset_index()
    scan_hits = by_src_dst[by_src_dst['distinct_ports'] >= cfg.scan_min_ports]
    for _, r in scan_hits.iterrows():
        events.append({
            'timestamp': r['first_time'],
            'src_ip': r['src_ip'],
            'dst_ip': r['dst_ip'],
            'event': 'port_scan_suspect',
            'score': min(100, 70 + (r['distinct_ports'] - cfg.scan_min_ports) * 2),
            'detail': f"{r['distinct_ports']} distinct ports to {r['dst_ip']}"
        })

    # 3) Brute-force-like: many failed or short connections by same src
    if 'status' in df.columns:
        fails = df[df['status'].str.lower().str.contains('fail', na=False)]
        bf_src = fails.groupby('src_ip').size().reset_index(name='fail_count')
        bf_hits = bf_src[bf_src['fail_count'] >= cfg.brute_fail_threshold]
        for _, r in bf_hits.iterrows():
            first_time = fails[fails['src_ip']==r['src_ip']]['timestamp'].min()
            events.append({
                'timestamp': first_time,
                'src_ip': r['src_ip'],
                'dst_ip': 'multiple',
                'event': 'bruteforce_suspect',
                'score': min(100, 65 + (r['fail_count'] - cfg.brute_fail_threshold) * 3),
                'detail': f"{int(r['fail_count'])} failed attempts"
            })

    out = pd.DataFrame(events).sort_values('timestamp') if events else pd.DataFrame(columns=['timestamp','src_ip','dst_ip','event','score','detail'])
    return out
