# Smart Network Firewall Auto-Blocker 

**Goal:** Detect suspicious cross-subnet activity and *simulate* auto-blocking by maintaining a local blocklist. Visualize everything with a real-time dashboard.



## Features
- Parses sample firewall and connection logs
- Detects lateral movement attempts, simple port scans, and brute-force patterns
- Simulates auto-block by writing the offender IP to `data/blocklist.txt`
- Streamlit dashboard with live-ish refresh, event table, and metrics
- Clean, beginner-friendly Python architecture

---

## Folder Layout
```
smart-network-firewall-autoblocker/
  app/
    streamlit_app.py     # Dashboard UI
    detector.py          # Detection logic
    utils.py             # Helpers (IO, parsing, subnet ops)
  data/
    sample_logs/
      firewall_log.csv   # Example firewall events
      conn_log.csv       # Example connection/flow events
    blocklist.txt        # Simulated blocklist (created at runtime)
  scripts/
    generate_mock_traffic.py  # Generate synthetic logs
  .gitignore
  LICENSE
  README.md
  requirements.txt
```

---

## Quick Start

### 1) Create a virtual environment (recommended)
```bash
python3 -m venv .venv
source .venv/bin/activate   # macOS/Linux
# .venv\Scripts\activate  # Windows PowerShell
```

### 2) Install dependencies
```bash
pip install -r requirements.txt
```

### 3) (Optional) Regenerate the sample logs
```bash
python scripts/generate_mock_traffic.py
```

### 4) Run the dashboard
```bash
streamlit run app/streamlit_app.py
```

Open the URL shown in the terminal (usually http://localhost:8501).

---

## How Detection Works (High-Level)
We compute simple signals from logs:
- **Lateral movement:** same source IP touching hosts across *multiple internal subnets* in a short window.
- **Port scan:** same source IP hitting *many distinct ports* on a target or targets.
- **Brute force-like:** same source IP creating *many failed* connection attempts.

If a score crosses a threshold, we **simulate a block** by appending the IP to `data/blocklist.txt`.

> These heuristics are easy to read, and you can replace them later with ML (RandomForest / IsolationForest) when you collect more data.

---

## Upgrade Path (when you're ready)
- Replace simulated blocklist with a real **pfSense REST API** client.
- Add Zeek/Suricata parsing and richer features.
- Add an ML model for anomaly scoring (features are scaffolded).

---

## Resume-Ready Bullet (you can use this)
- Built a real-time dashboard that detects suspicious cross-subnet activity and **auto-blocks** offender IPs (simulated) with Python + Streamlit, demonstrating practical network defense automation and incident visualization.
