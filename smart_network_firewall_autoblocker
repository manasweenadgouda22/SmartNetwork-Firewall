# Smart Network Firewall Auto-Blocker

A small SOC-style project where I analyze network traffic logs and automatically identify suspicious IPs.
The goal is to act like a “mini firewall brain” that can detect abnormal connections and suggest which IPs should be blocked.

I built this so I can practice network engineering concepts + security analysis in one project.

---

## 🔍 What this tool does

1. I take raw connection logs (source IP, destination IP, timestamps, ports)
2. I detect risky patterns (ex: too many connections, weird endpoints, repeated hits)
3. I give a **risk score** for each IP
4. I output a **block list** based on the score
5. I visualize everything in a clean dashboard (Streamlit)

So this acts like a “thinking layer” on top of a firewall.

---

## 🧠 Why this project matters (for Network Engineering)

This is not just coding.
This project uses **real networking concepts**:

| Networking Concept  | How I used it                                            |
| ------------------- | -------------------------------------------------------- |
| CIDR / Subnets      | I separate internal LAN traffic vs external internet IPs |
| Ports + Services    | Some ports are high-risk and get more weight             |
| Firewall logic      | I generate deny/allow style decisions                    |
| Connection Behavior | scanning behavior gets higher risk                       |
| Edge Defense        | block list prevents lateral movement early               |

This helped me understand how network engineers think before creating firewall rules.

---

## 📂 Project Structure

```
smart-network-firewall-autoblocker/
 ├─ app/
 │   ├─ streamlit_app.py        → dashboard UI
 │   ├─ detector/
 │   │    └─ detector.py        → risk scoring logic
 │   └─ sample_logs.csv         → example traffic logs
 └─ requirements.txt            → Python dependencies
```

---

## 🚀 How to run locally

```bash
git clone <your_repo_link>
cd smart-network-firewall-autoblocker
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m streamlit run app/streamlit_app.py
```

open your browser:
**[http://localhost:8501](http://localhost:8501)**

---

## 🛠 Technologies I used

* Python (pandas, matplotlib)
* Streamlit (dashboard)
* Basic network traffic logic
* CIDR + subnet filtering
* Basic anomaly scoring

---

## 🎓 Why I built this

I wanted a practical project that shows I understand **network fundamentals** and **security operations** at the same time — but not too advanced so I can actually run it easily.

This is perfect for me as a Masters student starting in network engineering, because I am applying core networking concepts in an actual working tool.

---

## ✅ Future Improvements (Next Steps)

* auto-push block list into pfSense or FortiGate API
* ML model to improve anomaly detection
* add DNS log analysis
