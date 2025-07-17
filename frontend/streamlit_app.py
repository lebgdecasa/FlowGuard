"""
Streamlit front-end for FlowGuard
Run with:
    streamlit run streamlit_app.py
"""

import streamlit as st
import requests
from pathlib import Path
import pandas as pd

API_URL = st.secrets.get("FLOWGUARD_API_URL", "http://0.0.0.0:8000/predict")

st.set_page_config(page_title="FlowGuard Demo", page_icon="🛡️")
st.title("🛡️ FlowGuard Intrusion-Detection Demo")

# ---------------------------------------------------------------------
# 1. Feature pickers --------------------------------------------------
# ---------------------------------------------------------------------
st.subheader("Select flow features")

orig_pkts      = st.number_input("orig_pkts",   min_value=0, value=10, step=1)
orig_ip_bytes  = st.number_input("orig_ip_bytes", min_value=0, value=500, step=1)

proto          = st.radio("Protocol (proto)", options=["tcp", "udp"], horizontal=True)

conn_state_opts = [
    "OTH","REJ","RSTO","RSTOS0","RSTR","RSTRH",
    "S0","S1","S2","S3","SF","SH","SHR"
]
conn_state     = st.selectbox("Connection state (conn_state)", conn_state_opts, index=10)

# Raw history string – we’ll bucket it server-side
history_raw    = st.text_input(
    "Zeek history sequence (history)",
    value="S",
    help=("Enter the raw history string (e.g. 'S', 'ShADar', 'D'). "
          "The API will map it to one of the 5 history buckets."))

# ---------------------------------------------------------------------
# 2. Predict button ---------------------------------------------------
# ---------------------------------------------------------------------
if st.button("🔍 Predict"):
    payload = {
        "orig_pkts":     orig_pkts,
        "orig_ip_bytes": orig_ip_bytes,
        "proto":         proto,
        "conn_state":    conn_state,
        "history":       history_raw
    }

    with st.spinner("Calling FlowGuard API…"):
        resp = requests.post(API_URL, json=payload, timeout=10)

    if resp.ok:
        out = resp.json()
        st.success(f"**Prediction:** {out['prediction']}  "
                   f"  |  **Confidence:** {out['confidence']*100:.2f}%")
    else:
        st.error(f"API error {resp.status_code}: {resp.text}")
