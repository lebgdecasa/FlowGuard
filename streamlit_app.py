import streamlit as st
import requests

API_URL = "https://flowguard-api-938724554929.europe-west1.run.app"

st.title("FlowGuard Connection Predictor")

st.write("Enter connection details below:")

proto = st.selectbox("Protocol", ["TCP", "UDP", "ICMP"])
conn_state = st.text_input("Connection State", "ESTABLISHED")
history = st.text_input("History", "ShADadfF")
duration = st.number_input("Duration (seconds)", min_value=0.0, value=10.0)
orig_pkts = st.number_input("Originator Packets", min_value=0, value=5)
orig_ip_bytes = st.number_input("Originator IP Bytes", min_value=0, value=500)

if st.button("Predict"):
    input_data = {
        "proto": proto,
        "conn_state": conn_state,
        "history": history,
        "duration": duration,
        "orig_pkts": orig_pkts,
        "orig_ip_bytes": orig_ip_bytes
    }

    with st.spinner("Sending data to FlowGuard API..."):
        try:
            response = requests.post(API_URL, json=input_data)
            if response.status_code == 200:
                prediction = response.json()["prediction"]
                st.success(f"Prediction: {prediction}")
            else:
                st.error(f"Error: {response.text}")
        except Exception as e:
            st.error(f"Request failed: {e}")
