import streamlit as st
import requests
import json
import pandas as pd
import io
from datetime import datetime
import logging

# Set up logging to monitor the app's behavior, especially during batch processing.
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- PAGE CONFIGURATION ---
# Use a wide layout for better data display, similar to V1.
st.set_page_config(
    page_title="FlowGuard Network Traffic Analyzer",
    page_icon="🛡️",
    layout="wide"
)

# --- TITLE AND DESCRIPTION ---
st.title("🛡️ FlowGuard Network Traffic Analyzer")
st.markdown("A comprehensive tool to analyze network traffic for malicious activity, supporting single and batch analysis.")

# --- API CONFIGURATION ---

#TO-DO change once deployed
API_URL = st.secrets.get("FLOWGUARD_API_URL", "http://0.0.0.0:8000/predict")

# --- MALICIOUS PREDICTIONS LIST ---
# Define the list of malicious prediction labels at a global scope.
predictions_malicious = [
    "Attack", "C&C", "C&C - HeartBeat",
    "C&C - PartOfAHorizontalPortScan", "DDoS", "PartOfAHorizontalPortScan"
]

# --- TABS FOR DIFFERENT ANALYSIS MODES ---
# Keep the tabbed interface from V1 for a clean user experience.
tab1, tab2 = st.tabs(["Single Flow Analysis", "Batch Analysis (CSV)"])

# --- FEATURE OPTIONS (from V2) ---
# Define the connection state options required by the V2 model.
CONN_STATE_OPTS = [
    "OTH", "REJ", "RSTO", "RSTOS0", "RSTR", "RSTRH",
    "S0", "S1", "S2", "S3", "SF", "SH", "SHR"
]

# --- SINGLE ANALYSIS TAB ---
with tab1:
    st.header("Analyze a Single Network Flow")
    st.markdown("Enter the features of a single network flow to classify it as benign or malicious.")

    # Use a two-column layout for a cleaner form, as seen in V1.
    col1, col2 = st.columns(2)

    with col1:
        # --- INPUTS FROM V2 ---
        proto = st.radio(
            "Protocol (proto)*",
            options=["tcp", "udp"],
            horizontal=True,
            help="The network protocol used."
        )
        history = st.text_input(
            "Zeek History Sequence (history)*",
            value="S",
            help="Enter the raw history string (e.g., 'S', 'ShADar', 'D')."
        )
        orig_pkts = st.number_input(
            "Originator Packet Count (orig_pkts)*",
            min_value=0,
            value=10,
            step=1,
            help="Number of packets sent by the originator."
        )

    with col2:
        conn_state = st.selectbox(
            "Connection State (conn_state)*",
            CONN_STATE_OPTS,
            index=10,
            help="The state of the connection (e.g., 'SF' for normal)."
        )
        orig_ip_bytes = st.number_input(
            "Originator IP Bytes (orig_ip_bytes)*",
            min_value=0,
            value=500,
            step=1,
            help="Number of IP bytes sent by the originator."
        )

    st.markdown("---")
    # The primary button for triggering the analysis.
    if st.button("🔍 Analyze Traffic", type="primary", use_container_width=True):
        # --- API PAYLOAD (from V2) ---
        payload = {
            "proto": proto,
            "history": history,
            "conn_state": conn_state,
            "orig_pkts": orig_pkts,
            "orig_ip_bytes": orig_ip_bytes,
        }

        # --- RESULT DISPLAY (from V1) ---
        with st.spinner("🔄 Analyzing network traffic... Please wait."):
            try:
                response = requests.post(API_URL, json=payload, timeout=20)

                if response.status_code == 200:
                    result = response.json()
                    prediction = result.get('prediction', 'Error')
                    confidence = result.get('confidence', 0)

                    if prediction.lower() == 'benign':
                        st.success("✅ **Traffic Classification: BENIGN**")
                        st.balloons()
                        # Display a benign GIF for clear visual feedback.
                        _, img_col, _ = st.columns([1, 1, 1])
                        with img_col:
                            st.image("frontend/gifs/benign.gif")
                        st.metric(label="Confidence Score", value=f"{confidence * 100:.2f}%")

                    elif prediction.lower() in [p.lower() for p in predictions_malicious]:
                        st.error(f"⚠️ **Traffic Classification: MALICIOUS --> {prediction}**")
                        # Display a malicious GIF for immediate attention.
                        _, img_col, _ = st.columns([1, 1, 1])
                        with img_col:
                            st.image("frontend/gifs/malicious.gif")
                        st.metric(label="Confidence Score", value=f"{confidence * 100:.2f}%", delta="High Risk", delta_color="inverse")

                    else:
                        st.warning(f"❓ **Classification: {prediction}**")

                    # Expander for detailed analysis, a useful feature from V1.
                    with st.expander("📊 Detailed Analysis"):
                        st.write("**Confidence Score:**", f"{confidence:.4f}")
                        st.write("**Features Sent to API:**")
                        st.json(payload)

                else:
                    st.error(f"❌ API Error: Received status code {response.status_code}")
                    st.code(response.text, language='text')

            except requests.exceptions.RequestException as e:
                st.error(f"❌ Connection Error: Could not connect to the API. Details: {e}")

# --- BATCH ANALYSIS TAB ---
with tab2:
    st.header("Batch Analyze Network Flows from CSV")
    st.markdown("Upload a CSV file with network flow data to classify multiple entries at once.")

    # --- CSV TEMPLATE AND INSTRUCTIONS (adapted for V2 features) ---
    st.info("""
        **📄 CSV Format Instructions** Your CSV file must contain the following columns: `proto`, `history`, `conn_state`, `orig_pkts`, `orig_ip_bytes`.
    """)

    # Create a sample DataFrame and download button for user convenience.
    sample_data = pd.DataFrame({
        'proto': ['tcp', 'udp', 'tcp'],
        'history': ['S', 'D', 'ShADa'],
        'conn_state': ['SF', 'S0', 'REJ'],
        'orig_pkts': [10, 1, 2],
        'orig_ip_bytes': [600, 48, 80]
    })
    csv_buffer = io.StringIO()
    sample_data.to_csv(csv_buffer, index=False)
    st.download_button(
        label="📥 Download Sample CSV Template",
        data=csv_buffer.getvalue(),
        file_name="sample_flow_template.csv",
        mime="text/csv"
    )

    st.markdown("---")

    # The file uploader for batch analysis.
    uploaded_file = st.file_uploader(
        "Upload your CSV file",
        type=['csv'],
        help="Upload a CSV file containing the network flow features."
    )

    if uploaded_file is not None:
        try:
            df = pd.read_csv(uploaded_file)
            required_columns = ['proto', 'history', 'conn_state', 'orig_pkts', 'orig_ip_bytes']
            missing_columns = [col for col in required_columns if col not in df.columns]

            if missing_columns:
                st.error(f"❌ CSV Error: The following required columns are missing: {', '.join(missing_columns)}")
            else:
                st.success(f"✅ File uploaded successfully! Found {len(df)} flows to analyze.")
                with st.expander("👀 Preview Uploaded Data"):
                    st.dataframe(df.head())

                if st.button("🚀 Analyze All Flows", type="primary", use_container_width=True):
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    results = []
                    errors = []

                    for idx, row in df.iterrows():
                        progress = (idx + 1) / len(df)
                        progress_bar.progress(progress)
                        status_text.text(f"Processing flow {idx + 1} of {len(df)}...")

                        try:
                            # Prepare payload for each row.
                            payload = row[required_columns].to_dict()
                            # Ensure correct types for JSON serialization
                            payload['orig_pkts'] = int(payload['orig_pkts'])
                            payload['orig_ip_bytes'] = int(payload['orig_ip_bytes'])

                            response = requests.post(API_URL, json=payload, timeout=10)

                            if response.status_code == 200:
                                result = response.json()
                                res = row.to_dict()
                                prediction = result.get('prediction', '')
                                if prediction in predictions_malicious:
                                    res['prediction'] = 'Malicious - ' + prediction
                                else:
                                    res['prediction'] = prediction
                                res['confidence'] = result.get('confidence', 0)
                                results.append(res)
                            else:
                                errors.append(f"Row {idx + 1}: API Error (Code: {response.status_code}) - {response.text}")

                        except Exception as e:
                            errors.append(f"Row {idx + 1}: Processing Error - {str(e)}")

                    progress_bar.empty()
                    status_text.empty()

                    if results:
                        st.markdown("---")
                        st.header("📊 Batch Analysis Summary")
                        results_df = pd.DataFrame(results)

                        # --- METRICS AND SUMMARY (from V1) ---
                        predictions_malicious_for_count = ["Malicious - Attack", "Malicious - C&C", "Malicious - C&C - HeartBeat","Malicious - C&C - PartOfAHorizontalPortScan", "Malicious - DDoS", "Malicious - PartOfAHorizontalPortScan"]
                        malicious_count = len(results_df[results_df['prediction'].isin(predictions_malicious_for_count)])
                        benign_count = len(results_df[results_df['prediction'].str.lower() == 'benign'])
                        total_flows = len(results_df)

                        col1, col2, col3, col4 = st.columns(4)
                        col1.metric("Total Flows Analyzed", total_flows)
                        col2.metric("✅ Benign Flows", benign_count)
                        col3.metric("⚠️ Malicious Flows", malicious_count)
                        col4.metric("❌ Errors", len(errors))

                        # --- DETAILED RESULTS TABLE (from V1) ---
                        st.markdown("### 📋 Detailed Results")
                        results_df['Confidence'] = (results_df['confidence'] * 100).map('{:.2f}%'.format)
                        display_cols = required_columns + ['prediction', 'Confidence']

                        def highlight_malicious(row):
                            return ['background-color: #ffcccc' if row.prediction.lower() == 'malicious' else '' for _ in row]

                        st.dataframe(results_df[display_cols].style.apply(highlight_malicious, axis=1), use_container_width=True)

                        # Download button for the results.
                        csv_results = results_df.to_csv(index=False)
                        st.download_button(
                            label="📥 Download Full Analysis Results",
                            data=csv_results,
                            file_name=f"flowguard_batch_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                            mime="text/csv"
                        )

                    if errors:
                        with st.expander(f"⚠️ View {len(errors)} Processing Errors"):
                            for error in errors:
                                st.error(error)
        except Exception as e:
            st.error(f"❌ File Read Error: Could not process the uploaded CSV file. Details: {e}")

# --- SIDEBAR (from V1) ---
with st.sidebar:
    st.header("📖 How to Use")
    st.markdown("""
    ### Single Flow Analysis
    1.  Select the **features** for a single network flow on the main panel.
    2.  Click **Analyze Traffic** to get an instant classification.
    3.  Review the result, confidence score, and detailed breakdown.

    ### Batch Analysis (CSV)
    1.  Navigate to the **Batch Analysis** tab.
    2.  Prepare a **CSV file** with the required columns (template available for download).
    3.  **Upload** your file and click **Analyze All Flows**.
    4.  Review the summary metrics and detailed results table.
    """)

    st.header("🎯 Feature Descriptions")
    st.markdown("""
    - **Protocol**: Network protocol (`tcp` or `udp`).
    - **History**: Sequence of states from Zeek logs.
    - **Conn. State**: The final state of the connection.
    - **Originator Pkts**: Total packets from source to destination.
    - **Originator Bytes**: Total bytes from source to destination.
    """)

    st.header("🔧 API Status")
    if st.button("Check API Health"):
        with st.spinner("Pinging API..."):
            try:
                # Use a general health check endpoint if available, otherwise ping the base URL.
                health_url = API_URL.replace("/predict", "/health") # Assumes a /health endpoint
                health_response = requests.get(health_url, timeout=5)
                if health_response.status_code == 200:
                    st.success("✅ API is online and responding.")
                else:
                    st.warning(f"⚠️ API is reachable but returned status {health_response.status_code}.")
            except requests.RequestException:
                st.error("❌ API is unreachable.")

# --- FOOTER ---
st.markdown("---")
st.markdown("<div style='text-align: center;'><small>FlowGuard Network Traffic Analyzer | Merged Version</small></div>", unsafe_allow_html=True)
