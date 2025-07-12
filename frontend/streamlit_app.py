import streamlit as st
import requests
import json
import pandas as pd
import io
from datetime import datetime
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Set page configuration
st.set_page_config(
    page_title="FlowGuard Network Traffic Analyzer",
    page_icon="🛡️",
    layout="wide"
)

# Title and description
st.title("🛡️ FlowGuard Network Traffic Analyzer")
st.markdown("Analyze network traffic patterns to detect potential malicious activity")

# API configuration
#TO-DO change once deployed
API_URL = "https://flowguard-api-final-938724554929.europe-west1.run.app"

# Create tabs for single and batch analysis
tab1, tab2 = st.tabs(["Single Analysis", "Batch Analysis (CSV)"])

# Protocol and service mappings
proto_options = {
    "TCP": 0,
    "UDP": 1,
    "ICMP": 2
}

service_options = {
    "HTTP": 0,
    "DNS": 1,
    "DHCP": 2,
    "SSH": 3,
    "Other": 4
}

# Reverse mappings for display
proto_reverse = {v: k for k, v in proto_options.items()}
service_reverse = {v: k for k, v in service_options.items()}

# Single Analysis Tab
with tab1:
    st.subheader("Analyze Single Network Flow")

    # Create two columns for better layout
    col1, col2 = st.columns(2)

    with col1:
        # Protocol dropdown (required)
        proto = st.selectbox(
            "Protocol*",
            options=list(proto_options.keys()),
            help="Network protocol used"
        )

        # Service dropdown (required)
        service = st.selectbox(
            "Service*",
            options=list(service_options.keys()),
            help="Type of network service"
        )

        # Duration (required)
        duration = st.number_input(
            "Duration (seconds)*",
            min_value=0.0,
            value=0.0,
            step=0.1,
            help="Connection duration in seconds"
        )

    with col2:
        # Original bytes (required)
        orig_bytes = st.number_input(
            "Original Bytes*",
            min_value=0,
            value=0,
            step=1,
            help="Number of bytes from originator"
        )

        # Response bytes (required)
        resp_bytes = st.number_input(
            "Response Bytes*",
            min_value=0,
            value=0,
            step=1,
            help="Number of bytes in response"
        )

    # Analyze button
    st.markdown("---")
    analyze_button = st.button("🔍 Analyze Traffic", type="primary", use_container_width=True)

    # Results container
    result_container = st.container()

    if analyze_button:
        # Prepare data for API
        data = {
            "proto": proto_options[proto],
            "service": service_options[service],
            "duration": duration,
            "orig_bytes": orig_bytes,
            "resp_bytes": resp_bytes
        }

        # Show loading state
        with result_container:
            with st.spinner("🔄 Analyzing network traffic..."):
                try:
                    # Make API request
                    response = requests.post(API_URL, json=data)

                    if response.status_code == 200:
                        result = response.json()
                        prediction = result.get('prediction', -1)
                        confidence = result.get('confidence', {})

                        # Clear previous results
                        result_container.empty()

                        # Display results
                        if prediction == 0:
                            st.success("✅ **Traffic Classification: BENIGN**")
                            st.balloons()

                            # Placeholder for benign GIF
                            col1, col2, col3 = st.columns([1, 2, 1])
                            with col2:
                                st.image("frontend/gifs/benign.gif")

                            # Show confidence scores
                            st.metric(
                                label="Confidence Score",
                                value=f"{confidence.get('benign', 0) * 100:.1f}%",
                                delta="Benign"
                            )

                        elif prediction == 1:
                            st.error("⚠️ **Traffic Classification: MALICIOUS**")

                            # Placeholder for malicious GIF
                            col1, col2, col3 = st.columns([1, 2, 1])
                            with col2:
                                st.image("frontend/gifs/malicious.gif")

                            # Show confidence scores
                            st.metric(
                                label="Confidence Score",
                                value=f"{confidence.get('malicious', 0) * 100:.1f}%",
                                delta="Malicious",
                                delta_color="inverse"
                            )

                        # Display confidence breakdown
                        with st.expander("📊 Detailed Analysis"):
                            st.write("**Confidence Breakdown:**")
                            benign_conf = confidence.get('benign', 0) * 100
                            malicious_conf = confidence.get('malicious', 0) * 100

                            st.progress(benign_conf / 100)
                            st.write(f"Benign: {benign_conf:.2f}%")

                            st.progress(malicious_conf / 100)
                            st.write(f"Malicious: {malicious_conf:.2f}%")

                            st.write("**Analyzed Features:**")
                            st.json(data)

                    else:
                        st.error(f"❌ Error: API returned status code {response.status_code}")
                        st.write(response.text)

                except requests.exceptions.ConnectionError:
                    st.error("❌ **Connection Error:** Unable to connect to the API. Please ensure the API server is running on port 5001.")
                except Exception as e:
                    st.error(f"❌ **Error:** {str(e)}")

# Batch Analysis Tab
with tab2:
    st.subheader("Batch Analyze Network Flows from CSV")

    # CSV template download
    st.markdown("### 📄 CSV Format")
    st.markdown("Your CSV file should contain the following columns:")
    st.code("proto,service,duration,orig_bytes,resp_bytes")

    # Create sample CSV
    sample_data = pd.DataFrame({
        'proto': [0, 1, 0, 2, 0],
        'service': [0, 1, 3, 2, 4],
        'duration': [1.5, 0.3, 10.2, 0.0, 5.7],
        'orig_bytes': [1024, 512, 2048, 128, 4096],
        'resp_bytes': [2048, 256, 4096, 0, 8192]
    })

    csv_buffer = io.StringIO()
    sample_data.to_csv(csv_buffer, index=False)

    st.markdown("---")

    # File uploader
    uploaded_file = st.file_uploader(
        "Upload CSV file",
        type=['csv'],
        help="Upload a CSV file containing network flow data"
    )

    if uploaded_file is not None:
        try:
            # Read the CSV file
            df = pd.read_csv(uploaded_file)

            # Validate columns
            required_columns = ['proto', 'service', 'duration', 'orig_bytes', 'resp_bytes']
            missing_columns = [col for col in required_columns if col not in df.columns]

            if missing_columns:
                st.error(f"❌ Missing required columns: {', '.join(missing_columns)}")
            else:
                st.success(f"✅ Loaded {len(df)} network flows for analysis")

                # Show preview
                with st.expander("👀 Preview Data"):
                    st.dataframe(df.head(10))

                # Analyze button
                if st.button("🚀 Analyze All Flows", type="primary", use_container_width=True):

                    # Progress tracking
                    progress_bar = st.progress(0)
                    status_text = st.empty()

                    # Results storage
                    results = []
                    errors = []

                    # Process each row
                    for idx, row in df.iterrows():
                        logger.info(f"Processing row {idx + 1}/{len(df)}")
                        progress = (idx + 1) / len(df)
                        progress_bar.progress(progress)
                        status_text.text(f"Processing flow {idx + 1} of {len(df)}...")

                        try:
                            logger.info(f"Row {idx}: Preparing data for API")
                            # Prepare data
                            data = {
                                "proto": str(row['proto']),
                                "service": str(row['service']),
                                "duration": float(row['duration']),
                                "orig_bytes": int(row['orig_bytes']),
                                "resp_bytes": int(row['resp_bytes'])
                            }

                            # Make API request
                            logger.info(f"Row {idx}: Sending data {data} to API")
                            response = requests.post(API_URL, json=data)
                            logger.info(f"Row {idx}: Sent data {data} to API")
                            logger.info(f"Row {idx}: Received response {response.status_code}")

                            if response.status_code == 200:
                                result = response.json()
                                results.append({
                                    'index': idx,
                                    'prediction': result.get('prediction'),
                                    'confidence_benign': result.get('confidence', {}).get('benign', 0),
                                    'confidence_malicious': result.get('confidence', {}).get('malicious', 0),
                                    **data
                                })
                            else:
                                errors.append(f"Row {idx}: API error - {response.status_code}")

                        except Exception as e:
                            logger.error(f"Row {idx}: Error processing data - {str(e)}")
                            errors.append(f"Row {idx}: {str(e)}")

                    # Clear progress indicators
                    progress_bar.empty()
                    status_text.empty()

                    # Display results
                    if results:
                        st.markdown("---")
                        st.markdown("## 📊 Analysis Summary")

                        # Convert results to DataFrame
                        results_df = pd.DataFrame(results)

                        # Calculate statistics
                        total_flows = len(results)
                        malicious_count = sum(1 for r in results if r['prediction'] == 1)
                        benign_count = sum(1 for r in results if r['prediction'] == 0)
                        malicious_percentage = (malicious_count / total_flows) * 100

                        # Display key metrics
                        col1, col2, col3, col4 = st.columns(4)

                        with col1:
                            st.metric("Total Flows", total_flows)

                        with col2:
                            st.metric("Benign", benign_count, f"{(benign_count/total_flows)*100:.1f}%")

                        with col3:
                            st.metric("Malicious", malicious_count, f"{malicious_percentage:.1f}%", delta_color="inverse")

                        with col4:
                            st.metric("Errors", len(errors))

                        # Threat level indicator
                        st.markdown("### 🎯 Overall Threat Level")
                        if malicious_percentage == 0:
                            st.success("✅ **LOW RISK** - No malicious traffic detected")
                        elif malicious_percentage < 10:
                            st.info("ℹ️ **MODERATE RISK** - Some suspicious activity detected")
                        elif malicious_percentage < 30:
                            st.warning("⚠️ **HIGH RISK** - Significant malicious traffic detected")
                        else:
                            st.error("🚨 **CRITICAL RISK** - Heavy malicious traffic detected!")

                        # Detailed results table
                        st.markdown("### 📋 Detailed Results")

                        # Add classification labels
                        results_df['Classification'] = results_df['prediction'].map({0: '✅ Benign', 1: '⚠️ Malicious'})
                        results_df['Proto_Name'] = results_df['proto'].map(proto_reverse)
                        results_df['Service_Name'] = results_df['service'].map(service_reverse)
                        results_df['Confidence'] = results_df.apply(
                            lambda row: f"{row['confidence_benign']*100:.1f}%" if row['prediction'] == 0
                            else f"{row['confidence_malicious']*100:.1f}%",
                            axis=1
                        )

                        # Display table with selected columns
                        display_cols = ['index', 'Proto_Name', 'Service_Name', 'duration',
                                      'orig_bytes', 'resp_bytes', 'Classification', 'Confidence']
                        st.dataframe(
                            results_df[display_cols].style.apply(
                                lambda x: ['background-color: #ffcccc' if '⚠️' in v else '' for v in x],
                                subset=['Classification']
                            ),
                            use_container_width=True
                        )

                        # Download results
                        csv_results = results_df.to_csv(index=False)
                        st.download_button(
                            label="📥 Download Analysis Results",
                            data=csv_results,
                            file_name=f"flowguard_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                            mime="text/csv"
                        )

                        # Show errors if any
                        if errors:
                            with st.expander(f"⚠️ Errors ({len(errors)})"):
                                for error in errors:
                                    st.error(error)

                    else:
                        st.error("❌ No results were processed successfully")

        except Exception as e:
            st.error(f"❌ Error reading CSV file: {str(e)}")

# Sidebar with instructions
with st.sidebar:
    st.header("📖 Instructions")

    tab_selection = st.radio("Select Mode:", ["Single Analysis", "Batch Analysis"])

    if tab_selection == "Single Analysis":
        st.markdown("""
        ### Single Flow Analysis
        1. **Fill in all required fields**
        2. Click **Analyze Traffic** to get prediction
        3. View the classification result

        ### 🔍 Feature Descriptions:
        - **Protocol**: Network protocol (TCP/UDP/ICMP)
        - **Service**: Type of service (HTTP/DNS/etc.)
        - **Duration**: Connection duration in seconds
        - **Bytes**: Data transferred in bytes
        """)
    else:
        st.markdown("""
        ### Batch Analysis
        1. **Prepare CSV** with required columns
        2. **Upload** your CSV file
        3. Click **Analyze All Flows**
        4. **Review** summary and detailed results

        ### 📊 CSV Column Values:
        **Proto**: 0=TCP, 1=UDP, 2=ICMP
        **Service**: 0=HTTP, 1=DNS, 2=DHCP, 3=SSH, 4=Other
        """)

    st.markdown("""
    ### 🎯 Classification:
    - **Benign**: Normal network traffic
    - **Malicious**: Potentially harmful traffic
    """)

    st.header("🔧 API Status")
    if st.button("Check API Health"):
        try:
            health_response = requests.get("http://localhost:5001/health")
            if health_response.status_code == 200:
                health_data = health_response.json()
                if health_data.get('model_loaded'):
                    st.success("✅ API is running and model is loaded")
                else:
                    st.warning("⚠️ API is running but model not loaded")
            else:
                st.error("❌ API health check failed")
        except:
            st.error("❌ Cannot connect to API")

# Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center'>
    <small>FlowGuard Network Traffic Analyzer v2.0 | Powered by XGBoost</small>
</div>
""", unsafe_allow_html=True)
