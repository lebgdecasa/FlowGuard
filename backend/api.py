from flask import Flask, request, jsonify
import joblib
import pandas as pd
import json
import os

# --- INITIALIZATION ---
app = Flask(__name__)

# --- LOAD MODEL AND PREPROCESSING DATA ---
# Determine the absolute path to the files
# This assumes api.py is in the 'backend' directory, and the models are in the parent directory.
base_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(base_dir, 'flowguard_xgboost_model.pkl')
preprocessing_path = os.path.join(base_dir, 'flowguard_preprocessing.json')

try:
    model = joblib.load(model_path)
    with open(preprocessing_path, 'r') as f:
        preprocessing_data = json.load(f)

    FEATURES = preprocessing_data['features']
    PROTO_CATEGORIES = preprocessing_data['proto_categories']
    SERVICE_CATEGORIES = preprocessing_data['service_categories']

    print("Model and preprocessing data loaded successfully.")

except FileNotFoundError:
    print("Error: Model or preprocessing file not found.")
    print("Please run the training notebook (Test1.ipynb) to generate these files.")
    model = None
    FEATURES = None
    PROTO_CATEGORIES = None
    SERVICE_CATEGORIES = None


# --- PREPROCESSING FUNCTION ---
def preprocess_input(data):
    """
    Preprocesses raw input data for prediction.
    - Converts input to a DataFrame.
    - Encodes categorical features.
    - Ensures feature order.
    """
    if not isinstance(data, pd.DataFrame):
        df = pd.DataFrame(data, index=[0])
    else:
        df = data

    # Encode categorical features using the loaded categories
    df['proto'] = pd.Categorical(df['proto'], categories=PROTO_CATEGORIES).codes
    df['service'] = pd.Categorical(df['service'], categories=SERVICE_CATEGORIES).codes

    # Ensure all required features are present and in the correct order
    for col in FEATURES:
        if col not in df.columns:
            df[col] = 0 # Or handle missing columns appropriately

    return df[FEATURES]


# --- API ENDPOINTS ---
@app.route('/predict', methods=['POST'])
def predict():
    """
    Receives data, preprocesses it, makes a prediction, and returns the result.
    """
    if model is None:
        return jsonify({'error': 'Model not loaded. Please check server logs.'}), 500

    try:
        # Get data from POST request
        data = request.get_json(force=True)

        # Preprocess the data
        processed_data = preprocess_input(data)

        # Make prediction
        prediction = model.predict(processed_data)
        prediction_proba = model.predict_proba(processed_data)

        # Format response
        output = {
            'prediction': int(prediction[0]), # 0 for Benign, 1 for Malicious
            'confidence': {
                'benign': float(prediction_proba[0][0]),
                'malicious': float(prediction_proba[0][1])
            }
        }

        return jsonify(output)

    except Exception as e:
        print(f"An error occurred: {e}") # Add logging
        return jsonify({'error': str(e)}), 400

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint to verify service is running."""
    return jsonify({'status': 'ok', 'model_loaded': model is not None})


# --- RUN THE APP ---
if __name__ == '__main__':
    # Use 0.0.0.0 to make it accessible from outside the container
    app.run(host='0.0.0.0', port=5001, debug=True)
