import requests
import json
import random
import os

# --- CONFIGURATION ---
# URL of the running Flask API
API_URL = "http://127.0.0.1:5001/predict"

# --- LOAD PREPROCESSING DATA ---
# This is needed to generate realistic synthetic data
base_dir = os.path.dirname(os.path.abspath(__file__))
preprocessing_path = os.path.join(base_dir, '..', 'flowguard_preprocessing.json')

try:
    with open(preprocessing_path, 'r') as f:
        preprocessing_data = json.load(f)

    PROTO_CATEGORIES = preprocessing_data['proto_categories']
    SERVICE_CATEGORIES = preprocessing_data['service_categories']
    print("Loaded preprocessing data to generate a realistic sample.")

except FileNotFoundError:
    print("Error: 'flowguard_preprocessing.json' not found.")
    print("Please run the training notebook first to generate it.")
    PROTO_CATEGORIES = ['tcp', 'udp', 'icmp'] # Fallback
    SERVICE_CATEGORIES = ['dns', 'http', '-'] # Fallback


# --- GENERATE SYNTHETIC DATA ---
def create_synthetic_sample():
    """Creates a single data entry with random but valid values."""
    sample = {
        "proto": random.choice(PROTO_CATEGORIES),
        "service": random.choice(SERVICE_CATEGORIES),
        "duration": round(random.uniform(0, 10), 6),
        "orig_bytes": random.randint(0, 1500),
        "resp_bytes": random.randint(0, 1500)
    }
    return sample

# --- MAIN TEST FUNCTION ---
def test_prediction():
    """
    Generates a synthetic data sample, sends it to the API,
    and prints the response.
    """
    # 1. Generate a sample
    synthetic_data = create_synthetic_sample()
    print("\n--- Sending Synthetic Data ---")
    print(json.dumps(synthetic_data, indent=2))

    # 2. Make the API call
    try:
        response = requests.post(API_URL, json=synthetic_data)
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)

        # 3. Print the result
        print("\n--- Received API Response ---")
        print(f"Status Code: {response.status_code}")
        print("Prediction:")
        print(json.dumps(response.json(), indent=2))

    except requests.exceptions.RequestException as e:
        print(f"\n--- API Call Failed ---")
        print(f"Error: {e}")
        print("Please ensure the Flask API server in 'api.py' is running.")


if __name__ == "__main__":
    test_prediction()
