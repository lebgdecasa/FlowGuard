import pickle
import os
from fastapi import FastAPI
from pydantic import BaseModel
import pandas as pd
import numpy as np
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.linear_model import LogisticRegression

app = FastAPI()

# Load the model and preprocessing objects
# model_path = os.path.join(os.path.dirname(__file__), 'flowguard_logreg_model.pkl')
# with open(model_path, 'rb') as f:
#     model: LogisticRegression = pickle.load(f)
# with open('../encoder.pkl', 'rb') as f:
#     encoder: OneHotEncoder = pickle.load(f)
# with open('../scaler.pkl', 'rb') as f:
#     scaler: StandardScaler = pickle.load(f)

class FlowData(BaseModel):
    proto: str
    service: str
    duration: float
    orig_bytes: float
    resp_bytes: float
    conn_state: str

@app.get("/")
def root():
    return {"message": "Hello Cybersecurity expert!"}

@app.post("/predict")
def predict(data: FlowData):
    # # Create a dataframe from the input data
    # input_df = pd.DataFrame([data.model_dump()])

    # # Separate categorical and numerical features as per the notebook
    # categorical_features = ['proto', 'conn_state']
    # numerical_features = ['duration', 'orig_bytes', 'resp_bytes'] # 'service' is not used here

    # # Preprocessing categorical features
    # encoded_features = encoder.transform(input_df[categorical_features])
    # encoded_df = pd.DataFrame(encoded_features, columns=encoder.get_feature_names_out(categorical_features))

    # # Preprocessing numerical features
    # scaled_features = scaler.transform(input_df[numerical_features])
    # scaled_df = pd.DataFrame(scaled_features, columns=numerical_features)

    # # Combine preprocessed data, ensuring same column order as training
    # processed_df = pd.concat([scaled_df, encoded_df], axis=1)

    # Make prediction
    prediction = 0

    if prediction == 0:
        return {"prediction": "benign"}
    else:
        return {"prediction": "malicious"}
