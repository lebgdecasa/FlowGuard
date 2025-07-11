from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import pandas as pd
import pickle

from backend.feature_engineering import add_history_bucket, add_duration_bucket

app = FastAPI()

with open('backend/model_rf_full.pkl', 'rb') as f:
    pipeline = pickle.load(f)

class InputData(BaseModel):
    proto: str
    conn_state: str
    history: str
    duration: float
    orig_pkts: int
    orig_ip_bytes: int

@app.get("/")
def root():
    return {"message": "Welcome to FlowGuard prediction API! Use POST /predict to get predictions."}

@app.post("/predict")
def predict(data: InputData):
    try:
        df = pd.DataFrame([data.dict()])
        df = add_history_bucket(df)
        df = add_duration_bucket(df)

        prediction = pipeline.predict(df)
        label = "benign connection" if prediction[0] == 0 else "malicious connection"
        return {"prediction": label}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
