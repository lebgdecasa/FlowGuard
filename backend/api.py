"""
FlowGuard prediction API
—————————
Start with:
    uvicorn api:app --reload --port 8000
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import pandas as pd
import numpy as np
import joblib, json, pathlib
import uvicorn

# ---------------------------------------------------------------------
# Load artefacts ------------------------------------------------------
# ---------------------------------------------------------------------
ASSETS = pathlib.Path(__file__).parent

with open(ASSETS / "flowguard_preprocessing.json") as fp:
    CFG = json.load(fp)

ENCODER       = joblib.load(ASSETS / "flowguard_encoder.pkl")
LBL_ENCODER   = joblib.load(ASSETS / "flowguard_label_encoder.pkl")
SCALER        = joblib.load(ASSETS / "flowguard_scaler.pkl")
MODEL         = joblib.load(ASSETS / "flowguard_xgboost_model_final.pkl")

NUM_FEATURES  = CFG["numerical_features"]                # ['orig_pkts', 'orig_ip_bytes']
CAT_FEATURES  = CFG["categorical_features"]              # ['proto', 'conn_state', 'history_bucket']
ORDERED_COLS  = CFG["feature_names_out"]                 # final column order expected by model

# ---------------------------------------------------------------------
# History bucketing helper -------------------------------------------
# ---------------------------------------------------------------------
PURE_MALICIOUS = {'I', 'DTT'}
SUSPICIOUS_COMBOS = {
    'ShAdDaFf', 'ShAdDafF', 'ShADadfF', 'ShADafF',
    'ShADar', 'ShAdDaFr', 'ShAdDfFr', 'ShAdDaft',
    'ShADr', 'ShADdfFa'
}
PURE_BENIGN = {'D', 'Dd', 'R'}

def bucket_history(val: str) -> str:
    """Map raw Zeek history strings → bucket."""
    if val == 'S':
        return 'majority_S'
    if val in PURE_MALICIOUS:
        return 'pure_malicious'
    if val in SUSPICIOUS_COMBOS:
        return 'known_suspicious_combos'
    if val in PURE_BENIGN:
        return 'pure_benign'
    return 'rare_mixed'


# ---------------------------------------------------------------------
# Pydantic schema -----------------------------------------------------
# ---------------------------------------------------------------------
class FlowInput(BaseModel):
    orig_pkts: int              = Field(..., ge=0, example=5)
    orig_ip_bytes: int          = Field(..., ge=0, example=400)
    proto: str                  = Field(..., pattern="^(tcp|udp)$", example="tcp")
    conn_state: str             = Field(...,
        pattern="^(OTH|REJ|RSTO|RSTOS0|RSTR|RSTRH|S0|S1|S2|S3|SF|SH|SHR)$",
        example="SF")
    history: str                = Field(..., example="S")   # raw Zeek history sequence

# ---------------------------------------------------------------------
# Pre-processing pipeline --------------------------------------------
# ---------------------------------------------------------------------
def preprocess(x: FlowInput) -> np.ndarray:
    df = pd.DataFrame([x.dict()])

    # transform history → bucket and drop raw column
    df["history_bucket"] = df["history"].apply(bucket_history)
    df.drop(columns=["history"], inplace=True)

    # numeric -----------------
    num_scaled = SCALER.transform(df[NUM_FEATURES])

    # categorical -------------
    cat_ohe = ENCODER.transform(df[CAT_FEATURES])

    # concatenate -------------
    X = np.concatenate([num_scaled, cat_ohe], axis=1)

    # ensure column order matches training
    df_processed = pd.DataFrame(X)

    # The encoder loses the column names, so we rename them here
    # The order of columns is based on the notebook
    df_processed.columns = ORDERED_COLS
    return df_processed.values


# ---------------------------------------------------------------------
# FastAPI app ---------------------------------------------------------
# ---------------------------------------------------------------------
app = FastAPI(
    title="FlowGuard Predictor",
    description="Predict traffic class from Zeek flow features.",
    version="1.0.0",
)
@app.get('/health')
def health_check():
    """Health check endpoint to verify service is running."""
    return {'status': 'ok', 'model_loaded': MODEL is not None}

@app.post("/predict")
def predict(flow: FlowInput):
    try:
        X = preprocess(flow)
        pred_idx = MODEL.predict(X)
        proba    = MODEL.predict_proba(X).max()
        label    = LBL_ENCODER.inverse_transform(pred_idx)[0]
        return {
            "prediction": label,
            "confidence": round(float(proba), 4)
        }
    except Exception as err:
        raise HTTPException(status_code=400, detail=str(err))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
